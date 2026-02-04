#include "api.hpp"

namespace pulsevm { namespace chain {

    const string KEYi64 = "i64";

    namespace detail {
        struct ram_market_exchange_state_t {
            asset  ignore1;
            asset  ignore2;
            double ignore3;
            asset  core_symbol;
            double ignore4;
        };
    }

    symbol extract_core_symbol(const database_wrapper& db) {
        symbol core_symbol(0);

        // The following code makes assumptions about the contract deployed on pulse account (i.e. the system contract) and how it stores its data.
        const auto* t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple( "pulse"_n, "pulse"_n, "rammarket"_n ));
        if( t_id != nullptr ) {
            const auto &idx = db.get_index<key_value_index, by_scope_primary>();
            auto it = idx.find(boost::make_tuple( t_id->id, string_to_symbol_c(4,"RAMCORE") ));
            if( it != idx.end() ) {
                detail::ram_market_exchange_state_t ram_market_exchange_state;

                fc::datastream<const char *> ds( it->value.data(), it->value.size() );

                try {
                    fc::raw::unpack(ds, ram_market_exchange_state);
                } catch( ... ) {
                    return core_symbol;
                }

                if( ram_market_exchange_state.core_symbol.get_symbol().valid() ) {
                    core_symbol = ram_market_exchange_state.core_symbol.get_symbol();
                }
            }
        }

        return core_symbol;
    }

    string get_table_type( const abi_def& abi, const name& table_name ) {
        for( const auto& t : abi.tables ) {
            if( t.name == table_name ){
                return t.index_type;
            }
        }
        EOS_ASSERT( false, chain::contract_table_query_exception, "Table ${table} is not specified in the ABI", ("table",table_name) );
    }

    abi_def get_abi( const database_wrapper& db, uint64_t account ) {
        const account_object *code_accnt = db.find<account_object, by_name>(name(account));
        EOS_ASSERT(code_accnt != nullptr, chain::account_query_exception, "failed to retrieve account for ${account}", ("account", account) );
        abi_def abi;
        abi_serializer::to_abi(code_accnt->abi, abi);
        return abi;
    }

    rust::String get_account_info_without_core_symbol( const database_wrapper& db, uint64_t account, uint32_t head_block_num, const fc::time_point& head_block_time ) {
        auto result = get_account_info( db, account, std::nullopt, head_block_num, head_block_time );
        auto json = fc::json::to_pretty_string( result );
        return rust::String( json.c_str() );
    }

    rust::String get_account_info_with_core_symbol( const database_wrapper& db, uint64_t account, rust::Str expected_core_symbol, uint32_t head_block_num, const fc::time_point& head_block_time ) {
        auto result = get_account_info( db, account, symbol::from_string(string(expected_core_symbol.data(), expected_core_symbol.size())), head_block_num, head_block_time );
        auto json = fc::json::to_pretty_string( result );
        return rust::String( json.c_str() );
    }

    get_account_results get_account_info( const database_wrapper& db, uint64_t account, std::optional<symbol> expected_core_symbol, uint32_t head_block_num, const fc::time_point& head_block_time ) {
        auto deadline = fc::time_point::now().safe_add( fc::microseconds(30 * 1000 * 1000) ); // 30 seconds from now
        auto account_name = name(account);

        try {
            get_account_results result;
            result.account_name = account_name;

            result.head_block_num  = head_block_num;
            result.head_block_time = head_block_time;

            db.get_account_limits( account, result.ram_quota, result.net_weight, result.cpu_weight );

            const auto& accnt_obj = db.get_account( account );
            const auto& accnt_metadata_obj = db.get<account_metadata_object,by_name>( account_name );

            result.privileged       = accnt_metadata_obj.is_privileged();
            result.last_code_update = accnt_metadata_obj.last_code_update;
            result.created          = accnt_obj.creation_date;

            uint32_t greylist_limit = config::maximum_elastic_resource_multiplier;
            const block_timestamp_type current_usage_time (head_block_time);
            result.net_limit.set( db.get_account_net_limit_ex( account, greylist_limit, current_usage_time).first );
            if ( result.net_limit.last_usage_update_time && (result.net_limit.last_usage_update_time->slot == 0) ) {   // account has no action yet
                result.net_limit.last_usage_update_time = accnt_obj.creation_date;
            }
            result.cpu_limit.set( db.get_account_cpu_limit_ex( account, greylist_limit, current_usage_time).first );
            if ( result.cpu_limit.last_usage_update_time && (result.cpu_limit.last_usage_update_time->slot == 0) ) {   // account has no action yet
                result.cpu_limit.last_usage_update_time = accnt_obj.creation_date;
            }
            result.ram_usage = db.get_account_ram_usage( account );

            resource_limits::account_resource_limit subjective_cpu_bill_limit;
            subjective_cpu_bill_limit.used = 0;
            result.subjective_cpu_bill_limit = subjective_cpu_bill_limit;

            const auto linked_action_map = ([&](){
                const auto& links = db.get_index<permission_link_index,by_permission_name>();
                auto iter = links.lower_bound( boost::make_tuple( account_name ) );

                std::multimap<name, linked_action> result;
                while (iter != links.end() && iter->account == account_name ) {
                    auto action_name = iter->message_type.empty() ? std::optional<name>() : std::optional<name>(iter->message_type);
                    result.emplace(iter->required_permission, linked_action{iter->code, action_name});
                    ++iter;
                }

                return result;
            })();

            auto get_linked_actions = [&](name perm_name) {
                auto link_bounds = linked_action_map.equal_range(perm_name);
                auto linked_actions = std::vector<linked_action>();
                linked_actions.reserve(linked_action_map.count(perm_name));
                for (auto link = link_bounds.first; link != link_bounds.second; ++link) {
                    linked_actions.push_back(link->second);
                }
                return linked_actions;
            };

            const auto& permissions = db.get_index<permission_index,by_owner>();
            auto perm = permissions.lower_bound( boost::make_tuple( account_name ) );
            while( perm != permissions.end() && perm->owner == account_name ) {
                /// TODO: lookup perm->parent name
                name parent;

                // Don't lookup parent if null
                if( perm->parent._id ) {
                    const auto* p = db.find<permission_object,by_id>( perm->parent );
                    if( p ) {
                        EOS_ASSERT(perm->owner == p->owner, invalid_parent_permission, "Invalid parent permission");
                        parent = p->perm_name;
                    }
                }

                auto linked_actions = get_linked_actions(perm->perm_name);

                result.permissions.push_back( permission{ perm->perm_name, parent, perm->auth.to_authority(), std::move(linked_actions)} );
                ++perm;
            }

            // add eosio.any linked authorizations
            result.eosio_any_linked_actions = get_linked_actions(config::any_name);

            const auto& code_account = db.get<account_object,by_name>( config::system_account_name );
            struct http_params_t {
                std::optional<vector<char>> total_resources;
                std::optional<vector<char>> self_delegated_bandwidth;
                std::optional<vector<char>> refund_request;
                std::optional<vector<char>> voter_info;
                std::optional<vector<char>> rex_info;
            };

            http_params_t http_params;
            
            if( abi_def abi; abi_serializer::to_abi(code_account.abi, abi) ) {

                const auto token_code = "pulse.token"_n;

                auto core_symbol = extract_core_symbol(db);

                if (expected_core_symbol)
                    core_symbol = *expected_core_symbol;

                const auto* t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple( token_code, account_name, "accounts"_n ));
                if( t_id != nullptr ) {
                    const auto &idx = db.get_index<key_value_index, by_scope_primary>();
                    auto it = idx.find(boost::make_tuple( t_id->id, core_symbol.to_symbol_code() ));
                    if( it != idx.end() && it->value.size() >= sizeof(asset) ) {
                        asset bal;
                        fc::datastream<const char *> ds(it->value.data(), it->value.size());
                        fc::raw::unpack(ds, bal);

                        if( bal.get_symbol().valid() && bal.get_symbol() == core_symbol ) {
                        result.core_liquid_balance = bal;
                        }
                    }
                }

                auto lookup_object = [&](const name& obj_name, const name& account_name) -> std::optional<vector<char>> {
                    auto t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple( config::system_account_name, account_name, obj_name ));
                    if (t_id != nullptr) {
                        const auto& idx = db.get_index<key_value_index, by_scope_primary>();
                        auto it = idx.find(boost::make_tuple( t_id->id, account ));
                        if (it != idx.end()) {
                        vector<char> data;
                        copy_inline_row(*it, data);
                        return data;
                        }
                    }
                    return {};
                };
                
                http_params.self_delegated_bandwidth = lookup_object("delband"_n, account_name);
                http_params.refund_request           = lookup_object("refunds"_n, account_name);
                http_params.voter_info               = lookup_object("voters"_n, config::system_account_name);
                http_params.rex_info                 = lookup_object("rexbal"_n, config::system_account_name);
                
                auto yield = [&]() { return abi_serializer::create_yield_function(abi_serializer_max_time); };
                abi_serializer abis(std::move(abi), yield());
                
                if (http_params.total_resources)
                    result.total_resources = abis.binary_to_variant("UserResources", *http_params.total_resources, yield(), shorten_abi_errors);
                if (http_params.self_delegated_bandwidth)
                    result.self_delegated_bandwidth = abis.binary_to_variant("DelegatedBandwidth", *http_params.self_delegated_bandwidth, yield(), shorten_abi_errors);
                if (http_params.refund_request)
                    result.refund_request = abis.binary_to_variant("RefundRequest", *http_params.refund_request, yield(), shorten_abi_errors);
                if (http_params.voter_info)
                    result.voter_info = abis.binary_to_variant("VoterInfo", *http_params.voter_info, yield(), shorten_abi_errors);
                if (http_params.rex_info)
                    result.rex_info = abis.binary_to_variant("RexBalance", *http_params.rex_info, yield(), shorten_abi_errors);
                return result;
            }
            
            return result;
        } EOS_RETHROW_EXCEPTIONS(account_query_exception, "unable to retrieve account info")
    }

    rust::String get_currency_balance( const database_wrapper& db, uint64_t code, uint64_t account, std::optional<string> symbol ) {
        const abi_def abi = get_abi( db, code );
        (void)get_table_type( abi, name("accounts") );

        vector<asset> results;
        walk_key_value_table(db, name(code), name(account), "accounts"_n, [&](const key_value_object& obj){
            EOS_ASSERT( obj.value.size() >= sizeof(asset), asset_type_exception, "Invalid data on table");

            asset cursor;
            fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
            fc::raw::unpack(ds, cursor);

            EOS_ASSERT( cursor.get_symbol().valid(), asset_type_exception, "Invalid asset");

            if( !symbol || boost::iequals(cursor.symbol_name(), *symbol) ) {
                results.emplace_back(cursor);
            }

            // return false if we are looking for one and found it, true otherwise
            return !(symbol && boost::iequals(cursor.symbol_name(), *symbol));
        });

        auto json = fc::json::to_pretty_string( results );
        return rust::String( json.c_str() );
    }

    rust::String get_currency_balance_with_symbol( const database_wrapper& db, uint64_t code, uint64_t account, rust::Str symbol ) {
        return get_currency_balance( db, code, account, string( symbol.data(), symbol.size() ) );
    }

    rust::String get_currency_balance_without_symbol( const database_wrapper& db, uint64_t code, uint64_t account ) {
        return get_currency_balance( db, code, account, std::nullopt );
    }

    rust::String get_currency_stats( const database_wrapper& db, uint64_t code, rust::Str symbol ) {
        fc::mutable_variant_object results;

        const abi_def abi = get_abi( db, code );
        (void)get_table_type( abi, name("stat") );

        uint64_t scope = ( string_to_symbol( 0, boost::algorithm::to_upper_copy(string(symbol.data(), symbol.size())).c_str() ) >> 8 );

        walk_key_value_table(db, name(code), name(scope), "stat"_n, [&](const key_value_object& obj){
            EOS_ASSERT( obj.value.size() >= sizeof(get_currency_stats_result), asset_type_exception, "Invalid data on table");

            fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
            get_currency_stats_result result;

            fc::raw::unpack(ds, result.supply);
            fc::raw::unpack(ds, result.max_supply);
            fc::raw::unpack(ds, result.issuer);

            results[result.supply.symbol_name()] = result;
            return true;
        });

        auto json = fc::json::to_pretty_string( results );
        return rust::String( json.c_str() );
    }

    rust::String get_table_rows(
        const database_wrapper& db,
        bool json,
        uint64_t code,
        rust::Str scope,
        uint64_t table,
        rust::Str table_key,
        rust::Str lower_bound,
        rust::Str upper_bound,
        uint32_t limit,
        rust::Str key_type,
        rust::Str index_position,
        rust::Str encode_type,
        bool reverse,
        bool show_payer
    ) {
        auto params = get_table_rows_params {
            json,
            name(code),
            string(scope.data(), scope.size()),
            name(table),
            string(table_key.data(), table_key.size()),
            string(lower_bound.data(), lower_bound.size()),
            string(upper_bound.data(), upper_bound.size()),
            limit,
            string(key_type.data(), key_type.size()),
            string(index_position.data(), index_position.size()),
            string(encode_type.data(), encode_type.size()),
            reverse,
            show_payer,
        };
        auto deadline = fc::time_point::now().safe_add( fc::microseconds(30 * 1000 * 1000) ); // 30 seconds from now
        auto result = get_table_rows_internal(db, params, deadline)();
        auto json_result = fc::json::to_pretty_string( result );
        return rust::String( json_result.c_str() );
    }

    get_table_rows_return_t get_table_rows_internal( const database_wrapper& db, const get_table_rows_params& p, const fc::time_point& deadline ) {
        abi_def abi = get_abi( db, p.code.to_uint64_t() );
        bool primary = false;
        auto table_with_index = get_table_index_name( p, primary );
        if( primary ) {
            EOS_ASSERT( p.table == table_with_index, chain::contract_table_query_exception, "Invalid table name ${t}", ( "t", p.table ));
            auto table_type = get_table_type( abi, p.table );
            if( table_type == KEYi64 || p.key_type == "i64" || p.key_type == "name" ) {
                return get_table_rows_ex<key_value_index>(db, p, std::move(abi), deadline);
            }
            EOS_ASSERT( false, chain::contract_table_query_exception,  "Invalid table type ${type}", ("type",table_type)("abi",abi));
        } else {
            EOS_ASSERT( !p.key_type.empty(), chain::contract_table_query_exception, "key type required for non-primary index" );

            if (p.key_type == i64 || p.key_type == "name") {
                return get_table_rows_by_seckey<index64_index, uint64_t>(db, p, std::move(abi), deadline, [](uint64_t v)->uint64_t {
                    return v;
                });
            }

            EOS_ASSERT(false, chain::contract_table_query_exception,  "Unsupported secondary index type: ${t}", ("t", p.key_type));
        }
    }

    uint64_t convert_to_type(const name &n, const string &desc) {
        return n.to_uint64_t();
    }

    template<>
    uint64_t convert_to_type(const string& str, const string& desc) {
        try {
            return boost::lexical_cast<uint64_t>(str.c_str(), str.size());
        } catch( ... ) { }

        try {
            auto trimmed_str = str;
            boost::trim(trimmed_str);
            name s(trimmed_str);
            return s.to_uint64_t();
        } catch( ... ) { }

        if (str.find(',') != string::npos) { // fix #6274 only match formats like 4,EOS
            try {
                auto symb = symbol::from_string(str);
                return symb.value();
            } catch( ... ) { }
        }

        try {
            return ( string_to_symbol( 0, str.c_str() ) >> 8 );
        } catch( ... ) {
            EOS_ASSERT( false, chain_type_exception, "Could not convert ${desc} string '${str}' to any of the following: "
                                "uint64_t, valid name, or valid symbol (with or without the precision)",
                        ("desc", desc)("str", str));
        }
    }

    template<typename Type>
    string convert_to_string(const Type& source, const string& key_type, const string& encode_type, const string& desc) {
        try {
            return fc::variant(source).as<string>();
        } FC_RETHROW_EXCEPTIONS(warn, "Could not convert ${desc} from '${source}' to string.", ("desc", desc)("source",source) )
    }

    uint64_t get_table_index_name(const get_table_rows_params& p, bool& primary) {
        using boost::algorithm::starts_with;
        // see multi_index packing of index name
        const uint64_t table = p.table.to_uint64_t();
        uint64_t index = table & 0xFFFFFFFFFFFFFFF0ULL;
        EOS_ASSERT( index == table, chain::contract_table_query_exception, "Unsupported table name: ${n}", ("n", p.table) );

        primary = false;
        uint64_t pos = 0;
        if (p.index_position.empty() || p.index_position == "first" || p.index_position == "primary" || p.index_position == "one") {
            primary = true;
        } else if (starts_with(p.index_position, "sec") || p.index_position == "two") { // second, secondary
        } else if (starts_with(p.index_position , "ter") || starts_with(p.index_position, "th")) { // tertiary, ternary, third, three
            pos = 1;
        } else if (starts_with(p.index_position, "fou")) { // four, fourth
            pos = 2;
        } else if (starts_with(p.index_position, "fi")) { // five, fifth
            pos = 3;
        } else if (starts_with(p.index_position, "six")) { // six, sixth
            pos = 4;
        } else if (starts_with(p.index_position, "sev")) { // seven, seventh
            pos = 5;
        } else if (starts_with(p.index_position, "eig")) { // eight, eighth
            pos = 6;
        } else if (starts_with(p.index_position, "nin")) { // nine, ninth
            pos = 7;
        } else if (starts_with(p.index_position, "ten")) { // ten, tenth
            pos = 8;
        } else {
            try {
                pos = fc::to_uint64( p.index_position );
            } catch(...) {
                EOS_ASSERT( false, chain::contract_table_query_exception, "Invalid index_position: ${p}", ("p", p.index_position));
            }
            if (pos < 2) {
                primary = true;
                pos = 0;
            } else {
                pos -= 2;
            }
        }
        index |= (pos & 0x000000000000000FULL);
        return index;
    }
} }

FC_REFLECT( pulsevm::chain::detail::ram_market_exchange_state_t, (ignore1)(ignore2)(ignore3)(core_symbol)(ignore4) )