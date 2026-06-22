#include "database.hpp"
#include <pulsevm_ffi/src/bridge.rs.h>
#include <pulsevm/state_history/create_deltas.hpp>
#include <fc/reflect/reflect.hpp>
#include <filesystem>

namespace pulsevm::chain {

U128 index128_object_secondary_key_as_u128(const index128_object& o) {
    unsigned __int128 x = o.get_secondary_key();   // the real method
    return U128{ static_cast<uint64_t>(x), static_cast<uint64_t>(x >> 64) };
}

std::unique_ptr<pulsevm::chain::database_wrapper> open_database(
    rust::Str path,
    DatabaseOpenFlags flags,
    uint64_t size
) {
    // Convert rust::Str to std::filesystem::path
    std::string path_str(path.data(), path.size());
    std::filesystem::path fs_path(path_str);
    
    // Convert flags enum to chainbase flags
    chainbase::database::open_flags db_flags;
    if (static_cast<uint32_t>(flags) == 0) {
        db_flags = chainbase::database::open_flags::read_only;
    } else {
        db_flags = chainbase::database::open_flags::read_write;
    }
    
    // Create and return database
    return std::make_unique<pulsevm::chain::database_wrapper>(fs_path, db_flags, size);
}

void database_wrapper::initialize_database(const genesis_state& genesis) {
    // create the database header sigil
    this->create<database_header_object>([&]( auto& header ){
        // nothing to do for now
    });

    auto chain_id = genesis.compute_chain_id();
    this->create<global_property_object>([&genesis,&chain_id](auto& gpo ){
        gpo.configuration = genesis.initial_configuration;
        gpo.wasm_configuration = genesis_state::default_initial_wasm_configuration;
        gpo.chain_id = chain_id;
    });

    this->create<protocol_state_object>([&](auto& pso ){
        pso.num_supported_key_types = config::genesis_num_supported_key_types;
    });
    this->create<dynamic_global_property_object>([](auto&){});
    this->create<permission_object>([](auto&){});  /// reserve perm 0 (used else where)

    const auto& config = this->create<resource_limits::resource_limits_config_object>([](resource_limits::resource_limits_config_object& config){
        // see default settings in the declaration
    });

    const auto& state = this->create<resource_limits::resource_limits_state_object>([&config](resource_limits::resource_limits_state_object& state){
        // see default settings in the declaration

        // start the chain off in a way that it is "congested" aka slow-start
        state.virtual_cpu_limit = config.cpu_limit_parameters.max;
        state.virtual_net_limit = config.net_limit_parameters.max;
    });

    authority system_auth(genesis.initial_key);
    this->create_native_account( genesis.initial_timestamp, config::system_account_name.to_uint64_t(), system_auth, system_auth, true );

    auto empty_authority = authority(1, {}, {});
    auto active_producers_authority = authority(1, {}, {});
    active_producers_authority.accounts.push_back({{config::system_account_name, config::active_name}, 1});

    this->create_native_account( genesis.initial_timestamp, config::null_account_name.to_uint64_t(), empty_authority, empty_authority );
    this->create_native_account( genesis.initial_timestamp, config::producers_account_name.to_uint64_t(), empty_authority, active_producers_authority );
    const auto& active_permission       = this->get_permission({config::producers_account_name, config::active_name});
    const auto& majority_permission     = this->create_permission(
        config::producers_account_name.to_uint64_t(),
        config::majority_producers_permission_name.to_uint64_t(),
        active_permission.id._id,
        active_producers_authority,
        TimePoint { Microseconds { genesis.initial_timestamp.time_since_epoch().count() } }
    );
    this->create_permission(
        config::producers_account_name.to_uint64_t(), 
        config::minority_producers_permission_name.to_uint64_t(),
        majority_permission.id._id,
        active_producers_authority,
        TimePoint { Microseconds { genesis.initial_timestamp.time_since_epoch().count() } }
    );
}

void database_wrapper::create_native_account( const fc::time_point& initial_timestamp, u_int64_t account_name, const authority& owner, const authority& active, bool is_privileged ) {
    this->create<account_object>([&](auto& a) {
        a.name = name(account_name);
        a.creation_date = initial_timestamp;

        if( account_name == config::system_account_name.to_uint64_t() ) {
            a.abi.assign(pulsevm_abi_bin, sizeof(pulsevm_abi_bin));
        }
    });
    this->create<account_metadata_object>([&](auto & a) {
        a.name = name(account_name);
        a.set_privileged( is_privileged );
    });

    const auto& owner_permission  = this->create_permission(account_name, config::owner_name.to_uint64_t(), 0,
                                                                    owner, TimePoint { Microseconds { initial_timestamp.time_since_epoch().count() } } );
    const auto& active_permission = this->create_permission(account_name, config::active_name.to_uint64_t(), owner_permission.id._id,
                                                                    active, TimePoint { Microseconds { initial_timestamp.time_since_epoch().count() } } );

    this->initialize_account_resource_limits(account_name);

    int64_t ram_delta = config::overhead_per_account_ram_bytes;
    ram_delta += 2*config::billable_size_v<permission_object>;
    ram_delta += owner_permission.auth.get_billable_size();
    ram_delta += active_permission.auth.get_billable_size();

    this->add_pending_ram_usage(account_name, ram_delta);
    this->verify_account_ram_usage(account_name);
}

void database_wrapper::set_global_properties(const ChainConfigV0& cfg) {
    this->modify( this->get_global_properties(), [&]( pulsevm::chain::global_property_object& gprops ) {
        gprops.configuration.max_block_net_usage = cfg.max_block_net_usage;
        gprops.configuration.target_block_net_usage_pct = cfg.target_block_net_usage_pct;
        gprops.configuration.max_transaction_net_usage = cfg.max_transaction_net_usage;
        gprops.configuration.base_per_transaction_net_usage = cfg.base_per_transaction_net_usage;
        gprops.configuration.net_usage_leeway = cfg.net_usage_leeway;
        gprops.configuration.context_free_discount_net_usage_num = cfg.context_free_discount_net_usage_num;
        gprops.configuration.context_free_discount_net_usage_den = cfg.context_free_discount_net_usage_den;
        gprops.configuration.max_block_cpu_usage = cfg.max_block_cpu_usage;
        gprops.configuration.target_block_cpu_usage_pct = cfg.target_block_cpu_usage_pct;
        gprops.configuration.max_transaction_cpu_usage = cfg.max_transaction_cpu_usage;
        gprops.configuration.min_transaction_cpu_usage = cfg.min_transaction_cpu_usage;
        gprops.configuration.max_transaction_lifetime = cfg.max_transaction_lifetime;
        gprops.configuration.deferred_trx_expiration_window = cfg.deferred_trx_expiration_window;
        gprops.configuration.max_transaction_delay = cfg.max_transaction_delay;
        gprops.configuration.max_inline_action_size = cfg.max_inline_action_size;
        gprops.configuration.max_inline_action_depth = cfg.max_inline_action_depth;
        gprops.configuration.max_authority_depth = cfg.max_authority_depth;
    });
}

void database_wrapper::update_account_code(
    const account_metadata_object& account,
    rust::Slice<const std::uint8_t> new_code, 
    uint32_t head_block_num, 
    const TimePoint& pending_block_time,
    const digest_type& code_hash, 
    uint8_t vm_type, 
    uint8_t vm_version
) {
    if( new_code.size() > 0 ) {
        const code_object* new_code_entry = this->find<code_object, by_code_hash>( boost::make_tuple(code_hash, vm_type, vm_version) );

        if( new_code_entry ) {
            this->modify(*new_code_entry, [&](code_object& o) {
                ++o.code_ref_count;
            });
        } else {
            this->create<code_object>([&](code_object& o) {
                o.code_hash = code_hash;
                o.code.assign( new_code.data(), new_code.size() );
                o.code_ref_count = 1;
                o.first_block_used = head_block_num + 1;
                o.vm_type = vm_type;
                o.vm_version = vm_version;
            });
        }
    }

    this->modify( account, [&]( auto& a ) {
        a.code_sequence += 1;
        a.code_hash = code_hash;
        a.vm_type = vm_type;
        a.vm_version = vm_version;
        a.last_code_update = fc::time_point(fc::microseconds(pending_block_time.elapsed.count));
    });
}

CpuLimitResult database_wrapper::get_account_cpu_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_cpu_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

NetLimitResult database_wrapper::get_account_net_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_net_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

const permission_object& database_wrapper::create_permission(
    uint64_t account,
    uint64_t permission_name,
    uint64_t parent,
    const Authority& a,
    const TimePoint& creation_time
) {
    authority auth;
    auth.threshold = a.threshold;
    auth.keys.reserve(a.keys.size());
    auth.accounts.reserve(a.accounts.size());
    auth.waits.reserve(a.waits.size());
    for (const auto& k : a.keys) {
        auth.keys.emplace_back( key_weight{ *k.key, k.weight } );
    }
    for (const auto& ac : a.accounts) {
        auth.accounts.emplace_back( permission_level_weight{ { name(ac.permission.actor), name(ac.permission.permission) }, ac.weight } );
    }
    for (const auto& w : a.waits) {
        auth.waits.emplace_back( wait_weight{ w.wait_sec, w.weight } );
    }

    for(const key_weight& k: auth.keys)
        EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
        "Unactivated key type used when creating permission");

    const auto& perm_usage = this->create<permission_usage_object>([&](auto& p) {
        p.last_used = fc::time_point(fc::microseconds(creation_time.elapsed.count));
    });

    const auto& perm = this->create<permission_object>([&](auto& p) {
        p.usage_id     = perm_usage.id;
        p.parent       = permission_object::id_type(parent);
        p.owner        = name(account);
        p.perm_name    = name(permission_name);
        p.last_updated = fc::time_point(fc::microseconds(creation_time.elapsed.count));
        p.auth         = std::move(auth);
    });

    return perm;
}

const permission_object& database_wrapper::create_permission(
    uint64_t account,
    uint64_t permission_name,
    uint64_t parent,
    const authority& auth,
    const TimePoint& creation_time
) {
    for(const key_weight& k: auth.keys)
        EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
        "Unactivated key type used when creating permission");

    const auto& perm_usage = this->create<permission_usage_object>([&](auto& p) {
        p.last_used = fc::time_point(fc::microseconds(creation_time.elapsed.count));
    });

    const auto& perm = this->create<permission_object>([&](auto& p) {
        p.usage_id     = perm_usage.id;
        p.parent       = permission_object::id_type(parent);
        p.owner        = name(account);
        p.perm_name    = name(permission_name);
        p.last_updated = fc::time_point(fc::microseconds(creation_time.elapsed.count));
        p.auth         = std::move(auth);
    });

    return perm;
}

void database_wrapper::modify_permission( const permission_object& permission, const Authority& a, const TimePoint& pending_block_time ) {
    authority auth;
    auth.threshold = a.threshold;
    auth.keys.reserve(a.keys.size());
    auth.accounts.reserve(a.accounts.size());
    auth.waits.reserve(a.waits.size());
    for (const auto& k : a.keys) {
        auth.keys.emplace_back( key_weight{ *k.key, k.weight } );
    }
    for (const auto& ac : a.accounts) {
        auth.accounts.emplace_back( permission_level_weight{ { name(ac.permission.actor), name(ac.permission.permission) }, ac.weight } );
    }
    for (const auto& w : a.waits) {
        auth.waits.emplace_back( wait_weight{ w.wait_sec, w.weight } );
    }

    for(const key_weight& k: auth.keys)
        EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
        "Unactivated key type used when modifying permission");

    this->modify( permission, [&](permission_object& po) {
        po.auth = auth;
        po.last_updated = fc::time_point(fc::microseconds(pending_block_time.elapsed.count));
    });
}

void database_wrapper::update_permission_usage( const permission_object& permission, const TimePoint& pending_block_time ) {
    const auto& puo = this->get<permission_usage_object, by_id>( permission.usage_id );
    this->modify( puo, [&](permission_usage_object& p) {
        p.last_used = fc::time_point(fc::microseconds(pending_block_time.elapsed.count));
    });
}

TimePoint database_wrapper::get_permission_last_used( const permission_object& permission ) const {
    fc::time_point last_used = this->get<permission_usage_object, by_id>( permission.usage_id ).last_used;
    return TimePoint { Microseconds { last_used.time_since_epoch().count() } };
}

void database_wrapper::set_block_parameters(const ElasticLimitParameters& cpu_limit_parameters, const ElasticLimitParameters& net_limit_parameters ) {
    const auto& config = this->get<resource_limits::resource_limits_config_object>();
    
    if( config.cpu_limit_parameters.target == cpu_limit_parameters.target &&
        config.cpu_limit_parameters.max == cpu_limit_parameters.max &&
        config.cpu_limit_parameters.periods == cpu_limit_parameters.periods &&
        config.cpu_limit_parameters.max_multiplier == cpu_limit_parameters.max_multiplier &&
        config.cpu_limit_parameters.contract_rate.numerator == cpu_limit_parameters.contract_rate.numerator &&
        config.cpu_limit_parameters.contract_rate.denominator == cpu_limit_parameters.contract_rate.denominator &&
        config.cpu_limit_parameters.expand_rate.numerator == cpu_limit_parameters.expand_rate.numerator &&
        config.cpu_limit_parameters.expand_rate.denominator == cpu_limit_parameters.expand_rate.denominator &&
        config.net_limit_parameters.target == net_limit_parameters.target &&
        config.net_limit_parameters.max == net_limit_parameters.max &&
        config.net_limit_parameters.periods == net_limit_parameters.periods &&
        config.net_limit_parameters.max_multiplier == net_limit_parameters.max_multiplier &&
        config.net_limit_parameters.contract_rate.numerator == net_limit_parameters.contract_rate.numerator &&
        config.net_limit_parameters.contract_rate.denominator == net_limit_parameters.contract_rate.denominator &&
        config.net_limit_parameters.expand_rate.numerator == net_limit_parameters.expand_rate.numerator &&
        config.net_limit_parameters.expand_rate.denominator == net_limit_parameters.expand_rate.denominator )
        return;

    this->modify(config, [&](resource_limits::resource_limits_config_object& c){
        c.cpu_limit_parameters.target = cpu_limit_parameters.target;
        c.cpu_limit_parameters.max = cpu_limit_parameters.max;
        c.cpu_limit_parameters.periods = cpu_limit_parameters.periods;
        c.cpu_limit_parameters.max_multiplier = cpu_limit_parameters.max_multiplier;
        c.cpu_limit_parameters.contract_rate.numerator = cpu_limit_parameters.contract_rate.numerator;
        c.cpu_limit_parameters.contract_rate.denominator = cpu_limit_parameters.contract_rate.denominator;
        c.cpu_limit_parameters.expand_rate.numerator = cpu_limit_parameters.expand_rate.numerator;
        c.cpu_limit_parameters.expand_rate.denominator = cpu_limit_parameters.expand_rate.denominator;

        c.net_limit_parameters.target = net_limit_parameters.target;
        c.net_limit_parameters.max = net_limit_parameters.max;
        c.net_limit_parameters.periods = net_limit_parameters.periods;
        c.net_limit_parameters.max_multiplier = net_limit_parameters.max_multiplier;
        c.net_limit_parameters.contract_rate.numerator = net_limit_parameters.contract_rate.numerator;
        c.net_limit_parameters.contract_rate.denominator = net_limit_parameters.contract_rate.denominator;
        c.net_limit_parameters.expand_rate.numerator = net_limit_parameters.expand_rate.numerator;
        c.net_limit_parameters.expand_rate.denominator = net_limit_parameters.expand_rate.denominator;
    });
}

rust::Vec<uint8_t> database_wrapper::pack_deltas(bool full_snapshot) const {
    fc::datastream<size_t> ps;
    pulsevm::state_history::pack_deltas(ps, *this, full_snapshot);
    size_t sz = ps.tellp();

    std::vector<char> temp_buffer(sz);
    fc::datastream<char*> ds(temp_buffer.data(), sz);
    pulsevm::state_history::pack_deltas(ds, *this, full_snapshot);

    rust::Vec<uint8_t> out;
    out.reserve(sz);
    for (const auto& byte : temp_buffer) {
        out.push_back(static_cast<uint8_t>(byte));
    }

    return out;
}

void database_wrapper::clear_expired_input_transactions(const TimePoint& cutoff) {
    //Look for expired transactions in the deduplication list, and remove them.
    auto& transaction_idx = this->get_mutable_index<transaction_multi_index>();
    const auto& dedupe_index = transaction_idx.indices().get<by_expiration>();
    const auto total = dedupe_index.size();
    uint32_t num_removed = 0;
    while( (!dedupe_index.empty()) && ( fc::time_point(fc::microseconds(cutoff.elapsed.count)) > dedupe_index.begin()->expiration.to_time_point() ) ) {
        transaction_idx.remove(*dedupe_index.begin());
        ++num_removed;
    }
}

inline unsigned __int128 to_u128(const U128& v) {
    return (static_cast<unsigned __int128>(v.hi) << 64)
         |  static_cast<unsigned __int128>(v.lo);
}

inline U128 from_u128(unsigned __int128 x) {
    return U128{
        static_cast<uint64_t>(x),          // lo
        static_cast<uint64_t>(x >> 64),    // hi
    };
}

inline U256 from_u256(const key256_t& k) {
    U256 out;
    static_assert(sizeof(k) == 32, "key256_t must be 32 bytes");
    std::memcpy(out.value.data(), k.data(), 32);
    return out;
}

inline key256_t to_u256(const U256& u) {
    key256_t k;
    std::memcpy(k.data(), u.value.data(), 32);
    return k;
}

inline float128_t to_float128(const Float128& f) {
    float128_t out;
    out.v[0] = f.lo;   // low 64 bits
    out.v[1] = f.hi;   // high 64 bits
    return out;
}

inline Float128 from_float128(const float128_t& f) {
    return Float128{ f.v[0], f.v[1] };   // lo = v[0], hi = v[1]
}

const index128_object& database_wrapper::create_index128_object( const table_id_object& tab, uint64_t payer, uint64_t id, U128 secondary ) {
    unsigned __int128 sec = to_u128(secondary);
    auto tableid = tab.id;
    EOS_ASSERT( payer != 0, invalid_table_payer, "must specify a valid account to pay for new record" );
    const auto& obj = this->create<index128_object>( [&]( auto& o ) {
        o.t_id          = tableid;
        o.primary_key   = id;
        o.secondary_key = sec;
        o.payer         = name(payer);
    });

    this->modify( tab, [&]( auto& t ) {
        ++t.count;
    });

    return obj;
}

void database_wrapper::update_index128_object( const index128_object& obj, uint64_t payer, U128 secondary ) {
    this->modify( obj, [&]( auto& o ) {
        o.secondary_key = to_u128(secondary);
        o.payer = name(payer);
    });
}

void database_wrapper::db_idx128_remove( iterator_cache<index128_object>& keyval_cache, int iterator, u_int64_t receiver ) {
    const index128_object& obj = keyval_cache.get( iterator );
    const auto& table_obj = keyval_cache.get_table( obj.t_id );
    EOS_ASSERT( table_obj.code == name(receiver), table_access_violation, "db access violation" );

    this->modify( table_obj, [&]( auto& t ) {
        --t.count;
    });
    this->remove( obj );

    if (table_obj.count == 0) {
        this->remove_table(table_obj);
    }

    keyval_cache.remove( iterator );
}

int database_wrapper::db_idx128_find_secondary( iterator_cache<index128_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U128 secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    unsigned __int128 sec = to_u128(secondary);

    const auto* obj = this->find<index128_object, by_secondary>( boost::make_tuple( tab->id, sec ) );
    if( !obj ) return table_end_itr;

    primary = obj->primary_key;

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx128_find_primary( iterator_cache<index128_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U128& secondary, uint64_t primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto* obj = this->find<index128_object, by_primary>( boost::make_tuple( tab->id, primary ) );
    if( !obj ) return table_end_itr;

    secondary = from_u128(obj->secondary_key);

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx128_lowerbound( iterator_cache<index128_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U128& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    unsigned __int128 sec = to_u128(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index128_object>::type, by_secondary>();
    auto itr = idx.lower_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_u128(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx128_upperbound( iterator_cache<index128_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U128& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    unsigned __int128 sec = to_u128(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index128_object>::type, by_secondary>();
    auto itr = idx.upper_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_u128(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx128_end( iterator_cache<index128_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    return keyval_cache.cache_table( *tab );
}

int database_wrapper::db_idx128_next( iterator_cache<index128_object>& keyval_cache, int iterator, uint64_t& primary ) {
    if( iterator < -1 ) return -1; // cannot increment past end iterator of index

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call
    const auto& idx = this->get_index<typename chainbase::get_index_type<index128_object>::type, by_secondary>();

    auto itr = idx.iterator_to(obj);
    ++itr;

    if( itr == idx.end() || itr->t_id != obj.t_id ) return keyval_cache.get_end_iterator_by_table_id(obj.t_id);

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

int database_wrapper::db_idx128_previous( iterator_cache<index128_object>& keyval_cache, int iterator, uint64_t& primary ) {
    const auto& idx = this->get_index<typename chainbase::get_index_type<index128_object>::type, by_secondary>();

    if( iterator < -1 ) // is end iterator
    {
        auto tab = keyval_cache.find_table_by_end_iterator(iterator);
        EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

        auto itr = idx.upper_bound(tab->id);
        if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty index

        --itr;

        if( itr->t_id != tab->id ) return -1; // Empty index

        primary = itr->primary_key;
        return keyval_cache.add(*itr);
    }

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call

    auto itr = idx.iterator_to(obj);
    if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of index

    --itr;

    if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of index

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

const index256_object& database_wrapper::create_index256_object( const table_id_object& tab, uint64_t payer, uint64_t id, U256 secondary ) {
    auto sec = to_u256(secondary);
    auto tableid = tab.id;
    EOS_ASSERT( payer != 0, invalid_table_payer, "must specify a valid account to pay for new record" );
    const auto& obj = this->create<index256_object>( [&]( auto& o ) {
        o.t_id          = tableid;
        o.primary_key   = id;
        o.secondary_key = sec;
        o.payer         = name(payer);
    });

    this->modify( tab, [&]( auto& t ) {
        ++t.count;
    });

    return obj;
}

void database_wrapper::update_index256_object( const index256_object& obj, uint64_t payer, U256 secondary ) {
    this->modify( obj, [&]( auto& o ) {
        o.secondary_key = to_u256(secondary);
        o.payer = name(payer);
    });
}

void database_wrapper::db_idx256_remove( iterator_cache<index256_object>& keyval_cache, int iterator, u_int64_t receiver ) {
    const index256_object& obj = keyval_cache.get( iterator );
    const auto& table_obj = keyval_cache.get_table( obj.t_id );
    EOS_ASSERT( table_obj.code == name(receiver), table_access_violation, "db access violation" );

    this->modify( table_obj, [&]( auto& t ) {
        --t.count;
    });
    this->remove( obj );

    if (table_obj.count == 0) {
        this->remove_table(table_obj);
    }

    keyval_cache.remove( iterator );
}

int database_wrapper::db_idx256_find_secondary( iterator_cache<index256_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U256 secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_u256(secondary);

    const auto* obj = this->find<index256_object, by_secondary>( boost::make_tuple( tab->id, sec ) );
    if( !obj ) return table_end_itr;

    primary = obj->primary_key;

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx256_find_primary( iterator_cache<index256_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U256& secondary, uint64_t primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto* obj = this->find<index256_object, by_primary>( boost::make_tuple( tab->id, primary ) );
    if( !obj ) return table_end_itr;

    secondary = from_u256(obj->secondary_key);

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx256_lowerbound( iterator_cache<index256_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U256& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_u256(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index256_object>::type, by_secondary>();
    auto itr = idx.lower_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_u256(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx256_upperbound( iterator_cache<index256_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, U256& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_u256(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index256_object>::type, by_secondary>();
    auto itr = idx.upper_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_u256(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx256_end( iterator_cache<index256_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    return keyval_cache.cache_table( *tab );
}

int database_wrapper::db_idx256_next( iterator_cache<index256_object>& keyval_cache, int iterator, uint64_t& primary ) {
    if( iterator < -1 ) return -1; // cannot increment past end iterator of index

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call
    const auto& idx = this->get_index<typename chainbase::get_index_type<index256_object>::type, by_secondary>();

    auto itr = idx.iterator_to(obj);
    ++itr;

    if( itr == idx.end() || itr->t_id != obj.t_id ) return keyval_cache.get_end_iterator_by_table_id(obj.t_id);

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

int database_wrapper::db_idx256_previous( iterator_cache<index256_object>& keyval_cache, int iterator, uint64_t& primary ) {
    const auto& idx = this->get_index<typename chainbase::get_index_type<index256_object>::type, by_secondary>();

    if( iterator < -1 ) // is end iterator
    {
        auto tab = keyval_cache.find_table_by_end_iterator(iterator);
        EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

        auto itr = idx.upper_bound(tab->id);
        if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty index

        --itr;

        if( itr->t_id != tab->id ) return -1; // Empty index

        primary = itr->primary_key;
        return keyval_cache.add(*itr);
    }

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call

    auto itr = idx.iterator_to(obj);
    if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of index

    --itr;

    if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of index

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

const index_double_object& database_wrapper::create_idx_double_object( const table_id_object& tab, uint64_t payer, uint64_t id, uint64_t secondary ) {
    auto tableid = tab.id;
    EOS_ASSERT( payer != 0, invalid_table_payer, "must specify a valid account to pay for new record" );
    const auto& obj = this->create<index_double_object>( [&]( auto& o ) {
        o.t_id          = tableid;
        o.primary_key   = id;
        o.secondary_key = float64_t { secondary };;
        o.payer         = name(payer);
    });

    this->modify( tab, [&]( auto& t ) {
        ++t.count;
    });

    return obj;
}

void database_wrapper::update_idx_double_object( const index_double_object& obj, uint64_t payer, uint64_t secondary ) {
    this->modify( obj, [&]( auto& o ) {
        o.secondary_key = float64_t { secondary };;
        o.payer = name(payer);
    });
}

void database_wrapper::db_idx_double_remove( iterator_cache<index_double_object>& keyval_cache, int iterator, u_int64_t receiver ) {
    const index_double_object& obj = keyval_cache.get( iterator );
    const auto& table_obj = keyval_cache.get_table( obj.t_id );
    EOS_ASSERT( table_obj.code == name(receiver), table_access_violation, "db access violation" );

    this->modify( table_obj, [&]( auto& t ) {
        --t.count;
    });
    this->remove( obj );

    if (table_obj.count == 0) {
        this->remove_table(table_obj);
    }

    keyval_cache.remove( iterator );
}

int database_wrapper::db_idx_double_find_secondary( iterator_cache<index_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    auto sec = float64_t { secondary };
    const auto* obj = this->find<index_double_object, by_secondary>( boost::make_tuple( tab->id, sec ) );
    if( !obj ) return table_end_itr;

    primary = obj->primary_key;

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx_double_find_primary( iterator_cache<index_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t& secondary, uint64_t primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto* obj = this->find<index_double_object, by_primary>( boost::make_tuple( tab->id, primary ) );
    if( !obj ) return table_end_itr;

    secondary = obj->secondary_key.v;

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx_double_lowerbound( iterator_cache<index_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto& idx = this->get_index<typename chainbase::get_index_type<index_double_object>::type, by_secondary>();
    auto sec = float64_t { secondary };
    auto itr = idx.lower_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = itr->secondary_key.v;

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx_double_upperbound( iterator_cache<index_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto& idx = this->get_index<typename chainbase::get_index_type<index_double_object>::type, by_secondary>();
    auto sec = float64_t { secondary };
    auto itr = idx.upper_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = itr->secondary_key.v;

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx_double_end( iterator_cache<index_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    return keyval_cache.cache_table( *tab );
}

int database_wrapper::db_idx_double_next( iterator_cache<index_double_object>& keyval_cache, int iterator, uint64_t& primary ) {
    if( iterator < -1 ) return -1; // cannot increment past end iterator of index

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call
    const auto& idx = this->get_index<typename chainbase::get_index_type<index_double_object>::type, by_secondary>();

    auto itr = idx.iterator_to(obj);
    ++itr;

    if( itr == idx.end() || itr->t_id != obj.t_id ) return keyval_cache.get_end_iterator_by_table_id(obj.t_id);

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

int database_wrapper::db_idx_double_previous( iterator_cache<index_double_object>& keyval_cache, int iterator, uint64_t& primary ) {
    const auto& idx = this->get_index<typename chainbase::get_index_type<index_double_object>::type, by_secondary>();

    if( iterator < -1 ) // is end iterator
    {
        auto tab = keyval_cache.find_table_by_end_iterator(iterator);
        EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

        auto itr = idx.upper_bound(tab->id);
        if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty index

        --itr;

        if( itr->t_id != tab->id ) return -1; // Empty index

        primary = itr->primary_key;
        return keyval_cache.add(*itr);
    }

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call

    auto itr = idx.iterator_to(obj);
    if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of index

    --itr;

    if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of index

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

const index_long_double_object& database_wrapper::create_idx_long_double_object( const table_id_object& tab, uint64_t payer, uint64_t id, Float128 secondary ) {
    auto sec = to_float128(secondary);
    auto tableid = tab.id;
    EOS_ASSERT( payer != 0, invalid_table_payer, "must specify a valid account to pay for new record" );
    const auto& obj = this->create<index_long_double_object>( [&]( auto& o ) {
        o.t_id          = tableid;
        o.primary_key   = id;
        o.secondary_key = sec;
        o.payer         = name(payer);
    });

    this->modify( tab, [&]( auto& t ) {
        ++t.count;
    });

    return obj;
}

void database_wrapper::update_idx_long_double_object( const index_long_double_object& obj, uint64_t payer, Float128 secondary ) {
    this->modify( obj, [&]( auto& o ) {
        o.secondary_key = to_float128(secondary);
        o.payer = name(payer);
    });
}

void database_wrapper::db_idx_long_double_remove( iterator_cache<index_long_double_object>& keyval_cache, int iterator, u_int64_t receiver ) {
    const index_long_double_object& obj = keyval_cache.get( iterator );
    const auto& table_obj = keyval_cache.get_table( obj.t_id );
    EOS_ASSERT( table_obj.code == name(receiver), table_access_violation, "db access violation" );

    this->modify( table_obj, [&]( auto& t ) {
        --t.count;
    });
    this->remove( obj );

    if (table_obj.count == 0) {
        this->remove_table(table_obj);
    }

    keyval_cache.remove( iterator );
}

int database_wrapper::db_idx_long_double_find_secondary( iterator_cache<index_long_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, Float128 secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_float128(secondary);

    const auto* obj = this->find<index_long_double_object, by_secondary>( boost::make_tuple( tab->id, sec ) );
    if( !obj ) return table_end_itr;

    primary = obj->primary_key;

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx_long_double_find_primary( iterator_cache<index_long_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, Float128& secondary, uint64_t primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );

    const auto* obj = this->find<index_long_double_object, by_primary>( boost::make_tuple( tab->id, primary ) );
    if( !obj ) return table_end_itr;

    secondary = from_float128(obj->secondary_key);

    return keyval_cache.add( *obj );
}

int database_wrapper::db_idx_long_double_lowerbound( iterator_cache<index_long_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, Float128& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_float128(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index_long_double_object>::type, by_secondary>();
    auto itr = idx.lower_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_float128(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx_long_double_upperbound( iterator_cache<index_long_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, Float128& secondary, uint64_t& primary ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    auto table_end_itr = keyval_cache.cache_table( *tab );
    auto sec = to_float128(secondary);

    const auto& idx = this->get_index<typename chainbase::get_index_type<index_long_double_object>::type, by_secondary>();
    auto itr = idx.upper_bound( boost::make_tuple( tab->id, sec ) );
    if( itr == idx.end() ) return table_end_itr;
    if( itr->t_id != tab->id ) return table_end_itr;

    primary = itr->primary_key;
    secondary = from_float128(itr->secondary_key);

    return keyval_cache.add( *itr );
}

int database_wrapper::db_idx_long_double_end( iterator_cache<index_long_double_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table ) {
    auto tab = this->find_table( code, scope, table );
    if( !tab ) return -1;

    return keyval_cache.cache_table( *tab );
}

int database_wrapper::db_idx_long_double_next( iterator_cache<index_long_double_object>& keyval_cache, int iterator, uint64_t& primary ) {
    if( iterator < -1 ) return -1; // cannot increment past end iterator of index

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call
    const auto& idx = this->get_index<typename chainbase::get_index_type<index_long_double_object>::type, by_secondary>();

    auto itr = idx.iterator_to(obj);
    ++itr;

    if( itr == idx.end() || itr->t_id != obj.t_id ) return keyval_cache.get_end_iterator_by_table_id(obj.t_id);

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

int database_wrapper::db_idx_long_double_previous( iterator_cache<index_long_double_object>& keyval_cache, int iterator, uint64_t& primary ) {
    const auto& idx = this->get_index<typename chainbase::get_index_type<index_long_double_object>::type, by_secondary>();

    if( iterator < -1 ) // is end iterator
    {
        auto tab = keyval_cache.find_table_by_end_iterator(iterator);
        EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

        auto itr = idx.upper_bound(tab->id);
        if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty index

        --itr;

        if( itr->t_id != tab->id ) return -1; // Empty index

        primary = itr->primary_key;
        return keyval_cache.add(*itr);
    }

    const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call

    auto itr = idx.iterator_to(obj);
    if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of index

    --itr;

    if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of index

    primary = itr->primary_key;
    return keyval_cache.add(*itr);
}

}