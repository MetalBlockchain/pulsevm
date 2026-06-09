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
    const time_point& creation_time
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
        p.last_used = creation_time;
    });

    const auto& perm = this->create<permission_object>([&](auto& p) {
        p.usage_id     = perm_usage.id;
        p.parent       = permission_object::id_type(parent);
        p.owner        = name(account);
        p.perm_name    = name(permission_name);
        p.last_updated = creation_time;
        p.auth         = std::move(auth);
    });

    return perm;
}

void database_wrapper::modify_permission( const permission_object& permission, const Authority& a, const fc::time_point& pending_block_time ) {
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
        po.last_updated = pending_block_time;
    });
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

}