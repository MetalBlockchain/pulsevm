#pragma once
#include <pulsevm/chain/abi_def.hpp>
#include <pulsevm/chain/abi_serializer.hpp>
#include <pulsevm/chain/asset.hpp>
#include <pulsevm/chain/name.hpp>

#include <boost/algorithm/string.hpp>

#include <fc/io/json.hpp>
#include <fc/variant.hpp>

#include "database.hpp"

namespace pulsevm { namespace chain {

   constexpr const char i64[]       = "i64";
   constexpr const char i128[]      = "i128";
   constexpr const char i256[]      = "i256";
   constexpr const char float64[]   = "float64";
   constexpr const char float128[]  = "float128";
   constexpr const char sha256[]    = "sha256";
   constexpr const char ripemd160[] = "ripemd160";
   constexpr const char dec[]       = "dec";
   constexpr const char hex[]       = "hex";

   static constexpr uint32_t     max_return_items = 1000;
   const static uint32_t         default_abi_serializer_max_time_us = 15*1000;
   const static fc::microseconds abi_serializer_max_time = fc::microseconds( default_abi_serializer_max_time_us );
   const static bool shorten_abi_errors = true;

   struct account_resource_info {
      int64_t used = 0;
      int64_t available = 0;
      int64_t max = 0;
      std::optional<block_timestamp_type> last_usage_update_time;    // optional for backward nodeos support
      std::optional<int64_t> current_used;  // optional for backward nodeos support
      void set( const resource_limits::account_resource_limit& arl)
      {
         used = arl.used;
         available = arl.available;
         max = arl.max;
         last_usage_update_time = arl.last_usage_update_time;
         current_used = arl.current_used;
      }
   };

   struct linked_action {
      name                account;
      std::optional<name> action;
   };

   struct permission {
      name                                       perm_name;
      name                                       parent;
      authority                                  required_auth;
      std::optional<std::vector<linked_action>>  linked_actions;
   };

   struct get_account_results {
      name                       account_name;
      uint32_t                   head_block_num = 0;
      fc::time_point             head_block_time;

      bool                       privileged = false;
      fc::time_point             last_code_update;
      fc::time_point             created;

      std::optional<asset>       core_liquid_balance;

      int64_t                    ram_quota  = 0;
      int64_t                    net_weight = 0;
      int64_t                    cpu_weight = 0;

      account_resource_info      net_limit;
      account_resource_info      cpu_limit;
      int64_t                    ram_usage = 0;

      vector<permission>         permissions;

      fc::variant                total_resources;
      fc::variant                self_delegated_bandwidth;
      fc::variant                refund_request;
      fc::variant                voter_info;
      fc::variant                rex_info;

      std::optional<resource_limits::account_resource_limit> subjective_cpu_bill_limit;
      std::vector<linked_action> eosio_any_linked_actions;
   };

   struct get_currency_stats_result {
      asset          supply;
      asset          max_supply;
      account_name   issuer;
   };

   struct get_table_rows_params {
      bool                 json = false;
      name                 code;
      string               scope;
      name                 table;
      string               table_key;
      string               lower_bound;
      string               upper_bound;
      uint32_t             limit = 10;
      string               key_type;  // type of key specified by index_position
      string               index_position; // 1 - primary (first), 2 - secondary index (in order defined by multi_index), 3 - third index, etc
      string               encode_type{"dec"}; //dec, hex , default=dec
      bool                 reverse = false;
      bool                 show_payer = false; // show RAM payer
      uint32_t             time_limit_ms = 10000; // time limit for processing the request, in milliseconds
   };

   struct get_table_rows_result {
      vector<fc::variant> rows; ///< one row per item, either encoded as hex String or JSON object
      bool                more = false; ///< true if last element in data is not the end and sizeof data() < limit
      string              next_key; ///< fill lower_bound with this value to fetch more rows
   };

   using get_table_rows_return_t = std::function<chain::t_or_exception<get_table_rows_result>()>;

   static void copy_inline_row(const key_value_object& obj, vector<char>& data) {
      data.resize( obj.value.size() );
      memcpy( data.data(), obj.value.data(), obj.value.size() );
   }

   template<typename Function>
   void walk_key_value_table(const database_wrapper& db, const name& code, const name& scope, const name& table, Function f)
   {
      const auto* t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = db.get_index<key_value_index, by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         for (auto itr = lower; itr != upper; ++itr) {
               if (!f(*itr)) {
               break;
               }
         }
      }
   }

   // see specializations for uint64_t and double in source file
   template<typename Type>
   Type convert_to_type(const string& str, const string& desc) {
      try {
         return fc::variant(str).as<Type>();
      } FC_RETHROW_EXCEPTIONS(warn, "Could not convert ${desc} string '${str}' to key type.", ("desc", desc)("str",str) )
   }

   uint64_t convert_to_type(const name &n, const string &desc);

   template<>
   uint64_t convert_to_type(const string& str, const string& desc);

   template<typename Type>
   string convert_to_string(const Type& source, const string& key_type, const string& encode_type, const string& desc);

   abi_def get_abi( const database_wrapper& db, uint64_t account );
   using get_account_return_t = std::function<t_or_exception<get_account_results>()>;
   rust::String get_account_info_without_core_symbol( const database_wrapper& db, uint64_t account, uint32_t head_block_num, const fc::time_point& head_block_time );
   rust::String get_account_info_with_core_symbol( const database_wrapper& db, uint64_t account, rust::Str expected_core_symbol, uint32_t head_block_num, const fc::time_point& head_block_time );
   get_account_results get_account_info( const database_wrapper& db, uint64_t account, std::optional<symbol> expected_core_symbol, uint32_t head_block_num, const fc::time_point& head_block_time );
   rust::String get_currency_balance_with_symbol( const database_wrapper& db, uint64_t code, uint64_t account, rust::Str symbol );
   rust::String get_currency_balance_without_symbol( const database_wrapper& db, uint64_t code, uint64_t account );
   rust::String get_currency_stats( const database_wrapper& db, uint64_t code, rust::Str symbol );
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
   );

   get_table_rows_return_t get_table_rows_internal( const database_wrapper& db, const get_table_rows_params& p, const fc::time_point& deadline );
   template <typename IndexType>
   get_table_rows_return_t get_table_rows_ex( const database_wrapper& db, const get_table_rows_params& p, abi_def&& abi, const fc::time_point& deadline ) {
        fc::time_point params_deadline = p.time_limit_ms ? std::min(fc::time_point::now().safe_add(fc::milliseconds(p.time_limit_ms)), deadline) : deadline;

        struct http_params_t {
            name table;
            bool shorten_abi_errors;
            bool json;
            bool show_payer;
            bool more;
            std::string next_key;
            vector<std::pair<vector<char>, name>> rows;
        };
        
        http_params_t http_params { p.table, shorten_abi_errors, p.json, p.show_payer, false  };
        uint64_t scope = convert_to_type<uint64_t>(p.scope, "scope");

        const auto* t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple(p.code, name(scope), p.table));
        if( t_id != nullptr ) {
            const auto& idx = db.get_index<IndexType, by_scope_primary>();
            auto lower_bound_lookup_tuple = std::make_tuple( t_id->id, std::numeric_limits<uint64_t>::lowest() );
            auto upper_bound_lookup_tuple = std::make_tuple( t_id->id, std::numeric_limits<uint64_t>::max() );

            if( p.lower_bound.size() ) {
               if( p.key_type == "name" ) {
                  name s(p.lower_bound);
                  std::get<1>(lower_bound_lookup_tuple) = s.to_uint64_t();
               } else {
                  auto lv = convert_to_type<typename IndexType::value_type::key_type>( p.lower_bound, "lower_bound" );
                  std::get<1>(lower_bound_lookup_tuple) = lv;
               }
            }

            if( p.upper_bound.size() ) {
               if( p.key_type == "name" ) {
                  name s(p.upper_bound);
                  std::get<1>(upper_bound_lookup_tuple) = s.to_uint64_t();
               } else {
                  auto uv = convert_to_type<typename IndexType::value_type::key_type>( p.upper_bound, "upper_bound" );
                  std::get<1>(upper_bound_lookup_tuple) = uv;
               }
            }

            if( upper_bound_lookup_tuple < lower_bound_lookup_tuple  )
               return []() ->  chain::t_or_exception<get_table_rows_result> {
                  return get_table_rows_result();
               };

            auto walk_table_row_range = [&]( auto itr, auto end_itr ) {
               vector<char> data;
               uint32_t limit = p.limit;
               if (deadline != fc::time_point::maximum() && limit > max_return_items)
                  limit = max_return_items;
               for( unsigned int count = 0; count < limit && itr != end_itr; ++count, ++itr ) {
                  copy_inline_row(*itr, data);
                  http_params.rows.emplace_back(std::move(data), itr->payer);
                  if (fc::time_point::now() >= params_deadline)
                     break;
               }
               if( itr != end_itr ) {
                  http_params.more = true;
                  http_params.next_key = convert_to_string(itr->primary_key, p.key_type, p.encode_type, "next_key - next lower bound");
               }
            };

            auto lower = idx.lower_bound( lower_bound_lookup_tuple );
            auto upper = idx.upper_bound( upper_bound_lookup_tuple );
            if( p.reverse ) {
               walk_table_row_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
            } else {
               walk_table_row_range( lower, upper );
            }
        }
        
        // not enforcing the deadline for that second processing part (the serialization), as it is not taking place
        // on the main thread, but in the http thread pool.
        return [p = std::move(http_params), abi=std::move(abi), abi_serializer_max_time=abi_serializer_max_time]() mutable ->
            chain::t_or_exception<get_table_rows_result> {
            get_table_rows_result result;
            abi_serializer abis;
            abis.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
            auto table_type = abis.get_table_type(p.table);
            
            for (auto& row : p.rows) {
                fc::variant data_var;
                if( p.json ) {
                data_var = abis.binary_to_variant(table_type, row.first,
                                                    abi_serializer::create_yield_function(abi_serializer_max_time),
                                                    p.shorten_abi_errors );
                } else {
                data_var = fc::variant(row.first);
                }

                if (p.show_payer) {
                result.rows.emplace_back(fc::mutable_variant_object("data", std::move(data_var))("payer", row.second));
                } else {
                result.rows.emplace_back(std::move(data_var));
                }            
            }
            result.more = p.more;
            result.next_key = p.next_key;
            return result;
        };
   }

   uint64_t get_table_index_name(const get_table_rows_params& p, bool& primary);

   template <typename IndexType, typename SecKeyType, typename ConvFn>
   get_table_rows_return_t
   get_table_rows_by_seckey( const database_wrapper& db, const get_table_rows_params& p, abi_def&& abi, const fc::time_point& deadline, ConvFn conv ) {

      fc::time_point params_deadline = p.time_limit_ms ? std::min(fc::time_point::now().safe_add(fc::milliseconds(p.time_limit_ms)), deadline) : deadline;

      struct http_params_t {
         name table;
         bool shorten_abi_errors;
         bool json;
         bool show_payer;
         bool more;
         std::string next_key;
         vector<std::pair<vector<char>, name>> rows;
      };
      
      http_params_t http_params { p.table, shorten_abi_errors, p.json, p.show_payer, false  };
      name scope{ convert_to_type<uint64_t>(p.scope, "scope") };

      bool primary = false;
      const uint64_t table_with_index = get_table_index_name(p, primary);
      const auto* t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple(p.code, scope, p.table));
      const auto* index_t_id = db.find<table_id_object, by_code_scope_table>(boost::make_tuple(p.code, scope, name(table_with_index)));
      if( t_id != nullptr && index_t_id != nullptr ) {
         using secondary_key_type = std::invoke_result_t<decltype(conv), SecKeyType>;
         static_assert( std::is_same<typename IndexType::value_type::secondary_key_type, secondary_key_type>::value, "Return type of conv does not match type of secondary key for IndexType" );

         const auto& secidx = db.get_index<IndexType, by_secondary>();
         auto lower_bound_lookup_tuple = std::make_tuple( index_t_id->id._id, secondary_key_traits<secondary_key_type>::true_lowest(),
                                                          std::numeric_limits<uint64_t>::lowest() );
         auto upper_bound_lookup_tuple = std::make_tuple( index_t_id->id._id,
                                                          secondary_key_traits<secondary_key_type>::true_highest(),
                                                          std::numeric_limits<uint64_t>::max() );

         if( p.lower_bound.size() ) {
            if( p.key_type == "name" ) {
               if constexpr (std::is_same_v<uint64_t, SecKeyType>) {
                  SecKeyType lv = convert_to_type(name{p.lower_bound}, "lower_bound name");
                  std::get<1>(lower_bound_lookup_tuple) = conv(lv);
               } else {
                  EOS_ASSERT(false, chain::contract_table_query_exception, "Invalid key type of eosio::name ${nm} for lower bound", ("nm", p.lower_bound));
               }
            } else {
               SecKeyType lv = convert_to_type<SecKeyType>( p.lower_bound, "lower_bound" );
               std::get<1>(lower_bound_lookup_tuple) = conv( lv );
            }
         }

         if( p.upper_bound.size() ) {
            if( p.key_type == "name" ) {
               if constexpr (std::is_same_v<uint64_t, SecKeyType>) {
                  SecKeyType uv = convert_to_type(name{p.upper_bound}, "upper_bound name");
                  std::get<1>(upper_bound_lookup_tuple) = conv(uv);
               } else {
                  EOS_ASSERT(false, chain::contract_table_query_exception, "Invalid key type of eosio::name ${nm} for upper bound", ("nm", p.upper_bound));
               }
            } else {
               SecKeyType uv = convert_to_type<SecKeyType>( p.upper_bound, "upper_bound" );
               std::get<1>(upper_bound_lookup_tuple) = conv( uv );
            }
         }

         if( upper_bound_lookup_tuple < lower_bound_lookup_tuple )
            return []() ->  chain::t_or_exception<get_table_rows_result> {
               return get_table_rows_result();
            };

         auto walk_table_row_range = [&]( auto itr, auto end_itr ) {
            vector<char> data;
            uint32_t limit = p.limit;
            if (deadline != fc::time_point::maximum() && limit > max_return_items)
               limit = max_return_items;
            for( unsigned int count = 0; count < limit && itr != end_itr; ++count, ++itr ) {
               const auto* itr2 = db.find<chain::key_value_object, chain::by_scope_primary>( boost::make_tuple(t_id->id, itr->primary_key) );
               if( itr2 == nullptr ) continue;
               copy_inline_row(*itr2, data);
               http_params.rows.emplace_back(std::move(data), itr->payer);
               if (fc::time_point::now() >= params_deadline)
                  break;
            }
            if( itr != end_itr ) {
               http_params.more = true;
               http_params.next_key = convert_to_string(itr->secondary_key, p.key_type, p.encode_type, "next_key - next lower bound");
            }
         };

         auto lower = secidx.lower_bound( lower_bound_lookup_tuple );
         auto upper = secidx.upper_bound( upper_bound_lookup_tuple );
         if( p.reverse ) {
            walk_table_row_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
         } else {
            walk_table_row_range( lower, upper );
         }
      }

      // not enforcing the deadline for that second processing part (the serialization), as it is not taking place
      // on the main thread, but in the http thread pool.
      return [p = std::move(http_params), abi=std::move(abi), abi_serializer_max_time=abi_serializer_max_time]() mutable ->
         chain::t_or_exception<get_table_rows_result> {
         get_table_rows_result result;
         abi_serializer abis;
         abis.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
         auto table_type = abis.get_table_type(p.table);
         
         for (auto& row : p.rows) {
            fc::variant data_var;
            if( p.json ) {
               data_var = abis.binary_to_variant(table_type, row.first,
                                                 abi_serializer::create_yield_function(abi_serializer_max_time),
                                                 p.shorten_abi_errors );
            } else {
               data_var = fc::variant(row.first);
            }

            if (p.show_payer) {
               result.rows.emplace_back(fc::mutable_variant_object("data", std::move(data_var))("payer", row.second));
            } else {
               result.rows.emplace_back(std::move(data_var));
            }            
         }
         result.more = p.more;
         result.next_key = p.next_key;
         return result;
      };
   }
} }

FC_REFLECT( pulsevm::chain::linked_action, (account)(action) )
FC_REFLECT( pulsevm::chain::permission, (perm_name)(parent)(required_auth)(linked_actions) )
FC_REFLECT( pulsevm::chain::account_resource_info, (used)(available)(max)(last_usage_update_time)(current_used) )
FC_REFLECT( pulsevm::chain::get_account_results,
            (account_name)(head_block_num)(head_block_time)(privileged)(last_code_update)(created)
            (core_liquid_balance)(ram_quota)(net_weight)(cpu_weight)(net_limit)(cpu_limit)(ram_usage)(permissions)
            (total_resources)(self_delegated_bandwidth)(refund_request)(voter_info)(rex_info)
            (subjective_cpu_bill_limit) (eosio_any_linked_actions) )
FC_REFLECT( pulsevm::chain::get_table_rows_result, (rows)(more)(next_key) );
FC_REFLECT( pulsevm::chain::get_currency_stats_result, (supply)(max_supply)(issuer));