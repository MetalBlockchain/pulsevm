#pragma once

#include "types.hpp"
#include <chainbase/chainbase.hpp>
#include "multi_index_includes.hpp"

namespace pulsevm { namespace chain {

   /**
    * @class protocol_state_object
    * @brief Maintains global state information about consensus protocol rules
    * @ingroup object
    * @ingroup implementation
    */
   class protocol_state_object : public chainbase::object<protocol_state_object_type, protocol_state_object>
   {
   public:
      template<typename Constructor>
      protocol_state_object(Constructor&& c, chainbase::constructor_tag) :
         id(0) {
         c(*this);
      }

      struct activated_protocol_feature {
         digest_type feature_digest;
         uint32_t    activation_block_num = 0;

         activated_protocol_feature() = default;

         activated_protocol_feature( const digest_type& feature_digest, uint32_t activation_block_num )
         :feature_digest( feature_digest )
         ,activation_block_num( activation_block_num )
         {}

         bool operator==(const activated_protocol_feature& rhs) const {
            return feature_digest == rhs.feature_digest && activation_block_num == rhs.activation_block_num;
         }
      };

   public:
      id_type                                    id;
      shared_vector<activated_protocol_feature>  activated_protocol_features;
      shared_vector<digest_type>                 preactivated_protocol_features;
      uint32_t                                   num_supported_key_types = 0;
   };

   using protocol_state_multi_index = chainbase::shared_multi_index_container<
      protocol_state_object,
      indexed_by<
         ordered_unique<tag<by_id>,
            BOOST_MULTI_INDEX_MEMBER(protocol_state_object, protocol_state_object::id_type, id)
         >
      >
   >;
}}

CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::protocol_state_object, pulsevm::chain::protocol_state_multi_index)

FC_REFLECT(pulsevm::chain::protocol_state_object::activated_protocol_feature,
            (feature_digest)(activation_block_num)
          )

FC_REFLECT(pulsevm::chain::protocol_state_object,
            (activated_protocol_features)(preactivated_protocol_features)(num_supported_key_types)
          )