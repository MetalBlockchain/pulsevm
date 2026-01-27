#pragma once
#include "block_timestamp.hpp"
#include "types.hpp"

#include <optional>
#include <type_traits>

namespace pulsevm::chain {

   using validator_t = const std::function<void(block_timestamp_type, const flat_set<digest_type>&, const vector<digest_type>&)>;

   struct block_header
   {
      block_timestamp_type             timestamp;
      name                             producer;
      block_id_type                    previous;
      checksum256_type                 transaction_mroot;
      checksum256_type                 action_mroot;

      digest_type       digest()const;
      block_id_type     calculate_id() const;
      uint32_t          block_num() const { return num_from_id(previous) + 1; }
      static uint32_t   num_from_id(const block_id_type& id);
      uint32_t          protocol_version() const { return 0; }
   };


   struct signed_block_header : public block_header
   {
      signature_type    producer_signature;
   };

} /// namespace pulsevm::chain

FC_REFLECT(pulsevm::chain::block_header, (timestamp)(producer)(previous)(transaction_mroot)(action_mroot))

FC_REFLECT_DERIVED(pulsevm::chain::signed_block_header, (pulsevm::chain::block_header), (producer_signature))
