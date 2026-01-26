#pragma once
#include "block_header.hpp"
#include "transaction.hpp"

namespace pulsevm { namespace chain {

   /**
    * When a transaction is referenced by a block it could imply one of several outcomes which
    * describe the state-transition undertaken by the block producer.
    */

   struct transaction_receipt_header {
      enum status_enum {
         executed  = 0, ///< succeed, no error handler executed
         soft_fail = 1, ///< objectively failed (not executed), error handler executed
         hard_fail = 2, ///< objectively failed and error handler objectively failed thus no state change
         delayed   = 3, ///< transaction delayed/deferred/scheduled for future execution
         expired   = 4  ///< transaction expired and storage space refuned to user
      };

      transaction_receipt_header():status(hard_fail){}
      explicit transaction_receipt_header( status_enum s ):status(s){}

      friend inline bool operator ==( const transaction_receipt_header& lhs, const transaction_receipt_header& rhs ) {
         return std::tie(lhs.status, lhs.cpu_usage_us, lhs.net_usage_words) == std::tie(rhs.status, rhs.cpu_usage_us, rhs.net_usage_words);
      }

      fc::enum_type<uint8_t,status_enum>   status;
      uint32_t                             cpu_usage_us = 0; ///< total billed CPU usage (microseconds)
      fc::unsigned_int                     net_usage_words; ///<  total billed NET usage, so we can reconstruct resource state when skipping context free data... hard failures...
   };

   struct transaction_receipt : public transaction_receipt_header {

      transaction_receipt():transaction_receipt_header(){}
      explicit transaction_receipt( const transaction_id_type& tid ):transaction_receipt_header(executed),trx(tid){}
      explicit transaction_receipt( const packed_transaction& ptrx ):transaction_receipt_header(executed),trx(std::in_place_type<packed_transaction>, ptrx){}

      std::variant<transaction_id_type, packed_transaction> trx;

      digest_type digest()const {
         digest_type::encoder enc;
         fc::raw::pack( enc, status );
         fc::raw::pack( enc, cpu_usage_us );
         fc::raw::pack( enc, net_usage_words );
         if( std::holds_alternative<transaction_id_type>(trx) )
            fc::raw::pack( enc, std::get<transaction_id_type>(trx) );
         else
            fc::raw::pack( enc, std::get<packed_transaction>(trx).packed_digest() );
         return enc.result();
      }
   };

   using signed_block_ptr = std::shared_ptr<const signed_block>;
   // mutable_block_ptr is built up until it is signed and converted to signed_block_ptr
   // mutable_block_ptr is not thread safe and should be moved into signed_block_ptr when complete
   using mutable_block_ptr = std::unique_ptr<signed_block>;

   /**
    */
   struct signed_block : public signed_block_header{
   private:
      signed_block( const signed_block& ) = default;
      explicit signed_block( const signed_block_header& h ):signed_block_header(h){}
   public:
      signed_block() = default;
      signed_block( signed_block&& ) = default;
      signed_block& operator=(const signed_block&) = delete;
      signed_block& operator=(signed_block&&) = default;
      mutable_block_ptr clone() const { return std::unique_ptr<signed_block>(new signed_block(*this)); }
      static mutable_block_ptr create_mutable_block(const signed_block_header& h) { return std::unique_ptr<signed_block>(new signed_block(h)); }
      static signed_block_ptr  create_signed_block(mutable_block_ptr&& b) { b->pack(); return signed_block_ptr{std::move(b)}; }

      deque<transaction_receipt>   transactions; /// new or generated transactions

      const bytes& packed_signed_block() const { assert(!packed_block.empty()); return packed_block; }

   private:
      friend struct block_state;
      friend struct block_state_legacy;
      template<typename Stream> friend void fc::raw::unpack(Stream& s, pulsevm::chain::signed_block& v);
      void pack() { packed_block = fc::raw::pack( *this ); }

      bytes packed_block; // packed this
   };

   struct producer_confirmation {
      block_id_type   block_id;
      digest_type     block_digest;
      account_name    producer;
      signature_type  sig;
   };

} } /// pulsevm::chain

FC_REFLECT_ENUM( pulsevm::chain::transaction_receipt::status_enum,
                 (executed)(soft_fail)(hard_fail)(delayed)(expired) )

FC_REFLECT(pulsevm::chain::transaction_receipt_header, (status)(cpu_usage_us)(net_usage_words) )
FC_REFLECT_DERIVED(pulsevm::chain::transaction_receipt, (pulsevm::chain::transaction_receipt_header), (trx) )
FC_REFLECT_DERIVED(pulsevm::chain::signed_block, (pulsevm::chain::signed_block_header), (transactions) )

namespace fc::raw {
   template <typename Stream>
   void unpack(Stream& s, pulsevm::chain::signed_block& v) {
      try {
         if constexpr (requires { s.extract_mirror(); }) {
            fc::reflector<pulsevm::chain::signed_block>::visit( fc::raw::detail::unpack_object_visitor<Stream, pulsevm::chain::signed_block>( v, s ) );
            v.packed_block = s.extract_mirror();
         } else {
            fc::datastream_mirror<Stream> ds(s, sizeof(pulsevm::chain::signed_block) + 4096);
            fc::reflector<pulsevm::chain::signed_block>::visit( fc::raw::detail::unpack_object_visitor<fc::datastream_mirror<Stream>, pulsevm::chain::signed_block>( v, ds ) );
            v.packed_block = ds.extract_mirror();
         }
      } FC_RETHROW_EXCEPTIONS(warn, "error unpacking signed_block")
   }
}

