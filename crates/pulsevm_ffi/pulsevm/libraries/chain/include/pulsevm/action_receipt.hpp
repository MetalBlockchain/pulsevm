#pragma once

#include <pulsevm/types.hpp>

namespace pulsevm { namespace chain {

   /**
    *  For each action dispatched this receipt is generated
    */
   struct action_receipt {
      account_name                    receiver;
      digest_type                     act_digest;
      uint64_t                        global_sequence = 0; ///< total number of actions dispatched since genesis
      uint64_t                        recv_sequence   = 0; ///< total number of actions with this receiver since genesis
      flat_map<account_name,uint64_t> auth_sequence;
      fc::unsigned_int                code_sequence = 0; ///< total number of setcodes
      fc::unsigned_int                abi_sequence  = 0; ///< total number of setabis

      digest_type digest()const {
         digest_type::encoder e;
         fc::raw::pack(e, receiver);
         fc::raw::pack(e, act_digest);
         fc::raw::pack(e, global_sequence);
         fc::raw::pack(e, recv_sequence);
         fc::raw::pack(e, auth_sequence);
         fc::raw::pack(e, code_sequence);
         fc::raw::pack(e, abi_sequence);
         return e.result();
      }
   };

} }  /// namespace pulsevm::chain

FC_REFLECT( pulsevm::chain::action_receipt, (receiver)(act_digest)(global_sequence)(recv_sequence)(auth_sequence)(code_sequence)(abi_sequence) )
