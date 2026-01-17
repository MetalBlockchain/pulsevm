#pragma once

#include "types.hpp"
#include "action.hpp"

namespace pulsevm::chain {

   /**
    *  For each action dispatched this receipt is generated
    */
   struct action_receipt {
      name                            receiver;
      digest_type                     act_digest;
      uint64_t                        global_sequence = 0; ///< total number of actions dispatched since genesis
      uint64_t                        recv_sequence   = 0; ///< total number of actions with this receiver since genesis
      flat_map<name,uint64_t>         auth_sequence;
      fc::unsigned_int                code_sequence = 0; ///< total number of setcodes
      fc::unsigned_int                abi_sequence  = 0; ///< total number of setabis
   };

}  /// namespace pulsevm::chain

FC_REFLECT( pulsevm::chain::action_receipt, (receiver)(act_digest)(global_sequence)(recv_sequence)(auth_sequence)(code_sequence)(abi_sequence) )
