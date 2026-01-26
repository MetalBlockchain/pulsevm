#include "authority.hpp"

namespace fc {
   void to_variant(const pulsevm::chain::shared_public_key& var, fc::variant& vo) {
      vo = var.to_string({});
   }
} // namespace fc
