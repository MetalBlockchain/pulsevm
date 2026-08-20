#include <eosio/deferred_transaction_sidecar_plugin/deferred_transaction_sidecar_plugin.hpp>

#include <eosio/chain/generated_transaction_object.hpp>
#include <fc/filesystem.hpp>

#include <boost/signals2/connection.hpp>

#include <algorithm>
#include <fstream>

namespace eosio {

static appbase::abstract_plugin& sidecar_plugin = app().register_plugin<deferred_transaction_sidecar_plugin>();

static std::string uint128_to_decimal(chain::uint128_t value) {
   if (value == 0)
      return "0";

   std::string result;
   while (value != 0) {
      result.push_back(static_cast<char>('0' + (value % 10)));
      value /= 10;
   }
   std::reverse(result.begin(), result.end());
   return result;
}

class deferred_transaction_sidecar_plugin_impl {
public:
   explicit deferred_transaction_sidecar_plugin_impl(chain::controller& chain)
      : chain(chain) {}

   void connect() {
      accepted_block_connection.emplace(chain.accepted_block.connect(
         [this](const chain::block_state_ptr& block) { write_once(block); }));
   }

   void disconnect() { accepted_block_connection.reset(); }

   void write_once(const chain::block_state_ptr& block) {
      if (wrote)
         return;
      wrote = true;

      // This callback sees the post-block chainbase state. It is intentionally
      // attached to the same accepted_block signal used by state_history_plugin,
      // so source_block_id is the block identity the Rust importer checks.
      std::ofstream output(path.string(), std::ios::out | std::ios::trunc);
      EOS_ASSERT(output, chain::plugin_exception, "cannot open deferred sidecar ${p}", ("p", path.string()));
      output << "{\"version\":1,\"source_block_id\":\"" << block->id.str()
             << "\",\"transactions\":[";

      const auto& rows = chain.db().get_index<chain::generated_transaction_multi_index>();
      bool first = true;
      for (const auto& row : rows.indices()) {
         if (!first)
            output << ',';
         first = false;
         output << "{\"sender\":" << row.sender.to_uint64_t()
                << ",\"sender_id\":\"" << uint128_to_decimal(row.sender_id)
                << "\",\"payer\":" << row.payer.to_uint64_t()
                << ",\"trx_id\":\"" << row.trx_id.str()
                << "\",\"delay_until\":" << row.delay_until.time_since_epoch().count()
                << ",\"expiration\":" << row.expiration.time_since_epoch().count()
                << ",\"published\":" << row.published.time_since_epoch().count()
                << ",\"packed_trx\":\"";
         static constexpr char hex[] = "0123456789abcdef";
         for (const unsigned char byte : row.packed_trx) {
            output << hex[byte >> 4] << hex[byte & 0x0f];
         }
         output << "\"}";
      }
      output << "]}\n";
      output.close();
      EOS_ASSERT(output, chain::plugin_exception, "failed writing deferred sidecar ${p}", ("p", path.string()));
      ilog("wrote deferred transaction sidecar ${p} for block ${id}", ("p", path.string())("id", block->id));
   }

   chain::controller& chain;
   bfs::path path;
   bool wrote = false;
   fc::optional<boost::signals2::scoped_connection> accepted_block_connection;
};

deferred_transaction_sidecar_plugin::deferred_transaction_sidecar_plugin() = default;

void deferred_transaction_sidecar_plugin::set_program_options(options_description&, options_description& cfg) {
   cfg.add_options()("deferred-transaction-sidecar-path", bpo::value<bfs::path>()->required(),
      "write the complete generated_transaction chainbase sidecar at the first accepted block");
}

void deferred_transaction_sidecar_plugin::plugin_initialize(const variables_map& options) {
   my = std::make_shared<deferred_transaction_sidecar_plugin_impl>(app().get_plugin<chain_plugin>().chain());
   my->path = options.at("deferred-transaction-sidecar-path").as<bfs::path>();
   EOS_ASSERT(!fc::exists(my->path), chain::plugin_exception,
              "refusing to overwrite deferred sidecar ${p}", ("p", my->path.string()));
}

void deferred_transaction_sidecar_plugin::plugin_startup() { my->connect(); }

void deferred_transaction_sidecar_plugin::plugin_shutdown() { my->disconnect(); }

} // namespace eosio
