#include <eosio/deferred_transaction_sidecar_plugin/deferred_transaction_sidecar_plugin.hpp>

#include <eosio/chain/account_object.hpp>
#include <eosio/chain/code_object.hpp>
#include <eosio/chain/generated_transaction_object.hpp>
#include <eosio/chain/permission_object.hpp>

#include <algorithm>
#include <boost/signals2/connection.hpp>
#include <filesystem>
#include <fstream>
#include <optional>

namespace eosio {

using boost::signals2::scoped_connection;

static auto sidecar_plugin = application::register_plugin<deferred_transaction_sidecar_plugin>();

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

   void write_snapshot_state() {
      write_state(chain.head_block_id(), path);
   }

   void write_accepted_state(const chain::block_state_ptr& block_state) {
      const auto source_block_id = block_state->id;
      write_state(source_block_id, directory / (source_block_id.str() + ".json"));
   }

   void write_state(const chain::block_id_type& source_block_id, const std::filesystem::path& output_path) {
      EOS_ASSERT(!output_path.empty(), chain::plugin_exception, "deferred sidecar output path is empty");
      EOS_ASSERT(!std::filesystem::exists(output_path), chain::plugin_exception,
                 "refusing to overwrite deferred sidecar ${p}", ("p", output_path.string()));

      // chain_plugin has restored the snapshot before plugin startup. SHiP's
      // initial full-state record is anchored to this restored head block, so
      // the sidecar must use that ID rather than the next P2P-accepted block.
      std::ofstream output(output_path.string(), std::ios::out | std::ios::trunc);
      EOS_ASSERT(output, chain::plugin_exception, "cannot open deferred sidecar ${p}", ("p", output_path.string()));
      output << "{\"version\":1,\"source_block_id\":\"" << source_block_id.str()
             << "\",\"source_chain_id\":\"" << chain.get_chain_id().str()
             << "\",\"account_metadata\":[";

      bool first = true;
      const auto& metadata = chain.db().get_index<chain::account_metadata_index>();
      for (const auto& row : metadata.indices()) {
         if (!first)
            output << ',';
         first = false;
         output << "{\"name\":" << row.name.to_uint64_t()
                << ",\"recv_sequence\":" << row.recv_sequence
                << ",\"auth_sequence\":" << row.auth_sequence
                << ",\"code_sequence\":" << row.code_sequence
                << ",\"abi_sequence\":" << row.abi_sequence << "}";
      }
      output << "],\"code\":[";

      first = true;
      const auto& code = chain.db().get_index<chain::code_index>();
      for (const auto& row : code.indices()) {
         if (!first)
            output << ',';
         first = false;
         output << "{\"code_hash\":\"" << row.code_hash.str()
                << "\",\"vm_type\":" << static_cast<unsigned>(row.vm_type)
                << ",\"vm_version\":" << static_cast<unsigned>(row.vm_version)
                << ",\"code_ref_count\":" << row.code_ref_count
                << ",\"first_block_used\":" << row.first_block_used << "}";
      }
      output << "],\"permissions\":[";

      first = true;
      const auto& permissions = chain.db().get_index<chain::permission_index>();
      const auto& usages = chain.db().get_index<chain::permission_usage_index>();
      for (const auto& row : permissions.indices()) {
         if (!first)
            output << ',';
         first = false;
         const auto* usage = usages.find(row.usage_id);
         EOS_ASSERT(usage != nullptr, chain::plugin_exception,
                    "permission ${owner}/${name} has no usage row",
                    ("owner", row.owner.to_uint64_t())("name", row.name.to_uint64_t()));
         output << "{\"owner\":" << row.owner.to_uint64_t()
                << ",\"name\":" << row.name.to_uint64_t()
                << ",\"last_used\":" << usage->last_used.time_since_epoch().count() << "}";
      }
      output << "],\"transactions\":[";

      const auto& rows = chain.db().get_index<chain::generated_transaction_multi_index>();
      first = true;
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
      EOS_ASSERT(output, chain::plugin_exception, "failed writing deferred sidecar ${p}", ("p", output_path.string()));
      ilog("wrote deferred transaction sidecar ${p} for block ${id}", ("p", output_path.string())("id", source_block_id));
   }

   chain::controller& chain;
   std::filesystem::path path;
   std::filesystem::path directory;
   std::optional<scoped_connection> accepted_block_connection;
};

deferred_transaction_sidecar_plugin::deferred_transaction_sidecar_plugin() = default;

void deferred_transaction_sidecar_plugin::set_program_options(options_description&, options_description& cfg) {
   cfg.add_options()
      ("deferred-transaction-sidecar-path", bpo::value<std::filesystem::path>(),
       "write one complete chainbase sidecar at the restored snapshot head")
      ("deferred-transaction-sidecar-dir", bpo::value<std::filesystem::path>(),
       "write one complete chainbase sidecar at startup and after every accepted block");
}

void deferred_transaction_sidecar_plugin::plugin_initialize(const variables_map& options) {
   my = std::make_shared<deferred_transaction_sidecar_plugin_impl>(app().get_plugin<chain_plugin>().chain());
   const bool has_path = options.count("deferred-transaction-sidecar-path") != 0;
   const bool has_directory = options.count("deferred-transaction-sidecar-dir") != 0;
   EOS_ASSERT(has_path != has_directory, chain::plugin_exception,
              "set exactly one of --deferred-transaction-sidecar-path or --deferred-transaction-sidecar-dir");
   if (has_path) {
      my->path = options.at("deferred-transaction-sidecar-path").as<std::filesystem::path>();
      EOS_ASSERT(!std::filesystem::exists(my->path), chain::plugin_exception,
                 "refusing to overwrite deferred sidecar ${p}", ("p", my->path.string()));
   } else {
      my->directory = options.at("deferred-transaction-sidecar-dir").as<std::filesystem::path>();
      std::error_code error;
      std::filesystem::create_directories(my->directory, error);
      EOS_ASSERT(!error, chain::plugin_exception,
                 "cannot create deferred sidecar directory ${p}: ${e}",
                 ("p", my->directory.string())("e", error.message()));
   }
}

void deferred_transaction_sidecar_plugin::plugin_startup() {
   if (!my->path.empty()) {
      my->write_snapshot_state();
      return;
   }
   my->write_state(my->chain.head_block_id(), my->directory / (my->chain.head_block_id().str() + ".json"));
   my->accepted_block_connection.emplace(
      my->chain.accepted_block.connect([impl = my](const chain::block_state_ptr& block_state) {
         impl->write_accepted_state(block_state);
      }));
}

void deferred_transaction_sidecar_plugin::plugin_shutdown() {
   if (my)
      my->accepted_block_connection.reset();
}

} // namespace eosio
