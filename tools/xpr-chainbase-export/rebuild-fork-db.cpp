#include <eosio/chain/block_log.hpp>
#include <eosio/chain/block_state.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/fork_database.hpp>
#include <eosio/chain/protocol_feature_manager.hpp>

#include <filesystem>
#include <iostream>
#include <memory>

using namespace eosio::chain;

int main(int argc, char** argv) {
   if (argc != 4) {
      std::cerr << "usage: rebuild-fork-db BLOCKS_DIR PROTOCOL_FEATURES_DIR OUTPUT_DIR\n";
      return 2;
   }

   const std::filesystem::path blocks_dir = argv[1];
   const std::filesystem::path protocol_features_dir = argv[2];
   const std::filesystem::path output_dir = argv[3];
   if (!std::filesystem::is_directory(blocks_dir)) {
      std::cerr << "blocks directory does not exist: " << blocks_dir << '\n';
      return 1;
   }
   if (!std::filesystem::is_directory(protocol_features_dir)) {
      std::cerr << "protocol-features directory does not exist: "
                << protocol_features_dir << '\n';
      return 1;
   }
   if (std::filesystem::exists(output_dir) &&
       (!std::filesystem::is_directory(output_dir) || !std::filesystem::is_empty(output_dir))) {
      std::cerr << "output must be absent or an empty directory: " << output_dir << '\n';
      return 1;
   }
   const auto genesis = block_log::extract_genesis_state(blocks_dir);
   if (!genesis) {
      std::cerr << "block log does not contain a genesis state\n";
      return 1;
   }

   producer_authority_schedule initial_schedule = {
      0,
      {producer_authority{
         config::system_account_name,
         block_signing_authority_v0{1, {{genesis->initial_key, 1}}}
      }}
   };
   legacy::producer_schedule_type initial_legacy_schedule = {
      0,
      {{config::system_account_name, genesis->initial_key}}
   };

   block_header_state state;
   state.active_schedule = initial_schedule;
   state.pending_schedule.schedule = initial_schedule;
   state.pending_schedule.schedule_hash = fc::sha256::hash(initial_legacy_schedule);
   state.header.timestamp = genesis->initial_timestamp;
   state.header.action_mroot = genesis->compute_chain_id();
   state.id = state.header.calculate_id();
   state.block_num = state.header.block_num();
   state.activated_protocol_features = std::make_shared<protocol_feature_activation_set>();

   block_log blocks(blocks_dir);
   const auto head = blocks.head();
   if (!head) {
      std::cerr << "block log is empty\n";
      return 1;
   }
   if (const auto first = blocks.read_block_by_num(1); !first || first->calculate_id() != state.id) {
      std::cerr << "genesis header does not match block 1\n";
      return 1;
   }

   const auto protocol_features = initialize_protocol_features(protocol_features_dir, false);
   const auto activation_validator = [](block_timestamp_type,
                                        const flat_set<digest_type>&,
                                        const vector<digest_type>&) {};
   for (uint32_t block_num = 2; block_num <= head->block_num(); ++block_num) {
      auto block = blocks.read_block_by_num(block_num);
      if (!block) {
         std::cerr << "missing block " << block_num << '\n';
         return 1;
      }
      block_state next(state, block, protocol_features, activation_validator, true);
      if (next.id != block->calculate_id()) {
         std::cerr << "reconstructed id mismatch at block " << block_num << '\n';
         return 1;
      }
      state = std::move(next);
      if (block_num % 1000000 == 0)
         std::cerr << "reconstructed block " << block_num << '\n';
   }

   std::filesystem::create_directories(output_dir);
   fork_database forks(output_dir);
   forks.reset(state);
   forks.close();
   std::cout << "wrote fork database at block " << state.block_num
             << " id " << state.id.str() << '\n';
   return 0;
}
