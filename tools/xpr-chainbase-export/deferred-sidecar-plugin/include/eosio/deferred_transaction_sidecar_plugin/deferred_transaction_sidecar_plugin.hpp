#pragma once

#include <appbase/application.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>

#include <memory>

namespace eosio {

using namespace appbase;

class deferred_transaction_sidecar_plugin_impl;
using deferred_transaction_sidecar_ptr = std::shared_ptr<deferred_transaction_sidecar_plugin_impl>;

class deferred_transaction_sidecar_plugin : public plugin<deferred_transaction_sidecar_plugin> {
public:
   APPBASE_PLUGIN_REQUIRES((chain_plugin))

   deferred_transaction_sidecar_plugin();
   deferred_transaction_sidecar_plugin(const deferred_transaction_sidecar_plugin&) = delete;
   deferred_transaction_sidecar_plugin(deferred_transaction_sidecar_plugin&&) = delete;
   deferred_transaction_sidecar_plugin& operator=(const deferred_transaction_sidecar_plugin&) = delete;
   deferred_transaction_sidecar_plugin& operator=(deferred_transaction_sidecar_plugin&&) = delete;
   ~deferred_transaction_sidecar_plugin() override = default;

   void set_program_options(options_description& cli, options_description& cfg) override;
   void plugin_initialize(const variables_map& options);
   void plugin_startup();
   void plugin_shutdown();

private:
   deferred_transaction_sidecar_ptr my;
};

} // namespace eosio
