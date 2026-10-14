import { IConstants } from "../types";

declare global {
  interface Window {
    PULSEVM_LOCALNET: {
      chain_id: string;
      initial_timestamp: string;
      system_account: string;
      core_symbol: string;
      core_precision: number;
    };
  }
}

// This file is loaded by index.html before the app, so changing the genesis,
// host port, or chain ID does not require rebuilding the frontend.
const config = window.PULSEVM_LOCALNET;
const origin = window.location.origin;
const rpc = `${origin}/rpc`;

const constants: IConstants = {
  CHAIN: "local",
  CHAIN_ID: config.chain_id,
  CHAIN_START_DATE: new Date(`${config.initial_timestamp.replace(/Z$/, "")}Z`),
  DEFAULT_ENDPOINTS: [rpc],
  ACTIONS_ENDPOINTS: [rpc],
  TRANSACTIONS_ENDPOINTS: [origin],
  PROVIDER_ENDPOINTS: [{
    chainId: config.chain_id,
    port: Number(window.location.port || (window.location.protocol === "https:" ? 443 : 80)),
    protocol: window.location.protocol.replace(":", ""),
    host: window.location.host,
    httpEndpoint: rpc,
    blockchain: "eos",
  }],
  HISTORY_TYPES: ["hyperion"],
  HYPERION_URL: origin,
  API_URL: "",
  CORE_SYMBOL: config.core_symbol,
  CORE_PRECISION: config.core_precision,
  DISPLAY_CHAIN: "PulseVM Local",
  DOMAIN_TITLE: "PulseVM Local Explorer",
  KEY_PREFIX: "EOS",
  SYSTEM_DOMAIN: config.system_account,
  USE_PULSE_VM: true,
  NO_PRIMUS: true,
  VOTING_ENABLED: false,
  NFTS_ENABLED: false,
  SUPPORTS_FREE_CPU: false,
};

export default constants;
