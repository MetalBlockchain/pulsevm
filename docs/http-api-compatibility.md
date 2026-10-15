# HTTP API compatibility

PulseVM exposes its native JSON-RPC API at `/rpc` and a nodeos-compatible
Antelope API for wallet and application clients. On MetalGo, call the chain
through:

```text
http://<node>:9650/ext/bc/<blockchain-id>/v1/chain/<method>
```

Each method is registered as an exact route because MetalGo registers VM
handlers by exact path. Appending a method to a single `/v1/chain` route does
not work with the supported MetalGo router.

## Supported chain methods

PulseVM currently registers these `/v1/chain` methods:

- `get_info`, `get_account`, `get_block`, `get_block_info`
- `get_abi`, `get_raw_abi`, `get_table_rows`, `get_table_by_scope`
- `get_currency_balance`, `get_currency_stats`, `get_code_hash`
- `get_required_keys`, `push_transaction`, and `send_transaction`

Requests use JSON POST bodies. `push_transaction` and `send_transaction`
accept the Antelope packed transaction fields and submit through PulseVM's
transaction admission path. Unsupported methods return an Antelope-shaped
404 response.

## Browser clients

Successful `/rpc` and `/v1/chain/*` responses include CORS headers for public
browser clients. `OPTIONS` requests return a preflight response allowing `POST`
and the `Content-Type` header. Credentialed cross-origin requests are not
enabled; wallet authorization is carried by transaction signatures.

The API only provides chain behavior and state that exist on the selected
PulseVM chain. An Antelope-compatible route does not imply that a particular
token contract, account, table, or wallet is deployed there.
