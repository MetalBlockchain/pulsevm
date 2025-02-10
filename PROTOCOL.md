# PulseVM

A virtual machine, developed by Metallicus, focused on banking and efficient smart contracts using Snowman as the consensus algorithm. This VM is based on the EOS codebase with some protocol level changes.

## Accounts

Each account is identified by a human readable name between 1 and 12 characters in length. The characters can include a-z, 1-5, and optional dots (.) except the last character. This allows exactly 1,152,921,504,606,846,975 accounts minus one.

An example of such a name could be `glenn` or `proton.wrap`.

### Account Metadata

The following data is stored for an account:

| Field | Type | Description  |
|-----|----|---|
|account_name|name|Name of the account|
|privileged|bool|Is the account priviliged?|
|created|uint64|Time account was created|
|last_code_update|uint64|Time account code was set/updated|

## Permissions

Permissions control what Pulse accounts can do and how actions are authorized. This is accomplished through a flexible permission structure that links each account to a list of hierarchical named permissions, and each named permission to an authority table (see `permission` schema below).

|Name           |Type               |Description|
|----           |-----              |-----|
|perm_name      |name               |named permission   |
|parent         |name               |parent's named permission|
|required_auth  |authority          |associated authority table|

The `parent` field links the named permission level to its parent permission. This is what allows hierarchical permission levels in Pulse.

### Owner permission

The `owner` permission sits at the root of the permission hierarchy for every account. It is therefore the highest relative permission an account can have within its permission structure. Although the `owner` permission can do anything a lower level permission can, it is typically used for recovery purposes when a lower permission has been compromised. As such, keys associated with the `owner` permission are typically kept in cold storage, not used for signing regular operations.

### Active permission

The default permission linked to all actions is `active`, which sits one level below the `owner` permission within the hierarchy structure. As a result, the `active` permission can do anything the `owner` permission can, except changing the keys associated with the owner. The `active` permission is typically used for voting, transferring funds, and other account operations. For more specific actions, custom permissions are typically created below the `active` permission and mapped to specific contracts or actions.

## Authority table

Each account's permission can be linked to an authority table used to determine whether a given action authorization can be satisfied. The authority table contains the applicable permission name and threshold, the "factors" and their weights, all of which are used in the evaluation to determine whether the authorization can be satisfied. The permission threshold is the target numerical value that must be reached to satisfy the action authorization (see `authority` schema below):

|Name       |Type                       |Description|
|-          |-                          |-|
|threshold  |uint32_t                   |threshold value to satisfy authorization|
|keys       |[]key_weight               |list of public keys and weights|
|accounts   |[]permission_level_weight  |list of account@permission levels and weights|

>Please note that unlike the EOS codebase, we do not include the `wait_level` permission in the authority schema. This is a design decision we made as we don't intend to support deferred transactions.

## Default token

The default token is called the `SYS` token. It is the main token used to pay for resources.

## Resource Model

The resource model is split up in 3 pieces:
- RAM: Determines the amount of **data** an account can store, expressed in **kilobytes (KiB)**
- CPU: Determines the amount of **time** this account can use for transactions, expressed in **microseconds (μs)**
- NET: Determines the amount of **bandwidth** this account can use, expressed in **bytes**

> A critical difference with EOS is that in Pulse **CPU** is measured deterministically as opposed to arbitrarily. In EOS, CPU is measured as the amount of time a validator took to execute a specific transaction. This behavior is not ideal as a rogue validator could just consume every account's CPU resource by simply reporting incorrect CPU usage. In Pulse this metric will be determined based on the WASM instruction set and which host intrinsics were called.

## Blocks

Blocks are built as needed, **if there are no transactions then there will be no blocks**. A mempool is used to buffer transactions until they are included in a block. The target is 500 milliseconds per block.

## Supported integer data types

- uint8 and int8
- uint16 and int16
- uint32 and int32
- uint64 and int64
- uint128 and int128
- uint256 and int256

Pulse does not intend to support floating point data types. We do this to stay in line with industry leading blockchains such as *Ethereum*. In financial applications it's very common to use integer based arithmetics.

## System contract

Upon genesis there is a default system contract deployed located at the reserved account called `pulse`, it comes with the following default methods:

- `pulse.newaccount`: registers an account, assuming it doesn't already exist
- `pulse.setcode`: updates or removes the WASM contract of a specific account
- `pulse.setabi`: updates or removes the ABI specification of a specific account
- `pulse.updateauth`: updates an account's authorization
- `pulse.deleteauth`: deletes a specific authority level, cannot be `owner` or `activity` authority
- `pulse.linkauth`
- `pulse.deleteauth`

These follow the same spec as the `eosio` implementation.

## Smart Contracts

PulseVM will use the **WebAssembly** standard to facilitate the deployment and execution of smart contracts. The PulseSDK will allow developers to easily develop contracts, more info on this to follow.

The default programming language for Pulse contracts will be TypeScript, accompanied with **AssemblyScript**.

### Smart Contract Migration

Even though Pulse is based on EOS, there are quite some differences when it comes to smart contracts. A migration will be necessary for most smart contracts. This migration should however be relatively simple for most contracts.

### Intrinsics

- `is_account(name n): bool`: Verifies that n is an existing account
- `get_account(name n): uint64`: Returns the data of an account
- `get_account_creation_time(name n): uint64`: Returns the creation date of an account
- `require_auth(name n): void`: Verify specified account exists in the set of provided auths
- `has_auth(name n): bool`: Checks whether specified account exists in the set of provided auths
- `current_receiver(): name`: Get the current receiver of the action
- `is_priviliged(name n): bool`: Returns whether the current account is priviliged
- `set_priviliged(name n, bool priviliged): void`: Set the priviliged flag on an account
- `get_sender(): name`: Return name of account that sent current action
- `pulse_assert(uint32 test, string message): void`: Asserts test condition
- `pulse_exit(uint32 code): void`: Exits current processing without failing
- `db_store_i64(uint64 scope, name table, name payer, uint64 id, const void * data, uint32 len): int32`: Store a record in a primary 64-bit integer index table
- `db_update_i64(int32 iterator, name payer, const void * data, uint32 len): void`: Update a record in a primary 64-bit integer index table
- `db_remove_i64(int32 iterator): void`: Remove a record from a primary 64-bit integer index table
- `db_get_i64(int32 iterator, const void * data, uint32 len): int32`: Get a record in a primary 64-bit integer index table
- `db_next_i64(int32 iterator, uint64 * primary): int32`: Find the table row following the referenced table row in a primary 64-bit integer index table
- `db_previous_i64(int32 iterator, uint64 * primary): int32`: Find the table row preceding the referenced table row in a primary 64-bit integer index table
- `db_find_i64(name code, uint64 scope, name table, uint64 id): int32`: Find a table row in a primary 64-bit integer index table by primary key
- `db_lowerbound_i64(name code, uint64 scope, name table, uint64 id): int32`: Find the table row in a primary 64-bit integer index table that matches the lowerbound condition for a given primary key
- `db_upperbound_i64(name code, uint64 scope, name table, uint64 id): int32`: Find the table row in a primary 64-bit integer index table that matches the upperbound condition for a given primary key
- `db_end_i64(name code, uint64 scope, name table): int32`: Get an iterator representing just-past-the-end of the last table row of a primary 64-bit integer index table
- `assert_sha256(bytes data, uint32 length, checksum256 hash): void`
- `assert_sha512(bytes data, uint32 length, checksum512 hash): void`
- `sha256(bytes data, uint32 length, checksum256* hash): void`
- `sha512(bytes data, uint32 length, checksum512* hash): void`

## JsonRPC API

Contrary to EOS, Pulse uses the JsonRPC specification to expose its API. The following methods will be available:

- `pulse.issueTx`: submits a transaction, executes it locally and broadcasts it to the network upon succesful execution
- `pulse.getAccount`: retrieves information about an account
- `pulse.getAccountBalance`: retrieves an account's balance of a specific token
- `pulse.getBlock`: retrieves information about a block
- `pulse.getInfo`: returns information about the chain
- `pulse.getCode`: returns the WASM code deployed to an account
- `pulse.getAbi`: returns the ABI specification of an account's smart contract
- `pulse.getRequiredKeys`: returns the keys required to sign a transaction
- `pulse.getTableRows`: returns the rows of a specific table