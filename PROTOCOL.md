# PulseVM

A virtual machine focused on banking and efficient smart contracts using Snowman as the consensus algorithm.

## Accounts

Accounts are identified by a human readable name, similar to EOS the maximum length is 12.

## Resource Model

To be determined.

## Transactions

PulseVM will support the following transaction types:
 - CreateAccountTx: registers an account, assuming it doesn't already exist
 - UpdateAccountAuthTx: updates an account's authorization configuration
 - CreateAssetTx: creates an asset using the provided configuration
 - CreateDirectDebitMandateTx: establishes a contract allowing the beneficiary to debit the user's account according to the mandate's rules
 - PushAssetTx: initiated by the sender, transfers an asset with the given quantity from the sender to the receiver
 - PullAssetTx: initiated by the receiver, pulls funds from an account according to the mandate's rules
 - SetContractTx: updates the smart contract and/or ABI of a given account
 - CallContractTx: calls a given method of a smart contract

## Smart Contracts

PulseVM will use the WebAssembly standard to facilitate the deployment and execution of smart contracts.
The PulseSDK will allow developers to easily develop contracts, more info on this to follow.