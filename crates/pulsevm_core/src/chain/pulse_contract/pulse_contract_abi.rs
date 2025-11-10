use crate::chain::{abi::{AbiActionDefinition, AbiDefinition, AbiStructDefinition, AbiTypeDefinition}, config::{DELETEAUTH_NAME, LINKAUTH_NAME, NEWACCOUNT_NAME, ONBLOCK_NAME, ONERROR_NAME, SETABI_NAME, SETCODE_NAME, UNLINKAUTH_NAME, UPDATEAUTH_NAME}};

pub fn get_pulse_contract_abi() -> AbiDefinition {
    AbiDefinition {
        version: "eosio::abi/1.0".to_string(),
        structs: vec![
            AbiStructDefinition {
                name: "permission_level".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("actor".to_owned(), "account_name".to_owned()).into(),
                    ("permission".to_owned(), "permission_name".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "action".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("name".to_owned(), "action_name".to_owned()).into(),
                    ("authorization".to_owned(), "permission_level[]".to_owned()).into(),
                    ("data".to_owned(), "bytes".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "extension".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("type".to_owned(), "uint16".to_owned()).into(),
                    ("data".to_owned(), "bytes".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "transaction_header".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("expiration".to_owned(), "time_point_sec".to_owned()).into(),
                    ("ref_block_num".to_owned(), "uint16".to_owned()).into(),
                    ("ref_block_prefix".to_owned(), "uint32".to_owned()).into(),
                    ("max_net_usage_words".to_owned(), "varuint32".to_owned()).into(),
                    ("max_cpu_usage_ms".to_owned(), "uint8".to_owned()).into(),
                    ("delay_sec".to_owned(), "varuint32".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "transaction".to_string(),
                base: "transaction_header".to_string(),
                fields: vec![
                    ("context_free_actions".to_owned(), "action[]".to_owned()).into(),
                    ("actions".to_owned(), "action[]".to_owned()).into(),
                    (
                        "transaction_extensions".to_owned(),
                        "extension[]".to_owned(),
                    )
                        .into(),
                ],
            },
            AbiStructDefinition {
                name: "producer_key".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("producer_name".to_owned(), "account_name".to_owned()).into(),
                    ("block_signing_key".to_owned(), "public_key".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "producer_schedule".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("version".to_owned(), "uint32".to_owned()).into(),
                    ("producers".to_owned(), "producer_key[]".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "block_header".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("timestamp".to_owned(), "uint32".to_owned()).into(),
                    ("producer".to_owned(), "account_name".to_owned()).into(),
                    ("confirmed".to_owned(), "uint16".to_owned()).into(),
                    ("previous".to_owned(), "block_id_type".to_owned()).into(),
                    ("transaction_mroot".to_owned(), "checksum256".to_owned()).into(),
                    ("action_mroot".to_owned(), "checksum256".to_owned()).into(),
                    ("schedule_version".to_owned(), "uint32".to_owned()).into(),
                    ("new_producers".to_owned(), "producer_schedule?".to_owned()).into(),
                    ("header_extensions".to_owned(), "extension[]".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "key_weight".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("key".to_owned(), "public_key".to_owned()).into(),
                    ("weight".to_owned(), "weight_type".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "permission_level_weight".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("permission".to_owned(), "permission_level".to_owned()).into(),
                    ("weight".to_owned(), "weight_type".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "wait_weight".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("wait_sec".to_owned(), "uint32".to_owned()).into(),
                    ("weight".to_owned(), "weight_type".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "authority".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("threshold".to_owned(), "uint32".to_owned()).into(),
                    ("keys".to_owned(), "key_weight[]".to_owned()).into(),
                    (
                        "accounts".to_owned(),
                        "permission_level_weight[]".to_owned(),
                    )
                        .into(),
                    ("waits".to_owned(), "wait_weight[]".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "newaccount".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("creator".to_owned(), "account_name".to_owned()).into(),
                    ("name".to_owned(), "account_name".to_owned()).into(),
                    ("owner".to_owned(), "authority".to_owned()).into(),
                    ("active".to_owned(), "authority".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "setcode".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("vmtype".to_owned(), "uint8".to_owned()).into(),
                    ("vmversion".to_owned(), "uint8".to_owned()).into(),
                    ("code".to_owned(), "bytes".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "setabi".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("abi".to_owned(), "bytes".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "updateauth".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("permission".to_owned(), "permission_name".to_owned()).into(),
                    ("parent".to_owned(), "permission_name".to_owned()).into(),
                    ("auth".to_owned(), "authority".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "deleteauth".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("permission".to_owned(), "permission_name".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "linkauth".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("code".to_owned(), "account_name".to_owned()).into(),
                    ("type".to_owned(), "action_name".to_owned()).into(),
                    ("requirement".to_owned(), "permission_name".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "unlinkauth".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("account".to_owned(), "account_name".to_owned()).into(),
                    ("code".to_owned(), "account_name".to_owned()).into(),
                    ("type".to_owned(), "action_name".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "onerror".to_string(),
                base: "".to_string(),
                fields: vec![
                    ("sender_id".to_owned(), "uint128".to_owned()).into(),
                    ("sent_trx".to_owned(), "bytes".to_owned()).into(),
                ],
            },
            AbiStructDefinition {
                name: "onblock".to_string(),
                base: "".to_string(),
                fields: vec![("header".to_owned(), "block_header".to_owned()).into()],
            },
        ],
        actions: vec![
            AbiActionDefinition {
                name: NEWACCOUNT_NAME,
                type_name: "newaccount".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: SETCODE_NAME,
                type_name: "setcode".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: SETABI_NAME,
                type_name: "setabi".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: UPDATEAUTH_NAME,
                type_name: "updateauth".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: DELETEAUTH_NAME,
                type_name: "deleteauth".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: LINKAUTH_NAME,
                type_name: "linkauth".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: UNLINKAUTH_NAME,
                type_name: "unlinkauth".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: ONERROR_NAME,
                type_name: "onerror".to_string(),
                ricardian_contract: "".to_string(),
            },
            AbiActionDefinition {
                name: ONBLOCK_NAME,
                type_name: "onblock".to_string(),
                ricardian_contract: "".to_string(),
            },
        ],
        types: vec![
            AbiTypeDefinition {
                new_type_name: "account_name".to_string(),
                type_name: "name".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "permission_name".to_string(),
                type_name: "name".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "action_name".to_string(),
                type_name: "name".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "table_name".to_string(),
                type_name: "name".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "transaction_id_type".to_string(),
                type_name: "checksum256".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "block_id_type".to_string(),
                type_name: "checksum256".to_string(),
            },
            AbiTypeDefinition {
                new_type_name: "weight_type".to_string(),
                type_name: "uint16".to_string(),
            },
        ],
        tables: vec![],
        ricardian_clauses: vec![],
        error_messages: vec![],
        abi_extensions: vec![],
        variants: vec![],
        action_results: vec![],
    }
}
