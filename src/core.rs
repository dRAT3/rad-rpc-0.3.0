use std::collections::HashMap;
use std::hash::Hash;
use std::str::FromStr;

use parking_lot::RwLockWriteGuard;
use radix_engine::model::Receipt;
use radix_engine::transaction::TransactionExecutor;
use scrypto::buffer::scrypto_decode;
use scrypto::types::{Bid, EcdsaPublicKey, Rid};

use super::formatter;
use super::CONFIG;

use jsonrpc_core::serde_json::json;
use jsonrpc_core::*;
use jsonrpc_http_server::ServerBuilder;
use serde::Deserialize;

#[derive(Deserialize)]
struct RunParams {
    manifest: String,
    signers: Vec<String>,
}

pub fn core_thread() {
    let mut io = IoHandler::default();

    io.add_method("run", |params: Params| async move {
        let parsed: Option<RunParams> = params.parse().ok();
        match parsed {
            Some(p) => run(p).await,
            None => return parse_err(),
        }
    });

    let server = ServerBuilder::new(io)
        .threads(100)
        .start_http(&"127.0.0.1:3030".parse().unwrap())
        .expect("Unable to start http server");
    server.wait();
}

async fn run(params: RunParams) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    let mut signatures: Vec<EcdsaPublicKey> = Vec::new();

    for signer in params.signers {
        let key = EcdsaPublicKey::from_str(&signer);
        match key {
            Ok(k) => {
                signatures.push(k);
            }
            Err(_) => return ecdsa_err(),
        }
    }

    let mut compile_err = false;
    let mut receipt_opt: Option<Receipt> = None;

    let write_lock = CONFIG.write();
    let _ = RwLockWriteGuard::map(write_lock, |config| {
        let ledger = config.load();
        let mut executor = TransactionExecutor::new(ledger, false);
        let transaction = transaction_manifest::compile(&params.manifest).ok();
        match transaction {
            Some(mut transaction) => {
                transaction
                    .instructions
                    .push(radix_engine::model::Instruction::End { signatures });

                let receipt = executor.run(transaction);
                match receipt {
                    Ok(receipt) => receipt_opt = Some(receipt),
                    Err(_) => {}
                }
            }
            None => compile_err = true,
        }

        config
    });

    if compile_err {
        return transaction_compile_err();
    }

    if let Some(receipt) = receipt_opt {
        match receipt.result {
            Ok(_) => {
                let mut outputs: Vec<String> = Vec::new();

                for output in receipt.outputs {
                    outputs.push(formatter::format_value(
                        &output.dom,
                        &HashMap::new(),
                        &HashMap::new(),
                    ));
                }

                let packages_string: Vec<String> = receipt
                    .new_entities
                    .iter()
                    .cloned()
                    .filter(|&x| x.is_package())
                    .map(|x| x.to_string())
                    .collect();

                let components_string: Vec<String> = receipt
                    .new_entities
                    .iter()
                    .cloned()
                    .filter(|&x| x.is_component())
                    .map(|x| x.to_string())
                    .collect();

                let resource_defs_string: Vec<String> = receipt
                    .new_entities
                    .iter()
                    .cloned()
                    .filter(|&x| x.is_resource_def())
                    .map(|x| x.to_string())
                    .collect();

                Ok(json!({
                    "packages": packages_string,
                    "components": components_string,
                    "resource_defs": resource_defs_string,
                    "outputs": outputs
                }))
            }
            Err(_) => transaction_execution_error(),
        }
    } else {
        transaction_validation_err()
    }
}

fn parse_err() -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ParseError,
        message: "Can't parse parameters".to_string(),
        data: None,
    });
}

fn ecdsa_err() -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ParseError,
        message: "Can't parse ecdsa key".to_string(),
        data: None,
    });
}

fn transaction_validation_err() -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ServerError(666),
        message: "Transaction validation error".to_string(),
        data: None,
    });
}

fn transaction_execution_error() -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ServerError(33),
        message: "Transaction execution error".to_string(),
        data: None,
    });
}

fn transaction_compile_err() -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::InvalidRequest,
        message: "Transaction compile error".to_string(),
        data: None,
    });
}
