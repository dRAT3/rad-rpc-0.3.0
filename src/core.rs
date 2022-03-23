use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use parking_lot::{RwLockReadGuard, RwLockWriteGuard};
use radix_engine::engine::validate_data;
use radix_engine::ledger::{InMemorySubstateStore, SubstateStore};
use radix_engine::model::{DataValidationError, Receipt, Supply};
use radix_engine::transaction::TransactionExecutor;
use scrypto::types::{Address, EcdsaPublicKey, Mid, Vid};

use crate::identify_last::IdentifyLast;

use super::formatter;
use super::CONFIG;

use jsonrpc_core::serde_json::{json, Map};
use jsonrpc_core::*;
use jsonrpc_http_server::ServerBuilder;
use serde::Deserialize;

#[derive(Deserialize)]
struct RunParams {
    manifest: String,
    signers: Vec<String>,
}

#[derive(Deserialize)]
struct ShowParams {
    address: String,
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

    io.add_method("show", |params: Params| async move {
        let parsed: Option<ShowParams> = params.parse().ok();
        match parsed {
            Some(p) => show(p).await,
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

async fn show(params: ShowParams) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    let address = Address::from_str(&params.address);
    let parsed;
    match address {
        Ok(address) => {
            parsed = address;
        }
        Err(_) => return parse_err(),
    }

    match parsed {
        Address::Package(_) => dump_package(parsed),
        Address::Component(_) => dump_component(parsed),
        Address::ResourceDef(_) => return parse_err(),
    }
}

fn dump_package(address: Address) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    let mut bytes = 0;
    let read_lock = CONFIG.read();
    let _ = RwLockReadGuard::map(read_lock, |config| {
        let ledger = config.load_immutable();
        let package = ledger.get_package(address);
        match package {
            Some(package) => bytes = package.code().len(),
            None => bytes = 0,
        }
        config
    });

    if bytes > 0 {
        Ok(json!({ "bytes": bytes }))
    } else {
        return not_found_err("Package not found");
    }
}

fn dump_component(address: Address) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    let read_lock = CONFIG.read();
    let mut not_found = false;
    let mut internal_error = false;
    let mut return_vec = Vec::new();

    let _ = RwLockReadGuard::map(read_lock, |config| {
        let ledger = config.load_immutable();
        let component = ledger.get_component(address);
        match component {
            Some(c) => {
                return_vec.push(json!({
                    "package_address": c.package_address().to_string(),
                    "blueprint_name": c.blueprint_name().to_string()
                }));

                let state = c.state();
                let state_validated = validate_data(state);
                let state_validated_outer;
                match state_validated {
                    Ok(v) => {
                        let state_string =
                            formatter::format_value(&v.dom, &HashMap::new(), &HashMap::new());

                        return_vec.push(json!({ "state": state_string }));

                        state_validated_outer = v;
                    }
                    Err(_) => {
                        internal_error = true;
                        return config;
                    }
                }

                let mut queue: Vec<Mid> = state_validated_outer.lazy_maps.clone();
                let mut i = 0;
                let mut maps_visited: HashSet<Mid> = HashSet::new();
                let mut vaults_found: HashSet<Vid> =
                    state_validated_outer.vaults.iter().cloned().collect();
                let mut lazy_maps: Vec<jsonrpc_core::Value> = Vec::new();
                while i < queue.len() {
                    let mid = queue[i];
                    i += 1;
                    if maps_visited.insert(mid) {
                        match dump_lazy_map(&address, &mid, ledger) {
                            Ok(v) => {
                                lazy_maps.push(jsonrpc_core::Value::Object(v.2));
                                queue.extend(v.0);

                                for vault in v.1 {
                                    vaults_found.insert(vault);
                                }
                            }
                            Err(_) => internal_error = true,
                        }
                    }
                }
                match dump_resources(address, &vaults_found, ledger) {
                    Ok(mut vec) => return_vec.append(&mut vec),
                    Err(_) => internal_error = true,
                }
            }
            None => not_found = true,
        }
        config
    });

    if not_found {
        not_found_err("Component not found")
    } else if internal_error {
        internal_err("Problem while validating state", 555)
    } else {
        Ok(json!("ok"))
    }
}

fn dump_lazy_map<T: SubstateStore>(
    address: &Address,
    mid: &Mid,
    ledger: &T,
) -> std::result::Result<
    (Vec<Mid>, Vec<Vid>, serde_json::map::Map<String, Value>),
    DataValidationError,
> {
    let mut referenced_maps = Vec::new();
    let mut referenced_vaults = Vec::new();
    let mut json_map: serde_json::Map<String, Value> = serde_json::map::Map::new();

    let map = ledger.get_lazy_map(address, mid).unwrap();
    for (last, (k, v)) in map.map().iter().identify_last() {
        let k_validated = validate_data(k)?;
        let v_validated = validate_data(v)?;

        let k_string = formatter::format_value(&k_validated.dom, &HashMap::new(), &HashMap::new());
        let v_string = formatter::format_value(&v_validated.dom, &HashMap::new(), &HashMap::new());

        json_map.insert(k_string, jsonrpc_core::Value::String(v_string));

        referenced_maps.extend(k_validated.lazy_maps);
        referenced_maps.extend(v_validated.lazy_maps);
        referenced_vaults.extend(k_validated.vaults);
        referenced_vaults.extend(v_validated.vaults);
    }
    Ok((referenced_maps, referenced_vaults, json_map))
}

fn dump_resources<T: SubstateStore>(
    address: Address,
    vaults: &HashSet<Vid>,
    ledger: &T,
) -> std::result::Result<Vec<Value>, DataValidationError> {
    println!("{}:", "Resources");
    let mut vec_res = Vec::new();
    for (last, vid) in vaults.iter().identify_last() {
        let vault = ledger.get_vault(&address, vid).unwrap();
        let amount = vault.amount();
        let resource_address = vault.resource_address();
        let resource_def = ledger.get_resource_def(resource_address).unwrap();

        let name = resource_def.metadata().get("name");
        let symbol = resource_def.metadata().get("symbol");
        vec_res.push(
            json!({"amount": amount.to_string(), "resource_def": resource_address.to_string(), "name": name, "symbol": symbol }),
        );
        /*
        println!(
            "{{ amount: {}, resource_def: {}{}{} }}",
            amount,
            resource_address,
            resource_def
                .metadata()
                .get("name")
                .map(|name| format!(", name: \"{}\"", name))
                .unwrap_or(String::new()),
            resource_def
                .metadata()
                .get("symbol")
                .map(|symbol| format!(", symbol: \"{}\"", symbol))
                .unwrap_or(String::new()),
        );
        */
        if let Supply::NonFungible { keys } = vault.total_supply() {
            for (inner_last, key) in keys.iter().identify_last() {
                let non_fungible = ledger.get_non_fungible(resource_address, key).unwrap();
                let immutable_data = validate_data(&non_fungible.immutable_data()).unwrap();
                let mutable_data = validate_data(&non_fungible.mutable_data()).unwrap();
                /*
                println!(
                    "NON_FUNGIBLE {{ id: {}, immutable_data: {}, mutable_data: {} }}",
                    key, immutable_data, mutable_data
                );
                */

                vec_res.push(json!({
                "NON_FUNGIBLE": {
                    "id": key.to_vec(),
                    "immutable_data": immutable_data.raw,
                    "mutable_data": mutable_data.raw,
                }
                }));
            }
        }
    }
    Ok(vec_res)
}

fn internal_err(msg: &str, code: i64) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ServerError(code),
        message: msg.to_string(),
        data: None,
    });
}
fn not_found_err(msg: &str) -> jsonrpc_core::Result<jsonrpc_core::Value> {
    return Err(jsonrpc_core::Error {
        code: ErrorCode::ServerError(1),
        message: msg.to_string(),
        data: None,
    });
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
