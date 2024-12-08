use crate::api::errors::ApiErrorType;
use crate::api::responses::{
    json_embed, json_embed_block, json_embed_transaction, json_serialize_embed, APIAsset,
    APICreateResponseContent, CallResponse, JsonReply,
};
use crate::api::utils::{map_string_err, map_to_string_err};
use crate::comms_handler::Node;
use crate::configurations::MempoolNodeSharedConfig;
use crate::constants::LAST_BLOCK_HASH_KEY;
use crate::db_utils::SimpleDb;
use crate::interfaces::{
    node_type_as_str, AddressesWithOutPoints, BlockchainItem, BlockchainItemMeta,
    BlockchainItemType, DebugData, DruidPool, MempoolApi, MineApiRequest, MineRequest, NodeType,
    OutPointData, StoredSerializingBlock, UserApi, UserApiRequest, UserRequest, UtxoFetchType,
};
use crate::mempool::MempoolError;
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::storage::{get_stored_value_from_db, indexed_block_hash_key};
use crate::threaded_call::{self, ThreadedCallSender};
use crate::utils::{decode_pub_key, decode_signature, StringError};
use crate::wallet::{AddressStore, AddressStoreHex, WalletDb, WalletDbError};
use crate::Response;
use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{fmt, str};
use tracing::{debug, error};
use tw_chain::constants::{D_DISPLAY_PLACES, TOTAL_TOKENS};
use tw_chain::crypto::sign_ed25519::{PublicKey, Signature};
use tw_chain::primitives::asset::{Asset, ItemAsset, TokenAmount};
use tw_chain::primitives::druid::DdeValues;
use tw_chain::primitives::transaction::{GenesisTxHashSpec, OutPoint, Transaction, TxIn, TxOut};
use tw_chain::script::lang::Script;
use tw_chain::script::{OpCodes, StackEntry};
use tw_chain::utils::transaction_utils::{construct_address_for, construct_tx_hash};
use warp::hyper::StatusCode;

pub type DbgPaths = Vec<&'static str>;

/// Data entry from the blockchain
#[derive(Debug, Serialize, Deserialize)]
enum BlockchainData {
    Block(StoredSerializingBlock),
    Transaction(Transaction),
}

/// Private/public keypairs, stored with payment address as key.
/// Values are encrypted
#[derive(Debug, Serialize, Deserialize)]
pub struct Addresses {
    pub addresses: BTreeMap<String, AddressStoreHex>,
}

/// Information about a wallet to be returned to requester
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletInfo {
    running_total: f64,
    running_total_tokens: u64,
    locked_total: f64,
    locked_total_tokens: u64,
    available_total: f64,
    available_total_tokens: u64,
    item_total: BTreeMap<String, u64>, /* DRS tx hash - amount */
    addresses: AddressesWithOutPoints,
}

/// Encapsulated payment received from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulatedPayment {
    pub address: String,
    pub amount: TokenAmount,
    pub passphrase: String,
    pub locktime: Option<u64>,
}

/// Item asset creation structure received from client
///
/// This structure is used to create a item asset on EITHER
/// the mempool or user node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateItemAssetDataMempool {
    pub item_amount: u64,
    pub genesis_hash_spec: GenesisTxHashSpec,
    pub script_public_key: String,
    pub public_key: String,
    pub signature: String,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateItemAssetDataUser {
    pub item_amount: u64,
    pub genesis_hash_spec: GenesisTxHashSpec,
    pub metadata: Option<String>,
}

/// Stack entry enum which stores Signature and PubKey items as hex strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrettyStackEntry {
    Op(OpCodes),
    Signature(#[serde(deserialize_with = "hex_string_or_bytes")] String),
    PubKey(#[serde(deserialize_with = "hex_string_or_bytes")] String),
    Num(usize),
    Bytes(#[serde(deserialize_with = "hex_string_or_bytes")] String),
}

impl PrettyStackEntry {
    fn to_internal(self) -> Result<StackEntry, StringError> {
        match self {
            Self::Op(op) => Ok(StackEntry::Op(op)),
            Self::Signature(data) => Ok(StackEntry::Signature(
                Signature::from_slice(hex::decode(data).map_err(map_to_string_err)?.as_slice())
                    .ok_or(StringError(String::default()))?,
            )),
            Self::PubKey(data) => Ok(StackEntry::PubKey(
                PublicKey::from_slice(hex::decode(data).map_err(map_to_string_err)?.as_slice())
                    .ok_or(StringError(String::default()))?,
            )),
            Self::Num(val) => Ok(StackEntry::Num(val)),
            Self::Bytes(data) => Ok(StackEntry::Bytes(data)),
        }
    }

    fn from_internal(entry: StackEntry) -> Self {
        match entry {
            StackEntry::Op(op) => Self::Op(op),
            StackEntry::Signature(signature) => Self::Signature(hex::encode(signature.as_ref())),
            StackEntry::PubKey(pubkey) => Self::PubKey(hex::encode(pubkey.as_ref())),
            StackEntry::Num(val) => Self::Num(val),
            StackEntry::Bytes(data) => Self::Bytes(data),
        }
    }
}

/// Information needed for the creaion of TxIn script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CreateTxInScript {
    #[allow(non_camel_case_types)]
    //unfortunately, this has to be lower-case in order to ensure that we can deserialize the JSON
    // format returned by /transactions_by_key and similar API routes
    stack(Vec<PrettyStackEntry>),
    Pay2PkH {
        /// Data to sign
        signable_data: Option<String>,
        /// Hex encoded signature
        signature: String,
        /// Hex encoded complete public key
        public_key: String,
        /// Optional address version field
        address_version: Option<u64>,
    },
}

/// Information needed for the creaion of TxIn.
/// This API would change if types are modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTxIn {
    /// The previous_out to use
    pub previous_out: Option<OutPoint>,
    /// script info
    pub script_signature: Option<CreateTxInScript>,
}

/// Information necessary for the creation of a Transaction
/// This API would change if types are modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransaction {
    /// String to sign in each inputs
    pub inputs: Vec<CreateTxIn>,
    pub outputs: Vec<TxOut>,
    pub version: usize,
    pub fees: Option<Vec<TxOut>>,
    pub druid_info: Option<DdeValues>,
}

/// A Transaction which has been serialized to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSerializedTransaction {
    pub txn_hash_hex: String,
    pub txn_hex: String,
}

/// Struct received from client to change passphrase
///
/// Entries will be encrypted with TLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePassphraseData {
    pub old_passphrase: String,
    pub new_passphrase: String,
}

/// Struct received from client to construct address
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AddressConstructData {
    pub pub_key: Option<Vec<u8>>,
    pub pub_key_hex: Option<String>,
    pub version: Option<u64>,
}

/// Struct received from client to fetch pending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchPendingData {
    pub druid_list: Vec<String>,
}

/// Struct received from client to fetch pending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchPendingtResult {
    pub pending_transactions: DruidPool,
}

//======= GET HANDLERS =======//

/// Gets the state of the connected wallet and returns it.
/// Returns a `WalletInfo` struct
/// extra is used to deonte spent_transactions or which page of transaction_pages
pub async fn get_wallet_info(
    wallet_db: WalletDb,
    extra: Option<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let mut fund_store = match wallet_db.get_fund_store_err() {
        Ok(fund) => fund,
        Err(_) => return r.into_err_internal(ApiErrorType::CannotAccessWallet),
    };

    let mut addresses = AddressesWithOutPoints::new();
    let txs;
    if let Some(param) = extra.as_deref() {
        if let Ok(page_usize) = param.parse::<usize>() {
            txs = fund_store.transaction_pages(page_usize).clone();
        } else if param.parse::<u64>().is_ok() {
            txs = fund_store.transaction_pages(0).clone();
        } else {
            txs = match extra.as_deref() {
                Some("spent") => fund_store.spent_transactions().clone(),
                _ => fund_store.transactions().clone(),
            };
        }
    } else {
        txs = fund_store.transactions().clone();
    }

    for (out_point, asset) in txs {
        addresses
            .entry(wallet_db.get_transaction_address(&out_point))
            .or_default()
            .push(OutPointData::new(out_point.clone(), asset.clone()));
    }
    let locked_coinbase = wallet_db.get_locked_coinbase().await;
    let total = fund_store.running_total().clone();
    let available = {
        fund_store.filter_locked_coinbase(&locked_coinbase);
        fund_store.running_total()
    };
    let send_val = WalletInfo {
        running_total: total.tokens.0 as f64 / D_DISPLAY_PLACES,
        running_total_tokens: total.tokens.0,
        locked_total: (total.tokens.0 - available.tokens.0) as f64 / D_DISPLAY_PLACES,
        locked_total_tokens: (total.tokens.0 - available.tokens.0),
        available_total: available.tokens.0 as f64 / D_DISPLAY_PLACES,
        available_total_tokens: available.tokens.0,
        item_total: total.items,
        addresses,
    };

    r.into_ok(
        "Wallet info successfully fetched",
        json_serialize_embed(send_val),
    )
}

/// Gets all present keys and sends them out for export
pub async fn get_export_keypairs(
    wallet_db: WalletDb,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let known_addr = wallet_db.get_known_addresses();
    let mut addresses = BTreeMap::new();

    for addr in known_addr {
        addresses.insert(addr.clone(), wallet_db.get_address_store(&addr).into());
    }

    let response_data = Addresses { addresses };

    r.into_ok(
        "Key-pairs successfully exported",
        json_serialize_embed(response_data),
    )
}

/// Gets a newly generated payment address
pub async fn get_payment_address(
    mut wallet_db: WalletDb,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let (address, _) = wallet_db.generate_payment_address();
    r.into_ok(
        "New payment address generated",
        json_serialize_embed(address),
    )
}

/// Gets the latest block information
pub async fn get_latest_block(
    db: Arc<Mutex<SimpleDb>>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    get_json_reply_stored_value_from_db(db, LAST_BLOCK_HASH_KEY, false, call_id, route)
}

/// Gets the debug info for a specified node type
///
/// Contains an optional field for an auxiliary `Node`,
/// i.e a Miner node may or may not have additional User
/// node capabilities- providing additional debug data.
pub async fn get_debug_data(
    debug_paths: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
    route: &str,
    call_id: String,
    routes_pow: BTreeMap<String, usize>,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let node_type = node_type_as_str(node.get_node_type());
    let node_peers = node.get_peer_list().await;

    let data = match aux_node {
        Some(aux) => {
            let aux_type = node_type_as_str(aux.get_node_type());
            let aux_peers = aux.get_peer_list().await;
            DebugData {
                node_type: format!("{node_type}/{aux_type}"),
                node_api: debug_paths,
                node_peers: [node_peers, aux_peers].concat(),
                routes_pow,
            }
        }
        None => DebugData {
            node_type: node_type.to_owned(),
            node_api: debug_paths,
            node_peers,
            routes_pow,
        },
    };
    r.into_ok(
        "Debug data successfully retrieved",
        json_serialize_embed(data),
    )
}

/// Get to fetch information about the current mining block
pub async fn get_current_mining_block(
    current_block: CurrentBlockWithMutex,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let data: Option<BlockPoWReceived> = current_block.lock().await.clone();
    r.into_ok(
        "Current mining block successfully retrieved",
        json_serialize_embed(data),
    )
}

/// Get all addresses for unspent tokens on the UTXO set
pub async fn get_utxo_addresses(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let addresses = make_api_threaded_call(
        &mut threaded_calls,
        |c| c.get_committed_utxo_tracked_set().get_all_addresses(),
        "Can't access UTXO",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok(
        "UTXO addresses successfully retrieved",
        json_serialize_embed(addresses),
    )
}

//POST get a mempool node's config which is shareable amongst its peers
pub async fn get_shared_config_mempool(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    // Send request to mempool node
    let res = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.get_shared_config(),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok(
        "Successfully fetched shared config",
        json_serialize_embed(res),
    )
}

/// GET The current issued supply of the token
pub async fn get_issued_supply(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    // Send request to mempool node
    let res = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.get_issued_supply(),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok(
        "Successfully fetched issued supply",
        json_serialize_embed(res),
    )
}

/// GET The total supply of the token
pub async fn get_total_supply(
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    r.into_ok(
        "Successfully fetched total supply",
        json_serialize_embed(TOTAL_TOKENS),
    )
}

/// GET All outgoing payments from this node
pub async fn get_outgoing_txs(
    route: &'static str,
    db: WalletDb,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    match db.get_outgoing_txs() {
        Ok(tx) => r.into_ok(
            "Successfully fetched last constructed transaction",
            json_serialize_embed(tx),
        ),
        Err(_e) => r.into_err_internal(ApiErrorType::CannotAccessWallet),
    }
}

//======= POST HANDLERS =======//

/// Post to retrieve items from the blockchain db by hash key
pub async fn post_blockchain_entry_by_key(
    db: Arc<Mutex<SimpleDb>>,
    keys: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    get_json_reply_items_from_db(db, keys, route, call_id)
}

/// Post to batch retrieve multiple transactions from the blockchain db by hash keys
pub async fn post_transactions_by_key(
    db: Arc<Mutex<SimpleDb>>,
    keys: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    get_json_reply_items_from_db(db, keys, route, call_id)
}

/// Post to retrieve block information by number
pub async fn post_block_by_num(
    db: Arc<Mutex<SimpleDb>>,
    block_nums: Vec<u64>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let keys: Vec<_> = block_nums
        .iter()
        .map(|num| indexed_block_hash_key(*num))
        .collect();
    get_json_reply_items_from_db(db, keys, route, call_id)
}

/// Post to import new keypairs to the connected wallet
pub async fn post_import_keypairs(
    peer: Node,
    db: WalletDb,
    keypairs: Addresses,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let response_keys: Vec<String> = keypairs.addresses.keys().cloned().collect();
    let response_data = json_serialize_embed(response_keys);
    let r = CallResponse::new(route, &call_id);
    let addresses: Vec<String> = keypairs.addresses.keys().cloned().collect();

    let mut key_pairs_converted = BTreeMap::new();
    for (address, address_store_hex) in keypairs.addresses.into_iter() {
        match AddressStore::try_from_hex_store(address_store_hex) {
            Ok(address_store) => {
                key_pairs_converted.insert(address, address_store);
            }
            Err(e) => {
                return r.into_err_with_data(
                    StatusCode::BAD_REQUEST,
                    ApiErrorType::BadRequest,
                    json_serialize_embed(e.to_string()),
                )
            }
        };
    }

    for (addr, address_set) in key_pairs_converted.into_iter() {
        match db.save_address_to_wallet(addr, address_set) {
            Ok(_) => {}
            Err(_e) => {
                return r.into_err_with_data(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ApiErrorType::CannotAccessUserNode,
                    response_data,
                );
            }
        }
    }

    match peer.get_node_type() {
        NodeType::Miner => {
            // Update running total from mempool node
            if let Err(e) = peer.inject_next_event(
                peer.local_address(),
                MineRequest::MinerApi(MineApiRequest::RequestUTXOSet(UtxoFetchType::AnyOf(
                    addresses,
                ))),
            ) {
                error!("route:update_running_total error: {:?}", e);
                return r.into_err_internal(ApiErrorType::CannotAccessMinerNode);
            }
        }
        NodeType::User => {
            // Update running total from mempool node
            if let Err(e) = peer.inject_next_event(
                peer.local_address(),
                UserRequest::UserApi(UserApiRequest::UpdateWalletFromUtxoSet {
                    address_list: UtxoFetchType::AnyOf(addresses),
                }),
            ) {
                error!("route:update_running_total error: {:?}", e);
                return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
            }
        }
        _ => return r.into_err_internal(ApiErrorType::InternalError),
    }

    r.into_ok("Key-pairs successfully imported", response_data)
}

///Post make a new payment from the connected wallet
pub async fn post_make_payment(
    db: WalletDb,
    peer: Node,
    mut threaded_calls: ThreadedCallSender<dyn UserApi>,
    encapsulated_data: EncapsulatedPayment,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
        locktime,
    } = encapsulated_data;

    let r = CallResponse::new(route, &call_id);

    if let Err(e) = db.test_passphrase(passphrase).await {
        return wallet_db_error(e, r);
    };

    let response = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.make_payment(address, amount, locktime),
        "Cannot fetch UTXO balance",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    if !response.success {
        return r.into_err_internal(ApiErrorType::Generic(response.reason));
    }

    let request = UserRequest::UserApi(UserApiRequest::SendNextPayment);
    if let Err(e) = peer.inject_next_event(peer.local_address(), request) {
        error!("route:make_payment error: {:?}", e);
        return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
    }

    r.into_progress("Payment processing", json_serialize_embed(response))
}

///Post make a new payment from the connected wallet using an ip address
pub async fn post_make_ip_payment(
    db: WalletDb,
    peer: Node,
    encapsulated_data: EncapsulatedPayment,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
        locktime,
    } = encapsulated_data;

    let r = CallResponse::new(route, &call_id);

    let payment_peer: SocketAddr = match address.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return r.into_err_bad_req(ApiErrorType::CannotParseAddress);
        }
    };

    let request = match db.test_passphrase(passphrase).await {
        Ok(_) => UserRequest::UserApi(UserApiRequest::MakeIpPayment {
            payment_peer,
            amount,
            locktime,
        }),
        Err(e) => {
            return wallet_db_error(e, r);
        }
    };

    if let Err(e) = peer.inject_next_event(peer.local_address(), request) {
        error!("route:make_payment error: {:?}", e);
        return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
    }

    r.into_ok(
        "IP payment processing",
        json_serialize_embed(construct_make_payment_map(address.clone(), amount)),
    )
}

///Post make a donation request from the user node at specified ip address
pub async fn post_request_donation(
    peer: Node,
    address: String,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let paying_peer: SocketAddr = match address.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return r.into_err_bad_req(ApiErrorType::CannotParseAddress);
        }
    };

    let request = UserRequest::UserApi(UserApiRequest::RequestDonation { paying_peer });

    if let Err(e) = peer.inject_next_event(peer.local_address(), request) {
        error!("route:request_donation error: {:?}", e);
        return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
    }

    r.into_ok("Donation request sent", json_serialize_embed("null"))
}

/// Post to update running total of connected wallet
pub async fn post_update_running_total(
    peer: Node,
    wallet_db: WalletDb,
    addresses: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    if addresses.is_empty() {
        return r.into_err_internal(ApiErrorType::Generic("No addresses provided".to_owned()));
    }

    let known_addresses = wallet_db.get_known_addresses();
    let address_list = match addresses.first() {
        Some(first) if first == "all" => known_addresses,
        _ => addresses,
    };

    debug!("Updating running total for addresses: {:?}", address_list);
    let request = UserRequest::UserApi(UserApiRequest::UpdateWalletFromUtxoSet {
        address_list: UtxoFetchType::AnyOf(address_list),
    });

    if let Err(e) = peer.inject_next_event(peer.local_address(), request) {
        error!("route:update_running_total error: {:?}", e);
        return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
    }

    r.into_ok("Running total updated", json_serialize_embed("null"))
}

/// Post to fetch the balance for given addresses in UTXO
pub async fn post_fetch_utxo_balance(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    addresses: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let balances = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            c.get_committed_utxo_tracked_set()
                .get_balance_for_addresses(&addresses)
        },
        "Cannot fetch UTXO balance",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok(
        "Balance successfully fetched",
        json_serialize_embed(balances),
    )
}

//POST fetch pending transaction from a mempool node
pub async fn post_fetch_druid_pending(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    fetch_input: FetchPendingData,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let pending_transactions = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            let pending = c.get_pending_druid_pool();
            (fetch_input.druid_list.iter())
                .filter_map(|k| pending.get_key_value(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<DruidPool>()
        },
        "Cannot fetch pending transactions",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok(
        "Pending transactions successfully fetched",
        json_serialize_embed(pending_transactions),
    )
}

/// Post to create a item asset transaction on User node
pub async fn post_create_item_asset_user(
    peer: Node,
    item_data: CreateItemAssetDataUser,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let CreateItemAssetDataUser {
        item_amount,
        genesis_hash_spec,
        metadata,
    } = item_data;

    let request = UserRequest::UserApi(UserApiRequest::SendCreateItemRequest {
        item_amount,
        genesis_hash_spec,
        metadata,
    });
    let r = CallResponse::new(route, &call_id);

    if let Err(e) = peer.inject_next_event(peer.local_address(), request) {
        error!("route:create_item_asset error: {:?}", e);
        return r.into_err_internal(ApiErrorType::CannotAccessUserNode);
    }

    r.into_ok("Item asset(s) created", json_serialize_embed(item_amount))
}

/// Post to create a item asset transaction on Mempool node
pub async fn post_create_item_asset(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    create_item_asset_data: CreateItemAssetDataMempool,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let CreateItemAssetDataMempool {
        item_amount,
        genesis_hash_spec,
        script_public_key,
        public_key,
        signature,
        metadata,
    } = create_item_asset_data;

    let r = CallResponse::new(route, &call_id);

    // Create item asset on the Mempool node
    let spk = script_public_key.clone();
    let md = metadata.clone();
    let (tx_hash, mempool_resp) = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            let (tx, tx_hash) = c
                .create_item_asset_tx(
                    item_amount,
                    spk,
                    public_key,
                    signature,
                    genesis_hash_spec,
                    md
                )?;
            let mempool_resp = c.receive_transactions(vec![tx]);
            Ok::<(String, Response), MempoolError>((tx_hash, mempool_resp))
        },
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))? /* Error from threaded call */
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?; /* Error in transaction creation process */

    match mempool_resp.success {
        true => {
            // Response content
            let item_asset = ItemAsset::new(item_amount, Some(tx_hash.clone()), metadata);
            let api_asset = APIAsset::new(Asset::Item(item_asset), None);
            let create_info = APICreateResponseContent::new(api_asset, script_public_key, tx_hash);
            let response_data = json_serialize_embed(create_info);
            r.into_ok("Item asset(s) created", response_data)
        }
        false => r.into_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorType::Generic(mempool_resp.reason.to_owned()),
        ),
    }
}

/// Post transactions to mempool node
pub async fn post_create_transactions(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    data: Vec<CreateTransaction>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let transactions = data
        .into_iter()
        .map(to_transaction)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_string_err(r.clone(), e, StatusCode::BAD_REQUEST))?;

    // Construct response
    let ctx_map = construct_ctx_map(&transactions);

    // Send request to mempool node
    let mempool_resp = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.receive_transactions(transactions),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    // If the creation failed for some reason
    if !mempool_resp.success {
        debug!(
            "route:post_create_transactions error: {:?}",
            mempool_resp.reason
        );
        return r.into_err_internal(ApiErrorType::Generic(mempool_resp.reason.to_owned()));
    }

    r.into_ok("Transaction(s) processing", json_serialize_embed(ctx_map))
}

/// Get the status of a transaction on the mempool node
pub async fn post_transaction_status(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    data: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let status = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.get_transaction_status(data),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    r.into_ok("Transaction(s) status", json_serialize_embed(status))
}

/// Serialize transactions to binary without submitting to mempool node
pub async fn post_serialize_transactions(
    data: Vec<CreateTransaction>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let serialized_transactions = data
        .into_iter()
        .map(to_transaction)
        .map(|res| {
            let tx = res?;
            match bincode::serialize(&tx) {
                Ok(bytes) => Ok(JsonSerializedTransaction {
                    txn_hash_hex: construct_tx_hash(&tx),
                    txn_hex: hex::encode(bytes),
                }),
                Err(msg) => Err(StringError(msg.to_string())),
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_string_err(r.clone(), e, StatusCode::BAD_REQUEST))?;

    r.into_ok(
        "Transaction(s) serialized",
        json_serialize_embed(serialized_transactions),
    )
}

/// Deserialize transactions from binary without submitting to mempool node
pub async fn post_deserialize_transactions(
    data: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);

    let deserialized_transactions = data
        .into_iter()
        .map(from_hex_transaction)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_string_err(r.clone(), e, StatusCode::BAD_REQUEST))?;

    r.into_ok(
        "Transaction(s) deserialized",
        json_serialize_embed(deserialized_transactions),
    )
}

// POST to change wallet passphrase
pub async fn post_change_wallet_passphrase(
    mut db: WalletDb,
    passphrase_struct: ChangePassphraseData,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let ChangePassphraseData {
        old_passphrase,
        new_passphrase,
    } = passphrase_struct;

    let r = CallResponse::new(route, &call_id);

    if new_passphrase.is_empty() {
        //New passphrase cannot be blank
        return r.into_err(StatusCode::UNAUTHORIZED, ApiErrorType::BlankPassphrase);
    }
    match db
        .change_wallet_passphrase(old_passphrase, new_passphrase)
        .await
    {
        Ok(_) => r.into_ok(
            "Passphrase changed successfully",
            json_serialize_embed("null"),
        ),
        Err(e) => wallet_db_error(e, r),
    }
}

// POST to check for transaction presence
pub async fn post_blocks_by_tx_hashes(
    db: Arc<Mutex<SimpleDb>>,
    tx_hashes: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let block_nums: Vec<u64> = tx_hashes
        .into_iter()
        .filter_map(
            |tx_hash| match get_stored_value_from_db(db.clone(), tx_hash) {
                Some(BlockchainItem {
                    item_meta: BlockchainItemMeta::Tx { block_num, .. },
                    ..
                }) => Some(block_num),
                _ => None,
            },
        )
        .collect();
    r.into_ok(
        "Database item(s) successfully retrieved",
        json_serialize_embed(block_nums),
    )
}

//POST create a new payment address from a mempool node
pub async fn post_payment_address_construction(
    data: AddressConstructData,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let pub_key = data.pub_key;
    let pub_key_hex = data.pub_key_hex;
    let version = data.version;
    let r = CallResponse::new(route, &call_id);

    let pub_key = pub_key.or_else(|| pub_key_hex.and_then(|k| hex::decode(k).ok()));
    let pub_key = pub_key.filter(|k| !k.is_empty());
    let pub_key = pub_key.and_then(|k| PublicKey::from_slice(&k));

    if let Some(pub_key) = pub_key {
        let data: String = construct_address_for(&pub_key, version);
        return r.into_ok(
            "Address successfully constructed",
            json_serialize_embed(data),
        );
    }

    r.into_ok(
        "Address successfully constructed",
        json_serialize_embed("null"),
    )
}

//POST pause nodes in a coordinated manner
pub async fn pause_nodes(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    route: &'static str,
    call_id: String,
    b_num: Option<u64>, // NOTE: Nodes will pause at b_num + b_num
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    // Send request to mempool node
    let res = make_api_threaded_call(
        &mut threaded_calls,
        // NOTE: Nodes will pause at current_block + b_num; default is 1 block from current block
        move |c| c.pause_nodes(b_num.unwrap_or(1)),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    if !res.success {
        debug!("route:pause_nodes error: {:?}", res.reason);
        return r.into_err_internal(ApiErrorType::Generic(res.reason.to_owned()));
    }

    r.into_ok(&res.reason, json_serialize_embed("null"))
}

//POST resume nodes in a coordinated manner
pub async fn resume_nodes(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    // Send request to mempool node
    let res = make_api_threaded_call(
        &mut threaded_calls,
        |c| c.resume_nodes(),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    if !res.success {
        debug!("route:resume_nodes error: {:?}", res.reason);
        return r.into_err_internal(ApiErrorType::Generic(res.reason.to_owned()));
    }

    r.into_ok(&res.reason, json_serialize_embed("null"))
}

//POST update a mempool node's config, sharing it to all other peers
pub async fn update_shared_config(
    mut threaded_calls: ThreadedCallSender<dyn MempoolApi>,
    shared_config: MempoolNodeSharedConfig,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    // Send request to mempool node
    let res = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.send_shared_config(shared_config),
        "Cannot access Mempool Node",
    )
    .await
    .map_err(|e| map_string_err(r.clone(), e, StatusCode::INTERNAL_SERVER_ERROR))?;

    if !res.success {
        debug!("route:update_shared_config error: {:?}", res.reason);
        return r.into_err_internal(ApiErrorType::Generic(res.reason.to_owned()));
    }

    r.into_ok(&res.reason, json_serialize_embed("null"))
}

//======= Helpers =======//

/// Filters through wallet errors which are internal vs errors caused by user input
pub fn wallet_db_error(
    err: WalletDbError,
    call_response: CallResponse,
) -> Result<JsonReply, JsonReply> {
    match err {
        WalletDbError::PassphraseError => {
            call_response.into_err(StatusCode::UNAUTHORIZED, ApiErrorType::InvalidPassphrase)
        }
        _ => call_response.into_err_internal(ApiErrorType::InternalError),
    }
}

/// Expect optional field
pub fn with_opt_field<T>(field: Option<T>, e: &str) -> Result<T, StringError> {
    field.ok_or_else(|| StringError(e.to_owned()))
}

/// Deserializer for hex strings which accepts both hex string literals and arrays of bytes.
fn hex_string_or_bytes<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexStringOrBytes();

    impl<'de> Visitor<'de> for HexStringOrBytes {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("hex string or byte array")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            // Validate that the hex string can be decoded
            hex::decode(value).map_err(E::custom)?;

            Ok(value.to_owned())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut elts = Vec::new();
            while let Some(elt) = seq.next_element::<u8>()? {
                elts.push(elt);
            }
            Ok(hex::encode(elts))
        }
    }

    deserializer.deserialize_any(HexStringOrBytes())
}

/// Create a `Transaction` from a `CreateTransaction`
pub fn to_transaction(data: CreateTransaction) -> Result<Transaction, StringError> {
    let CreateTransaction {
        inputs,
        outputs,
        version,
        druid_info,
        fees,
    } = data;

    let inputs = {
        let mut tx_ins = Vec::new();
        for i in inputs {
            let previous_out = with_opt_field(i.previous_out, "Invalid previous_out")?;
            let script_signature = with_opt_field(i.script_signature, "Invalid script_signature")?;

            let tx_in = match script_signature {
                CreateTxInScript::stack(stack) => TxIn {
                    previous_out: Some(previous_out),
                    script_signature: Script::from(
                        stack
                            .into_iter()
                            .map(PrettyStackEntry::to_internal)
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                },
                CreateTxInScript::Pay2PkH {
                    signable_data,
                    signature,
                    public_key,
                    address_version,
                } => {
                    let final_signable_data = if let Some(sd) = signable_data {
                        sd
                    } else {
                        "".to_string()
                    };

                    let signature =
                        with_opt_field(decode_signature(&signature).ok(), "Invalid signature")?;
                    let public_key =
                        with_opt_field(decode_pub_key(&public_key).ok(), "Invalid public_key")?;

                    TxIn {
                        previous_out: Some(previous_out),
                        script_signature: Script::pay2pkh(
                            final_signable_data,
                            signature,
                            public_key,
                            address_version,
                        ),
                    }
                }
            };

            tx_ins.push(tx_in);
        }
        tx_ins
    };

    Ok(Transaction {
        inputs,
        outputs,
        version,
        fees: fees.unwrap_or_default(),
        druid_info,
    })
}

/// Create a `CreateTransaction` from a hex string representing a serialized `Transaction`
fn from_hex_transaction(data: String) -> Result<CreateTransaction, StringError> {
    let bytes = hex::decode(data).map_err(map_to_string_err)?;
    let tx = bincode::deserialize::<Transaction>(bytes.as_slice()).map_err(map_to_string_err)?;
    Ok(from_transaction(tx))
}

/// Create a `CreateTransaction` from a hex string representing a serialized `Transaction`
fn from_transaction(tx: Transaction) -> CreateTransaction {
    let Transaction {
        inputs,
        outputs,
        version,
        fees,
        druid_info,
    } = tx;

    let inputs = {
        let mut tx_ins = Vec::new();
        for i in inputs {
            //TODO: determine if the transaction is P2PKH or something else (?)
            tx_ins.push(CreateTxIn {
                previous_out: i.previous_out,
                script_signature: Some(CreateTxInScript::stack(
                    i.script_signature
                        .stack
                        .into_iter()
                        .map(PrettyStackEntry::from_internal)
                        .collect::<Vec<_>>(),
                )),
            });
        }
        tx_ins
    };

    CreateTransaction {
        inputs,
        outputs,
        version,
        fees: Some(fees),
        druid_info,
    }
}

/// Fetches JSON blocks.
fn get_json_reply_stored_value_from_db(
    db: Arc<Mutex<SimpleDb>>,
    key: &str,
    wrap: bool,
    call_id: String,
    route: &'static str,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let item = get_stored_value_from_db(db, key.as_bytes()).ok_or_else(|| {
        r.clone()
            .into_err(StatusCode::NO_CONTENT, ApiErrorType::NoDataFoundForKey)
            .unwrap_err()
    })?;

    let json_content = match (wrap, item.item_meta.as_type()) {
        (true, BlockchainItemType::Block) => json_embed_block(item.data_json),
        (true, BlockchainItemType::Tx) => json_embed_transaction(item.data_json),
        (false, _) => json_embed(&[&item.data_json]),
    };

    r.into_ok("Database item(s) successfully retrieved", json_content)
}

/// Fetches JSON items. Items which for whatever reason are
/// unretrievable will be replaced with a default (best handling?)
pub fn get_json_reply_items_from_db(
    db: Arc<Mutex<SimpleDb>>,
    keys: Vec<String>,
    route: &'static str,
    call_id: String,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse::new(route, &call_id);
    let key_values: Vec<_> = keys
        .into_iter()
        .map(|key| {
            get_stored_value_from_db(db.clone(), key)
                .map(|item| {
                    (
                        item.key,
                        item.data_json,
                        construct_json_meta(item.item_meta),
                    )
                })
                .unwrap_or_else(|| (b"".to_vec(), b"\"\"".to_vec(), b"\"\"".to_vec()))
        })
        .collect();

    // Make JSON tupple with key and JSON item
    let key_values: Vec<_> = key_values
        .iter()
        .map(|(k, v, m)| [&b"[\""[..], k, &b"\","[..], v, &b","[..], m, &b"]"[..]])
        .collect();

    // Make JSON array:
    let mut key_values: Vec<_> = key_values.join(&&b","[..]);
    key_values.insert(0, &b"["[..]);
    key_values.push(&b"]"[..]);

    r.into_ok(
        "Database item(s) successfully retrieved",
        json_embed(&key_values),
    )
}

/// Threaded call for API
pub async fn make_api_threaded_call<'a, T: ?Sized, R: Send + Sized + Sync + 'static>(
    tx: &mut ThreadedCallSender<T>,
    f: impl FnOnce(&mut T) -> R + Send + Sized + Sync + 'static,
    tag: &'a str,
) -> Result<R, StringError> {
    threaded_call::make_threaded_call(tx, f, tag).await
}

/// Constructs the mapping of output address to asset for `create_transactions`
pub fn construct_ctx_map(transactions: &[Transaction]) -> BTreeMap<String, (String, APIAsset)> {
    let mut tx_info = BTreeMap::new();

    for tx in transactions {
        for out in &tx.outputs {
            let address = out.script_public_key.clone().unwrap_or_default();
            let asset = APIAsset::new(out.value.clone(), None);

            tx_info.insert(construct_tx_hash(tx), (address, asset));
        }
    }

    tx_info
}

pub fn construct_json_meta(meta: BlockchainItemMeta) -> Vec<u8> {
    serde_json::to_vec(&meta).unwrap()
}

/// Constructs the mapping of output address to asset for `make_payment`
pub fn construct_make_payment_map(
    to_address: String,
    amount: TokenAmount,
) -> BTreeMap<String, APIAsset> {
    let mut tx_info = BTreeMap::new();
    tx_info.insert(to_address, APIAsset::new(Asset::Token(amount), None));
    tx_info
}
