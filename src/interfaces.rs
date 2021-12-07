#![allow(unused)]
use crate::hash_block;
use crate::raft::{CommittedIndex, RaftMessageWrapper};
use crate::tracked_utxo::TrackedUtxoSet;
use bytes::Bytes;
use naom::crypto::sign_ed25519::PublicKey;
use naom::primitives::asset::Asset;
use naom::primitives::asset::TokenAmount;
use naom::primitives::block::Block;
use naom::primitives::druid::DruidExpectation;
use naom::primitives::transaction::TxIn;
use naom::primitives::transaction::{OutPoint, Transaction, TxOut};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::{error, fmt};

/// Simple BTreeMap structure used to hold `(OutPoint, Asset)` pairs with respect to a public key address
pub type AddressesWithOutPoints = BTreeMap<String, Vec<(OutPoint, Asset)>>;

/// UTXO set type
pub type UtxoSet = BTreeMap<OutPoint, TxOut>;
pub type UtxoSetRef<'a> = BTreeMap<&'a OutPoint, &'a TxOut>;

/// DRUID Pool
pub type DruidPool = BTreeMap<String, DruidDroplet>;

/// Token to uniquely identify messages.
pub type Token = u64;

/// Enum that determines full UTXO retrieval or subset UTXO retrieval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UtxoFetchType {
    All,
    AnyOf(Vec<String>),
}

/// Struct used to keep-track of the next receipt-based payment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbPaymentData {
    pub sender_asset: Asset,
    pub sender_half_druid: String,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
}

/// Struct used to make a request for a new receipt-based payment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbPaymentRequestData {
    pub sender_address: String,
    pub sender_half_druid: String,
    pub sender_from_addr: String,
    pub sender_asset: Asset,
}

/// Struct used to make a response to a new receipt-based payment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbPaymentResponseData {
    pub receiver_address: String,
    pub receiver_half_druid: String,
    pub sender_druid_expectation: DruidExpectation,
}

/// A placeholder struct for sensible feedback
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub success: bool,
    pub reason: &'static str,
}

/// Mined block as stored in DB.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct StoredSerializingBlock {
    pub block: Block,
    pub mining_tx_hash_and_nonces: BTreeMap<u64, (String, Vec<u8>)>,
}

/// Common info in all mined block that form a complete block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonBlockInfo {
    pub block: Block,
    pub block_txs: BTreeMap<String, Transaction>,
}

/// Additional info specific to one of the mined block that form a complete block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinedBlockExtraInfo {
    pub nonce: Vec<u8>,
    pub mining_tx: (String, Transaction),
    pub shutdown: bool,
}

/// Stored block info needed to generate next block
#[derive(Default, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockStoredInfo {
    pub block_hash: String,
    pub block_num: u64,
    pub nonce: Vec<u8>,
    pub merkle_hash: String,
    pub mining_transactions: BTreeMap<String, Transaction>,
    pub shutdown: bool,
}

/// PoW structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWork {
    pub address: String,
    pub nonce: Vec<u8>,
}

/// PoW structure for blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWorkBlock {
    pub nonce: Vec<u8>,
    pub block: Block,
}

impl Default for ProofOfWorkBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofOfWorkBlock {
    ///Proof of work block constructor
    pub fn new() -> Self {
        ProofOfWorkBlock {
            nonce: Vec::new(),
            block: Block::new(),
        }
    }
}

/// Druid pool structure for checking and holding participants
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DruidDroplet {
    pub participants: usize,
    pub tx: BTreeMap<String, Transaction>,
}

/// A placeholder Contract struct
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contract;

/// A placeholder Heat struct
pub struct Heat;

/// Denotes existing node types
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Miner,
    Storage,
    Compute,
    User,
    PreLaunch,
}

/// Returns a string to represent the specified node type
pub fn node_type_as_str(node_type: NodeType) -> &'static str {
    match node_type {
        NodeType::Miner => "Miner",
        NodeType::Compute => "Compute",
        NodeType::Storage => "Storage",
        NodeType::User => "User",
        NodeType::PreLaunch => "Prelaunch",
        _ => "The requested node is an unknown node type",
    }
}

// Returns a vector of possible API routes for the specified node type
// TODO: Isn't there way we don't have to hard code this?
pub fn api_debug_routes(node_type: &str) -> Vec<String> {
    match node_type {
        "Miner" => vec![
            "current_mining_block".to_owned(),
            "change_passphrase".to_owned(),
            "export_keypairs".to_owned(),
            "wallet_info".to_owned(),
            "import_keypairs".to_owned(),
            "new_payment_address".to_owned(),
            "debug_data".to_owned(),
        ],
        "Storage" => vec![
            "latest_block".to_owned(),
            "blockchain_entry_by_key".to_owned(),
            "block_by_num".to_owned(),
            "block_by_tx_hashes".to_owned(),
            "debug_data".to_owned(),
        ],
        "Compute" => vec![
            "fetch_balance".to_owned(),
            "create_transactions".to_owned(),
            "create_receipt_asset".to_owned(),
            "debug_data".to_owned(),
            "utxo_addresses".to_owned(),
        ],
        "User" => vec![
            "wallet_info".to_owned(),
            "make_payment".to_owned(),
            "make_ip_payment".to_owned(),
            "request_donation".to_owned(),
            "export_keypairs".to_owned(),
            "import_keypairs".to_owned(),
            "update_running_total".to_owned(),
            "new_payment_address".to_owned(),
            "create_receipt_asset".to_owned(),
            "change_passphrase".to_owned(),
            "debug_data".to_owned(),
        ],
        /* Miner node with User node capabilities */
        "Miner/User" => vec![
            "wallet_info".to_owned(),
            "make_payment".to_owned(),
            "make_ip_payment".to_owned(),
            "request_donation".to_owned(),
            "export_keypairs".to_owned(),
            "import_keypairs".to_owned(),
            "update_running_total".to_owned(),
            "new_payment_address".to_owned(),
            "create_receipt_asset".to_owned(),
            "change_passphrase".to_owned(),
            "current_mining_block".to_owned(),
            "debug_data".to_owned(),
        ],
        _ => Vec::new(),
    }
}

/// Mined block or transaction as stored in DB.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockchainItem {
    pub version: u32,
    pub item_meta: BlockchainItemMeta,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub data_json: Vec<u8>,
}

impl BlockchainItem {
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

/// Denotes blockchain item metadata
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockchainItemMeta {
    Block { block_num: u64, tx_len: u32 },
    Tx { block_num: u64, tx_num: u32 },
}

impl Default for BlockchainItemMeta {
    fn default() -> Self {
        Self::Block {
            block_num: 0,
            tx_len: 0,
        }
    }
}

impl BlockchainItemMeta {
    pub fn as_type(&self) -> BlockchainItemType {
        match self {
            Self::Block { .. } => BlockchainItemType::Block,
            Self::Tx { .. } => BlockchainItemType::Tx,
        }
    }
}

/// Denotes blockchain item types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockchainItemType {
    Block,
    Tx,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbItem {
    pub column: String,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
}

/// Internal protocol messages exchanged between nodes.
/// Handle nodes membership & bootstrapping. Wrap higher-level protocols.
///
/// ### Message IDs
/// The requests & response pairs must have corresponding message IDs to make sure
/// that an application is able to match them. However, not all requests require responses,
/// and in this case the application will not be registering its interest in a response with
/// a certain message ID.
///
/// Message IDs are also used for _gossip_: a node will remember message IDs it has seen and will
/// retransmit all messages it has not seen yet.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum CommMessage {
    /// Handshake request that peers send when they connect to someone.
    HandshakeRequest {
        /// Node network version.
        network_version: u32,
        /// Type of node sending the request.
        node_type: NodeType,
        /// Publicly available socket address of the node that can be used for inbound connections.
        public_address: SocketAddr,
    },
    /// Handshake response.
    HandshakeResponse {
        /// Node network version.
        network_version: u32,
        /// Type of node sending the response.
        node_type: NodeType,
        /// contacts of ring members.
        contacts: Vec<SocketAddr>,
    },
    /// Gossip message, multicast to all peers within the same ring.
    Gossip {
        /// Contents of the gossip message. Can encapsulate other message types.
        payload: Bytes,
        /// Number of hops this message made.
        ttl: u8,
        /// Unique message identifier.
        id: Token,
    },
    /// Wraps a direct message from peer to peer. Can encapsulate other message types.
    Direct {
        /// Contents of a message. Can be serialized message of another type.
        payload: Bytes,
        /// Unique message ID. Can be used for correspondence between requests and responses.
        id: Token,
    },
}

///============ STORAGE NODE ============///

/// Encapsulates storage requests
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize, Clone)]
pub enum StorageRequest {
    GetBlockchainItem {
        key: String,
    },
    SendBlockchainItem {
        key: String,
        item: BlockchainItem,
    },
    GetHistory {
        start_time: u64,
        end_time: u64,
    },
    GetUnicornTable {
        n_last_items: Option<u64>,
    },
    SendPow {
        pow: ProofOfWork,
    },
    SendBlock {
        common: CommonBlockInfo,
        mined_info: MinedBlockExtraInfo,
    },
    Store {
        incoming_contract: Contract,
    },
    Closing,
    SendRaftCmd(RaftMessageWrapper),
}

impl fmt::Debug for StorageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use StorageRequest::*;

        match *self {
            GetBlockchainItem { ref key } => write!(f, "GetBlockchainItem"),
            SendBlockchainItem { ref key, ref item } => write!(f, "SendBlockchainItem"),
            GetHistory {
                ref start_time,
                ref end_time,
            } => write!(f, "GetHistory"),
            GetUnicornTable { ref n_last_items } => write!(f, "GetUnicornTable"),
            SendPow { ref pow } => write!(f, "SendPoW"),
            SendBlock {
                ref common,
                ref mined_info,
            } => write!(f, "SendBlock"),
            Store {
                ref incoming_contract,
            } => write!(f, "Store"),
            Closing => write!(f, "Closing"),
            SendRaftCmd(_) => write!(f, "SendRaftCmd"),
        }
    }
}

pub trait StorageInterface {
    /// Get a blockchain item from stored history.
    ///
    /// ### Arguments
    ///
    /// * `peer` - The requestor address.
    /// * `key`  - The blockchain item key.
    fn get_blockchain_item(&mut self, peer: SocketAddr, key: String) -> Response;

    /// Receive a blockchain item from storage node.
    ///
    /// ### Arguments
    ///
    /// * `peer` - The requestor address.
    /// * `key`  - The blockchain item key.
    /// * `item` - The data associated with key.
    fn receive_blockchain_item(
        &mut self,
        peer: SocketAddr,
        key: String,
        item: BlockchainItem,
    ) -> Response;

    /// Returns a read only section of a stored history.
    /// Time slices are considered to be block IDs (u64).
    fn get_history(&self, start_time: &u64, end_time: &u64) -> Response;

    /// Whitelists the supplied address for edit permissions.
    ///
    /// ### Arguments
    ///
    /// * `address` - Address to whitelist
    fn whitelist(&mut self, address: SocketAddr) -> Response;

    /// Provides the UnicornShard table, with an optional section slice.
    /// Not providing a section slice will return the entire table.
    ///
    /// ### Arguments
    ///
    /// * `n_last_items`    - Number of last items to fetch from unicorn list
    fn get_unicorn_table(&self, n_last_items: Option<u64>) -> Response;

    /// Receives a PoW to match against the current pre-block.
    ///
    /// ### Arguments
    ///
    /// * `pow` - Proof of Work to match
    fn receive_pow(&self, pow: ProofOfWork) -> Response;

    /// Receives agreed contracts for storage
    ///
    /// ### Arguments
    ///
    /// * `contract`    - Contract to store
    fn receive_contracts(&self, contract: Contract) -> Response;
}

///============ MINER NODE ============///

/// Encapsulates miner requests
#[derive(Serialize, Deserialize, Clone)]
pub enum MineRequest {
    SendBlock {
        block: Vec<u8>,
        reward: TokenAmount,
    },
    SendRandomNum {
        rnum: Vec<u8>,
        win_coinbases: Vec<String>,
    },
    SendPartitionList {
        p_list: Vec<ProofOfWork>,
    },
    SendBlockchainItem {
        key: String,
        item: BlockchainItem,
    },
    SendTransactions {
        tx_merkle_verification: Vec<String>,
    },
    Closing,
}

impl fmt::Debug for MineRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MineRequest::*;

        match *self {
            SendBlockchainItem { ref key, ref item } => write!(f, "SendBlockchainItem"),
            SendBlock {
                ref block,
                ref reward,
            } => write!(f, "SendBlock"),
            SendRandomNum {
                ref rnum,
                ref win_coinbases,
            } => write!(f, "SendRandomNum"),
            SendPartitionList { ref p_list } => write!(f, "SendPartitionList"),
            SendTransactions {
                ref tx_merkle_verification,
            } => write!(f, "SendTransactions"),
            Closing => write!(f, "Closing"),
        }
    }
}

pub trait MinerInterface {
    /// Receive a blockchain item from storage node.
    ///
    /// ### Arguments
    ///
    /// * `peer` - The requestor address.
    /// * `key`  - The blockchain item key.
    /// * `item` - The data associated with key.
    fn receive_blockchain_item(
        &mut self,
        peer: SocketAddr,
        key: String,
        item: BlockchainItem,
    ) -> Response;
}

///============ COMPUTE NODE ============///

// Encapsulates compute requests injected by API
#[derive(Deserialize, Serialize, Clone)]
pub enum ComputeApiRequest {
    SendCreateReceiptRequest {
        receipt_amount: u64,
        script_public_key: String,
        public_key: String,
        signature: String,
    },
    SendTransactions {
        transactions: Vec<Transaction>,
    },
}

/// Encapsulates compute requests & responses.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum ComputeRequest {
    /// Process an API internal request
    ComputeApi(ComputeApiRequest),

    SendRbTransaction {
        transaction: Transaction,
    },
    SendUtxoRequest {
        address_list: UtxoFetchType,
    },
    SendBlockStored(BlockStoredInfo),
    SendPoW {
        block_num: u64,
        nonce: Vec<u8>,
        coinbase: Transaction,
    },
    SendPartitionEntry {
        partition_entry: ProofOfWork,
    },
    SendTransactions {
        transactions: Vec<Transaction>,
    },
    SendPartitionRequest,
    SendUserBlockNotificationRequest,
    Closing,
    SendRaftCmd(RaftMessageWrapper),
}

impl fmt::Debug for ComputeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ComputeRequest::*;

        match *self {
            ComputeApi(ComputeApiRequest::SendCreateReceiptRequest { .. }) => {
                write!(f, "Api::SendCreateReceiptRequest")
            }
            ComputeApi(ComputeApiRequest::SendTransactions { .. }) => {
                write!(f, "Api::SendTransactions")
            }

            SendUtxoRequest { ref address_list } => write!(f, "SendUtxoRequest"),
            SendBlockStored(ref _info) => write!(f, "SendBlockStored"),
            SendPoW {
                ref block_num,
                ref nonce,
                ref coinbase,
            } => write!(f, "SendPoW({})", block_num),
            SendPartitionEntry {
                ref partition_entry,
            } => write!(f, "SendPartitionEntry"),
            SendTransactions { ref transactions } => write!(f, "SendTransactions"),
            SendRbTransaction { ref transaction } => write!(f, "SendRbTransaction"),
            SendUserBlockNotificationRequest => write!(f, "SendUserBlockNotificationRequest"),
            SendPartitionRequest => write!(f, "SendPartitionRequest"),
            Closing => write!(f, "Closing"),
            SendRaftCmd(_) => write!(f, "SendRaftCmd"),
        }
    }
}

pub trait ComputeInterface {
    /// Fetch UTXO set for given addresses
    fn fetch_utxo_set(&mut self, peer: SocketAddr, address_list: UtxoFetchType) -> Response;

    /// Partitions a set of provided UUIDs for key creation/agreement
    /// TODO: Figure out the correct return type
    fn partition(&self, uuids: Vec<&'static str>) -> Response;

    /// Returns the internal service level data
    fn get_service_levels(&self) -> Response;

    /// Receives transactions to be bundled into blocks
    ///
    /// ### Arguments
    ///
    /// * `transactions` - Transactions to be added into blocks.
    fn receive_transactions(&mut self, transactions: Vec<Transaction>) -> Response;

    /// Executes a received and approved contract
    ///
    /// ### Arguments
    ///
    /// * `contract` - Contract struct containing the contract to be executed.
    fn execute_contract(&self, contract: Contract) -> Response;

    /// Returns the next block reward value
    fn get_next_block_reward(&self) -> f64;
}

pub trait ComputeApi {
    /// Get the UTXO tracked set
    fn get_committed_utxo_tracked_set(&self) -> &TrackedUtxoSet;
    /// Get pending DRUID pool
    fn get_pending_druid_pool(&self) -> &DruidPool;
}

///============ USER NODE ============///

/// Encapsulates user requests injected by API
#[derive(Deserialize, Serialize, Clone)]
pub enum UserApiRequest {
    /// Request to generate receipt-based asset
    SendCreateReceiptRequest { receipt_amount: u64 },

    /// Request to fetch UTXO set and update running total for specified addresses
    UpdateWalletFromUtxoSet {
        // TODO: Might need to change this request to a generic type for multiple use cases
        address_list: UtxoFetchType,
    },

    /// Request donation
    RequestDonation { paying_peer: SocketAddr },

    /// Request to make a payment to an IP address
    MakeIpPayment {
        payment_peer: SocketAddr,
        amount: TokenAmount,
    },

    /// Request to make a payment to a public key address
    MakePayment {
        address: String,
        amount: TokenAmount,
    },
}

/// Encapsulates user requests
#[derive(Deserialize, Serialize, Clone)]
pub enum UserRequest {
    /// Process an API internal request
    UserApi(UserApiRequest),

    /// Request to make a receipt-based payment
    SendRbPaymentRequest {
        rb_payment_request_data: RbPaymentRequestData,
    },
    /// Provide response for receipt-based payment request
    SendRbPaymentResponse {
        rb_payment_response: Option<RbPaymentResponseData>,
    },
    /// Request payment address with optional proof of work
    SendAddressRequest,
    /// Provide payment address with optional proof of work
    SendPaymentAddress {
        address: String,
    },
    /// Complete payment
    SendPaymentTransaction {
        transaction: Transaction,
    },

    /// Process received utxo set
    SendUtxoSet {
        utxo_set: UtxoSet,
    },
    /// Process received block being mined
    BlockMining {
        block: Block,
    },
    Closing,
}

impl fmt::Debug for UserRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UserApiRequest::*;
        use UserRequest::*;

        match *self {
            UserApi(UpdateWalletFromUtxoSet { .. }) => write!(f, "UpdateWalletFromUtxoSet"),
            UserApi(RequestDonation { .. }) => write!(f, "RequestDonation"),
            UserApi(MakeIpPayment { .. }) => write!(f, "MakeIpPayment"),
            UserApi(MakePayment { .. }) => write!(f, "MakePayment"),
            UserApi(SendCreateReceiptRequest { .. }) => write!(f, "SendCreateReceiptRequest"),

            SendAddressRequest { .. } => write!(f, "SendAddressRequest"),
            SendPaymentAddress { .. } => write!(f, "SendPaymentAddress"),
            SendPaymentTransaction { .. } => write!(f, "SendPaymentTransaction"),

            SendRbPaymentRequest { .. } => write!(f, "SendRbPaymentRequest"),
            SendRbPaymentResponse { .. } => write!(f, "SendRbPaymentResponse"),

            SendUtxoSet { .. } => write!(f, "SendUtxoSet"),
            BlockMining { .. } => write!(f, "BlockMining"),
            Closing => write!(f, "Closing"),
        }
    }
}
///============ PRE-LAUNCH NODE ============///
///
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DebugData {
    pub node_type: String,
    pub node_api: Vec<String>,
    pub node_peers: Vec<(String, SocketAddr, String)>,
}

/// Encapsulates storage requests
#[derive(Deserialize, Serialize, Clone)]
pub enum PreLaunchRequest {
    SendDbItems {
        committed: CommittedIndex,
        items: Vec<DbItem>,
    },
    Closing,
}

impl fmt::Debug for PreLaunchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PreLaunchRequest::*;

        match *self {
            SendDbItems { .. } => write!(f, "SendDbItems"),
            Closing => write!(f, "Closing"),
        }
    }
}
