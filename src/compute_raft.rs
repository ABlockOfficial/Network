use crate::active_raft::ActiveRaft;
use crate::configurations::ComputeNodeConfig;
use crate::constants::{BLOCK_SIZE_IN_TX, TX_POOL_LIMIT};
use crate::interfaces::BlockStoredInfo;
use crate::raft::{RaftData, RaftMessageWrapper};
use bincode::{deserialize, serialize};
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use naom::primitives::transaction_utils::get_inputs_previous_out_hash;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{self, Instant};
use tracing::{debug, error, trace, warn};

/// Item serialized into RaftData and process by Raft.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ComputeRaftItem {
    FirstBlock(BTreeMap<String, Transaction>),
    Block(BlockStoredInfo),
    Transactions(BTreeMap<String, Transaction>),
    DruidTransactions(Vec<BTreeMap<String, Transaction>>),
}

/// Key serialized into RaftData and process by Raft.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComputeRaftKey {
    proposer_id: u64,
    proposal_id: u64,
}

/// Commited item to process.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommittedItem {
    Transactions,
    FirstBlock,
    Block,
}

/// Accumulated previous block info
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AccumulatingBlockStoredInfo {
    /// Accumulating first block utxo_set
    FirstBlock(BTreeMap<String, Transaction>),
    /// Accumulating other blocks BlockStoredInfo
    Block(BlockStoredInfo),
}

/// All fields that are consensused between the RAFT group.
/// These fields need to be written and read from a committed log event.
#[derive(Clone, Debug, Default)]
pub struct ComputeConsensused {
    /// Sufficient majority
    unanimous_majority: usize,
    /// Sufficient majority
    sufficient_majority: usize,
    /// Committed transaction pool.
    tx_pool: BTreeMap<String, Transaction>,
    /// Committed DRUID transactions.
    tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
    /// Header to use for next block if ready to generate.
    tx_current_block_previous_hash: Option<String>,
    /// Index of the last block,
    tx_current_block_num: Option<u64>,
    /// Current block ready to mine (consensused).
    current_block: Option<Block>,
    /// All transactions present in current_block (consensused).
    current_block_tx: BTreeMap<String, Transaction>,
    /// UTXO set containain the valid transaction to use as previous input hashes.
    utxo_set: BTreeMap<String, Transaction>,
    /// Accumulating block:
    /// Require majority of compute node votes for normal blocks.
    /// Require unanimit for first block.
    current_block_stored_info: BTreeMap<Vec<u8>, (AccumulatingBlockStoredInfo, BTreeSet<u64>)>,
}

/// Consensused Compute fields and consensus managment.
pub struct ComputeRaft {
    /// True if first peer (leader).
    first_raft_peer: bool,
    /// The raft instance to interact with.
    raft_active: ActiveRaft,
    /// Consensused fields.
    consensused: ComputeConsensused,
    /// Local transaction pool.
    local_tx_pool: BTreeMap<String, Transaction>,
    /// Local DRUID transaction pool.
    local_tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
    /// Block to propose: should contain all needed information.
    last_block_stored_infos: Vec<BlockStoredInfo>,
    /// Min duration between each transaction poposal.
    propose_transactions_timeout_duration: Duration,
    /// Timeout expiration time for transactions poposal.
    propose_transactions_timeout_at: Instant,
    /// Proposed items in flight.
    proposed_in_flight: BTreeMap<ComputeRaftKey, RaftData>,
    /// Proposed transaction in flight length.
    proposed_tx_pool_len: usize,
    /// Maximum transaction in flight length.
    proposed_tx_pool_len_max: usize,
    /// Maximum transaction consensused and in flight for proposing more.
    proposed_and_consensused_tx_pool_len_max: usize,
    /// The last id of a proposed item.
    proposed_last_id: u64,
}

impl fmt::Debug for ComputeRaft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ComputeRaft()")
    }
}

impl ComputeRaft {
    /// Create a ComputeRaft, need to spawn the raft loop to use raft.
    pub async fn new(config: &ComputeNodeConfig) -> Self {
        let raft_active = ActiveRaft::new(
            config.compute_node_idx,
            &config.compute_nodes,
            config.compute_raft != 0,
            Duration::from_millis(config.compute_raft_tick_timeout as u64),
        );

        let propose_transactions_timeout_duration =
            Duration::from_millis(config.compute_transaction_timeout as u64);
        let propose_transactions_timeout_at =
            Instant::now() + propose_transactions_timeout_duration;

        let utxo_set = config
            .compute_seed_utxo
            .iter()
            .map(|hash| (hash.clone(), Transaction::new()))
            .collect();

        let first_raft_peer = config.compute_node_idx == 0 || !raft_active.use_raft();
        let peers_len = raft_active.peers_len();

        let consensused = ComputeConsensused {
            unanimous_majority: peers_len,
            sufficient_majority: peers_len / 2 + 1,
            ..ComputeConsensused::default()
        };

        Self {
            first_raft_peer,
            raft_active,
            consensused,
            local_tx_pool: BTreeMap::new(),
            local_tx_druid_pool: Vec::new(),
            last_block_stored_infos: Vec::new(),
            propose_transactions_timeout_duration,
            propose_transactions_timeout_at,
            proposed_in_flight: BTreeMap::new(),
            proposed_tx_pool_len: 0,
            proposed_tx_pool_len_max: BLOCK_SIZE_IN_TX / peers_len,
            proposed_and_consensused_tx_pool_len_max: BLOCK_SIZE_IN_TX * 2,
            proposed_last_id: 0,
        }
        .propose_initial_uxto_set(utxo_set)
        .await
    }

    /// All the peers to connect to when using raft.
    pub fn raft_peer_to_connect(&self) -> impl Iterator<Item = &SocketAddr> {
        self.raft_active.raft_peer_to_connect()
    }

    /// Blocks & waits for a next event from a peer.
    pub fn raft_loop(&self) -> impl Future<Output = ()> {
        self.raft_active.raft_loop()
    }

    /// Signal to the raft loop to complete
    pub async fn close_raft_loop(&mut self) {
        self.raft_active.close_raft_loop().await
    }

    /// Blocks & waits for a next commit from a peer.
    pub async fn next_commit(&self) -> Option<RaftData> {
        self.raft_active.next_commit().await
    }

    /// Process result from next_commit.
    /// Return Some if block to mine is ready to generate.
    pub async fn received_commit(&mut self, raft_data: RaftData) -> Option<CommittedItem> {
        let (key, item) = match deserialize::<(ComputeRaftKey, ComputeRaftItem)>(&raft_data) {
            Ok((key, item)) => {
                if self.proposed_in_flight.remove(&key).is_some() {
                    if let ComputeRaftItem::Transactions(ref txs) = &item {
                        self.proposed_tx_pool_len -= txs.len();
                    }
                }
                (key, item)
            }
            Err(error) => {
                warn!(?error, "ComputeRaftItem-deserialize");
                return None;
            }
        };

        match item {
            ComputeRaftItem::FirstBlock(uxto_set) => {
                if !self.consensused.is_first_block() {
                    error!("Proposed FirstBlock after startup {:?}", key);
                    return None;
                }

                self.consensused.append_first_block_info(key, uxto_set);
                if self.consensused.has_different_block_stored_info() {
                    error!("Proposed uxtosets are different {:?}", key);
                }

                if self.consensused.has_block_stored_info_ready() {
                    // First block complete:
                    self.consensused.apply_ready_block_stored_info();
                    return Some(CommittedItem::FirstBlock);
                }
            }
            ComputeRaftItem::Transactions(mut txs) => {
                self.consensused.tx_pool.append(&mut txs);
                return Some(CommittedItem::Transactions);
            }
            ComputeRaftItem::DruidTransactions(mut txs) => {
                self.consensused.tx_druid_pool.append(&mut txs);
                return Some(CommittedItem::Transactions);
            }
            ComputeRaftItem::Block(info) => {
                if !self.consensused.is_current_block(info.block_num) {
                    // Ignore already known or invalid blocks
                    trace!("Ignore invalid or outdated block stored info {:?}", key);
                    return None;
                }

                self.consensused.append_block_stored_info(key, info);
                if self.consensused.has_different_block_stored_info() {
                    warn!("Proposed previous blocks are different {:?}", key);
                }

                if self.consensused.has_block_stored_info_ready() {
                    // New block:
                    // Must not populate further tx_pool & tx_druid_pool
                    // before generating block.
                    self.consensused.apply_ready_block_stored_info();
                    return Some(CommittedItem::Block);
                }
            }
        }
        None
    }

    /// Blocks & waits for a next message to dispatch from a peer.
    /// Message needs to be sent to given peer address.
    pub async fn next_msg(&self) -> Option<(SocketAddr, RaftMessageWrapper)> {
        self.raft_active.next_msg().await
    }

    /// Process a raft message: send to spawned raft loop.
    pub async fn received_message(&mut self, msg: RaftMessageWrapper) {
        self.raft_active.received_message(msg).await
    }

    /// Blocks & waits for a timeout to propose transactions.
    pub async fn timeout_propose_transactions(&self) {
        time::delay_until(self.propose_transactions_timeout_at).await;
    }

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    async fn propose_initial_uxto_set(mut self, uxto_set: BTreeMap<String, Transaction>) -> Self {
        self.propose_item(&ComputeRaftItem::FirstBlock(uxto_set))
            .await;
        self
    }

    /// Process as received block info.
    pub async fn propose_block_with_last_info(&mut self) {
        let local_blocks = std::mem::take(&mut self.last_block_stored_infos);
        for block in local_blocks.into_iter() {
            self.propose_item(&ComputeRaftItem::Block(block)).await;
        }
    }

    /// Process as a result of timeout_propose_transactions.
    /// Reset timeout, and propose local transactions if available.
    pub async fn propose_local_transactions_at_timeout(&mut self) {
        self.propose_transactions_timeout_at =
            Instant::now() + self.propose_transactions_timeout_duration;

        let max_add = self
            .proposed_and_consensused_tx_pool_len_max
            .saturating_sub(self.proposed_and_consensused_tx_pool_len());

        let max_propose_len = std::cmp::min(max_add, self.proposed_tx_pool_len_max);
        let txs = take_first_n(max_propose_len, &mut self.local_tx_pool);
        if !txs.is_empty() {
            self.proposed_tx_pool_len += txs.len();
            self.propose_item(&ComputeRaftItem::Transactions(txs)).await;
        }
    }

    /// Process as a result of timeout_propose_transactions.
    /// Propose druid transactions if available.
    pub async fn propose_local_druid_transactions(&mut self) {
        let txs = std::mem::take(&mut self.local_tx_druid_pool);
        if !txs.is_empty() {
            self.propose_item(&ComputeRaftItem::DruidTransactions(txs))
                .await;
        }
    }

    /// Propose an item to raft if use_raft, or commit it otherwise.
    async fn propose_item(&mut self, item: &ComputeRaftItem) {
        self.proposed_last_id += 1;
        let key = ComputeRaftKey {
            proposer_id: self.raft_active.peer_id(),
            proposal_id: self.proposed_last_id,
        };

        debug!("propose_item: {:?} -> {:?}", key, item);
        let data = serialize(&(&key, item)).unwrap();
        self.proposed_in_flight.insert(key, data.clone());

        self.raft_active.propose_data(data).await
    }

    /// The current tx_pool that will be used to generate next block
    pub fn get_committed_tx_pool(&self) -> &BTreeMap<String, Transaction> {
        &self.consensused.tx_pool
    }

    /// Whether adding these will grow our pool within the limit.
    pub fn tx_pool_can_accept(&self, extra_len: usize) -> bool {
        self.combined_tx_pool_len() + extra_len <= TX_POOL_LIMIT
    }

    /// Current tx_pool lenght handled by this node.
    fn combined_tx_pool_len(&self) -> usize {
        self.local_tx_pool.len() + self.proposed_and_consensused_tx_pool_len()
    }

    /// Current proposed tx_pool lenght handled by this node.
    fn proposed_and_consensused_tx_pool_len(&self) -> usize {
        self.proposed_tx_pool_len + self.consensused.tx_pool.len()
    }

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    pub fn append_to_tx_pool(&mut self, mut transactions: BTreeMap<String, Transaction>) {
        self.local_tx_pool.append(&mut transactions);
    }

    /// Set result of mined block necessary for new block to be generated.
    pub fn append_block_stored_info(&mut self, info: BlockStoredInfo) {
        self.last_block_stored_infos.push(info);
    }

    /// Append new transaction to our local pool from which to propose
    /// consensused transactions.
    pub fn append_to_tx_druid_pool(&mut self, transactions: BTreeMap<String, Transaction>) {
        self.local_tx_druid_pool.push(transactions);
    }

    /// Set consensused committed block to mine.
    /// Internal call, public for test only.
    pub fn set_committed_mining_block(
        &mut self,
        block: Block,
        block_tx: BTreeMap<String, Transaction>,
    ) {
        self.consensused.set_committed_mining_block(block, block_tx)
    }

    /// Current block to mine or being mined.
    pub fn get_mining_block(&self) -> &Option<Block> {
        self.consensused.get_mining_block()
    }

    /// Current utxo_set including block being mined
    pub fn get_committed_utxo_set(&self) -> &BTreeMap<String, Transaction> {
        &self.consensused.get_committed_utxo_set()
    }

    /// Take mining block when mining is completed, use to populate mined block.
    pub fn take_mining_block(&mut self) -> (Block, BTreeMap<String, Transaction>) {
        self.consensused.take_mining_block()
    }

    /// Processes the very first block with utxo_set
    pub fn generate_first_block(&mut self) {
        self.consensused.generate_first_block()
    }

    /// Processes the next batch of transactions from the floating tx pool
    /// to create the next block
    pub fn generate_block(&mut self) {
        self.consensused.generate_block()
    }

    /// Find transactions for the current block.
    pub fn find_invalid_new_txs(&self, new_txs: &BTreeMap<String, Transaction>) -> Vec<String> {
        self.consensused.find_invalid_new_txs(new_txs)
    }
}

impl ComputeConsensused {
    /// Set consensused committed block to mine.
    /// Internal call, public for test only.
    pub fn set_committed_mining_block(
        &mut self,
        block: Block,
        block_tx: BTreeMap<String, Transaction>,
    ) {
        // Transaction only depend on mined block: append at the end.
        // The block is about to be mined, all transaction accepted can be used
        // to accept next block transactions.
        // TODO: Roll back append and removal if block rejected by miners.
        self.utxo_set.append(&mut block_tx.clone());

        self.current_block = Some(block);
        self.current_block_tx = block_tx;
    }

    /// Current block to mine or being mined.
    pub fn get_mining_block(&self) -> &Option<Block> {
        &self.current_block
    }

    /// Current utxo_set including block being mined
    pub fn get_committed_utxo_set(&self) -> &BTreeMap<String, Transaction> {
        &self.utxo_set
    }

    /// Take mining block when mining is completed, use to populate mined block.
    pub fn take_mining_block(&mut self) -> (Block, BTreeMap<String, Transaction>) {
        let block = std::mem::take(&mut self.current_block).unwrap();
        let block_tx = std::mem::take(&mut self.current_block_tx);
        (block, block_tx)
    }

    /// Processes the very first block with utxo_set
    pub fn generate_first_block(&mut self) {
        let next_block_tx = self.utxo_set.clone();
        let mut next_block = Block::new();
        next_block.transactions = next_block_tx.keys().cloned().collect();

        self.set_committed_mining_block(next_block, next_block_tx)
    }

    /// Processes the next batch of transactions from the floating tx pool
    /// to create the next block
    ///
    /// TODO: Label previous block time
    pub fn generate_block(&mut self) {
        let mut next_block = Block::new();
        let mut next_block_tx = BTreeMap::new();

        self.update_committed_dde_tx(&mut next_block, &mut next_block_tx);
        self.update_current_block_tx(&mut next_block, &mut next_block_tx);
        self.update_block_header(&mut next_block);

        self.set_committed_mining_block(next_block, next_block_tx)
    }

    /// Apply all consensused transactions to the block
    fn update_committed_dde_tx(
        &mut self,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        let mut tx_druid_pool = std::mem::take(&mut self.tx_druid_pool);
        for txs in tx_druid_pool.drain(..) {
            if !self.find_invalid_new_txs(&txs).is_empty() {
                // Drop invalid DRUID droplet
                continue;
            }

            // Process valid set of transactions from a single DRUID droplet.
            self.update_current_block_tx_with_given_valid_txs(txs, block, block_tx);
        }
    }

    /// Apply all valid consensused transactions to the block until BLOCK_SIZE_IN_TX
    fn update_current_block_tx(
        &mut self,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        // Clean tx_pool of invalid transactions for this block.
        for invalid in self.find_invalid_new_txs(&self.tx_pool) {
            self.tx_pool.remove(&invalid);
        }

        // Select subset of transaction to fill the block.
        let txs = take_first_n(BLOCK_SIZE_IN_TX, &mut self.tx_pool);

        // Process valid set of transactions.
        self.update_current_block_tx_with_given_valid_txs(txs, block, block_tx);
    }

    /// Apply the consensused information for the header.
    fn update_block_header(&mut self, block: &mut Block) {
        let previous_hash = std::mem::take(&mut self.tx_current_block_previous_hash).unwrap();
        let b_num = self.tx_current_block_num.unwrap();

        block.header.time = b_num as u32;
        block.header.previous_hash = Some(previous_hash);
        block.header.b_num = b_num;
    }

    /// Apply set of valid transactions to the block.
    fn update_current_block_tx_with_given_valid_txs(
        &mut self,
        mut txs: BTreeMap<String, Transaction>,
        block: &mut Block,
        block_tx: &mut BTreeMap<String, Transaction>,
    ) {
        for hash in get_inputs_previous_out_hash(txs.values()) {
            // All previous hash in valid txs set are present and must be removed.
            self.utxo_set.remove(hash).unwrap();
        }
        block.transactions.extend(txs.keys().cloned());
        block_tx.append(&mut txs);
    }

    /// Find transactions for the current block.
    pub fn find_invalid_new_txs(&self, new_txs: &BTreeMap<String, Transaction>) -> Vec<String> {
        let mut invalid = Vec::new();

        let mut removed_all = HashSet::new();
        for (hash_tx, value) in new_txs.iter() {
            let mut removed_roll_back = Vec::new();

            for hash_in in get_inputs_previous_out_hash(Some(value).into_iter()) {
                if self.utxo_set.contains_key(hash_in) && removed_all.insert(hash_in) {
                    removed_roll_back.push(hash_in);
                } else {
                    // Entry is invalid: roll back, mark entry and check next one.
                    for h in removed_roll_back {
                        removed_all.remove(h);
                    }
                    invalid.push(hash_tx.clone());
                    break;
                }
            }
        }

        invalid
    }

    /// Check if computing the first block.
    pub fn is_first_block(&self) -> bool {
        self.tx_current_block_num.is_none()
    }

    /// Check if computing the given block.
    pub fn is_current_block(&self, block_num: u64) -> bool {
        if let Some(tx_current_block_num) = self.tx_current_block_num {
            block_num == tx_current_block_num
        } else {
            false
        }
    }

    /// Check if we have inconsistent votes for the current block stored info.
    pub fn has_different_block_stored_info(&self) -> bool {
        self.current_block_stored_info.len() > 1
    }

    /// Check if we have enough votes to apply the block stored info.
    pub fn has_block_stored_info_ready(&self) -> bool {
        let threshold = if self.is_first_block() {
            self.unanimous_majority
        } else {
            self.sufficient_majority
        };

        self.max_agreeing_block_stored_info() >= threshold
    }

    /// Current maximum vote count for a block stored info.
    fn max_agreeing_block_stored_info(&self) -> usize {
        self.current_block_stored_info
            .values()
            .map(|v| v.1.len())
            .max()
            .unwrap_or(0)
    }

    /// Append a vote for first block info
    pub fn append_first_block_info(
        &mut self,
        key: ComputeRaftKey,
        utxo_set: BTreeMap<String, Transaction>,
    ) {
        self.append_current_block_stored_info(
            key,
            AccumulatingBlockStoredInfo::FirstBlock(utxo_set),
        )
    }

    /// Append a vote for a non first block info
    pub fn append_block_stored_info(&mut self, key: ComputeRaftKey, block: BlockStoredInfo) {
        self.append_current_block_stored_info(key, AccumulatingBlockStoredInfo::Block(block))
    }

    /// Append the given vote.
    pub fn append_current_block_stored_info(
        &mut self,
        key: ComputeRaftKey,
        block: AccumulatingBlockStoredInfo,
    ) {
        let block_ser = serialize(&block).unwrap();
        let block_hash = Sha3_256::digest(&block_ser).to_vec();

        self.current_block_stored_info
            .entry(block_hash)
            .or_insert((block, BTreeSet::new()))
            .1
            .insert(key.proposer_id);
    }

    /// Apply accumulated block info.
    pub fn apply_ready_block_stored_info(&mut self) {
        match self.take_ready_block_stored_info() {
            AccumulatingBlockStoredInfo::FirstBlock(utxo_set) => {
                self.tx_current_block_num = Some(0);
                self.utxo_set = utxo_set;
            }
            AccumulatingBlockStoredInfo::Block(mut info) => {
                self.tx_current_block_previous_hash = Some(info.block_hash);
                self.tx_current_block_num = Some(info.block_num + 1);
                self.utxo_set.append(&mut info.mining_transactions);
            }
        }
    }

    /// Take the block info with most vote and reset accumulator.
    fn take_ready_block_stored_info(&mut self) -> AccumulatingBlockStoredInfo {
        let infos = std::mem::take(&mut self.current_block_stored_info);
        infos
            .into_iter()
            .map(|(_digest, value)| value)
            .max_by_key(|(_, vote_ids)| vote_ids.len())
            .map(|(block_info, _)| block_info)
            .unwrap()
    }
}

/// Take the first `n` items of the given map.
fn take_first_n<K: Clone + Ord, V>(n: usize, from: &mut BTreeMap<K, V>) -> BTreeMap<K, V> {
    let mut result = std::mem::take(from);
    if let Some(max_key) = result.keys().nth(n).cloned() {
        // Set back overflowing in from.
        *from = result.split_off(&max_key);
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::configurations::NodeSpec;
    use crate::utils::create_valid_transaction;
    use sodiumoxide::crypto::sign;
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn generate_first_block_no_raft() {
        //
        // Arrange
        //
        let seed_utxo = ["000000", "000001", "000002"];
        let mut node = new_test_node(&seed_utxo).await;
        let mut expected_block_addr_to_hashes = BTreeMap::new();

        // 1. Add 2 valid and 2 double spend and one spent transactions
        // Keep only 2 valids, and first double spent by hash.
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003"],
            &["000100", "000101", "000103"],
            &mut expected_block_addr_to_hashes,
        ));

        //
        // Act
        //
        node.propose_local_transactions_at_timeout().await;
        node.propose_local_druid_transactions().await;
        node.propose_block_with_last_info().await;

        let commit = node.next_commit().await.unwrap();
        let first_block = node.received_commit(commit).await;
        let commit = node.next_commit().await.unwrap();
        let tx_no_block = node.received_commit(commit).await;

        //
        // Assert
        //
        let expected_utxo_t_hashes: BTreeSet<String> =
            seed_utxo.iter().map(|h| h.to_string()).collect();

        let actual_utxo_t_hashes: BTreeSet<String> =
            node.get_committed_utxo_set().keys().cloned().collect();

        assert_eq!(first_block, Some(CommittedItem::FirstBlock));
        assert_eq!(tx_no_block, Some(CommittedItem::Transactions));
        assert_eq!(actual_utxo_t_hashes, expected_utxo_t_hashes);
        assert_eq!(
            node.consensused.tx_pool.len(),
            expected_block_addr_to_hashes.len()
        );
        assert_eq!(node.consensused.tx_current_block_previous_hash, None);
    }

    #[tokio::test]
    async fn generate_current_block_no_raft() {
        //
        // Arrange
        //
        let seed_utxo = [
            // 1: (Skip "000003")
            "000000", "000001", "000002", // 2: (Skip "000012")
            "000010", "000011", // 3:
            "000020", "000021", "000023", // 4:
            "000030", "000031",
        ];
        let mut node = new_test_node(&seed_utxo).await;
        let mut expected_block_addr_to_hashes = BTreeMap::new();
        let mut expected_unused_utxo_hashes = Vec::<&str>::new();

        let commit = node.next_commit().await.unwrap();
        let _first_block = node.received_commit(commit).await.unwrap();
        let previous_block = BlockStoredInfo {
            block_hash: "0123".to_string(),
            block_num: 0,
            mining_transactions: BTreeMap::new(),
        };

        // 1. Add 2 valid and 2 double spend and one spent transactions
        // Keep only 2 valids, and first double spent by hash.
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003"],
            &["000100", "000101", "000103"],
            &mut expected_block_addr_to_hashes,
        ));
        node.append_to_tx_pool(valid_transaction(
            &["000000", "000002"],
            &["000200", "000202"],
            &mut expected_block_addr_to_hashes,
        ));
        expected_block_addr_to_hashes.remove(key_with_max_value(
            &expected_block_addr_to_hashes,
            "000100",
            "000200",
        ));
        expected_block_addr_to_hashes.remove("000103");
        // 2. Add double spend and spent within DRUID droplet
        // Drop all
        node.append_to_tx_druid_pool(valid_transaction(
            &["000010", "000010"],
            &["000310", "000311"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000011", "000012"],
            &["000311", "000312"],
            &mut BTreeMap::new(),
        ));
        expected_unused_utxo_hashes.extend(&["000010", "000011"]);
        // 3. Add double spend between DRUID droplet
        // Keep first one added
        node.append_to_tx_druid_pool(valid_transaction(
            &["000020", "000023"],
            &["000420", "000423"],
            &mut expected_block_addr_to_hashes,
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000021", "000023"],
            &["000521", "000523"],
            &mut BTreeMap::new(),
        ));
        expected_unused_utxo_hashes.extend(&["000021"]);
        // 4. Add double spend between DRUID droplet and transaction
        // Keep DRUID droplet
        node.append_to_tx_pool(valid_transaction(
            &["000030"],
            &["000621"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000030", "000031"],
            &["000730", "000731"],
            &mut expected_block_addr_to_hashes,
        ));

        //
        // Act
        //
        node.propose_local_transactions_at_timeout().await;
        node.propose_local_druid_transactions().await;

        node.append_block_stored_info(previous_block);
        node.propose_block_with_last_info().await;
        let mut commits = Vec::new();
        for _ in 0..3 {
            let commit = node.next_commit().await.unwrap();
            commits.push(node.received_commit(commit).await.unwrap());
        }
        node.generate_block();

        //
        // Assert
        //
        let expected_block_t_hashes: BTreeSet<String> =
            expected_block_addr_to_hashes.values().cloned().collect();
        let expected_utxo_t_hashes: BTreeSet<String> = expected_unused_utxo_hashes
            .iter()
            .map(|h| h.to_string())
            .chain(expected_block_t_hashes.iter().cloned())
            .collect();

        let actual_block_t_hashes: Option<BTreeSet<String>> = node
            .get_mining_block()
            .as_ref()
            .map(|b| b.transactions.iter().cloned().collect());
        let actual_block_tx_t_hashes: BTreeSet<String> =
            node.consensused.current_block_tx.keys().cloned().collect();
        let actual_utxo_t_hashes: BTreeSet<String> =
            node.get_committed_utxo_set().keys().cloned().collect();

        assert_eq!(
            commits,
            vec![
                CommittedItem::Transactions,
                CommittedItem::Transactions,
                CommittedItem::Block
            ]
        );
        assert_eq!(Some(expected_block_t_hashes.clone()), actual_block_t_hashes);
        assert_eq!(expected_block_t_hashes, actual_block_tx_t_hashes);
        assert_eq!(actual_utxo_t_hashes, expected_utxo_t_hashes);
        assert_eq!(node.consensused.tx_pool.len(), 0);
        assert_eq!(node.consensused.tx_druid_pool.len(), 0);
        assert_eq!(node.consensused.tx_current_block_previous_hash, None);
    }

    #[tokio::test]
    async fn in_flight_transactions_no_raft() {
        //
        // Arrange
        //
        let mut node = new_test_node(&[]).await;
        node.proposed_and_consensused_tx_pool_len_max = 3;
        node.proposed_tx_pool_len_max = 2;
        let commit = node.next_commit().await;
        node.received_commit(commit.unwrap()).await.unwrap();

        //
        // Act
        //
        let mut actual_combined_local_flight_consensused = Vec::new();
        let mut collect_info = |node: &ComputeRaft| {
            actual_combined_local_flight_consensused.push((
                node.combined_tx_pool_len(),
                node.local_tx_pool.len(),
                node.proposed_tx_pool_len,
                node.consensused.tx_pool.len(),
            ))
        };
        collect_info(&node);

        node.append_to_tx_pool(valid_transaction(
            &["000000", "000001", "000003", "000004", "000005", "000006"],
            &["000100", "000101", "000103", "000104", "000105", "000106"],
            &mut BTreeMap::new(),
        ));
        node.append_to_tx_druid_pool(valid_transaction(
            &["000010", "000011"],
            &["000200", "000200"],
            &mut BTreeMap::new(),
        ));
        collect_info(&node);

        for _ in 0..3 {
            node.propose_local_transactions_at_timeout().await;
            node.propose_local_druid_transactions().await;
            collect_info(&node);

            loop {
                tokio::select! {
                    commit = node.next_commit() => {node.received_commit(commit.unwrap()).await;}
                    _ = time::delay_for(Duration::from_millis(5)) => {break;}
                }
            }
            collect_info(&node);
        }

        //
        // Assert
        //
        assert_eq!(
            actual_combined_local_flight_consensused,
            vec![
                // Start
                (0, 0, 0, 0),
                // Transaction appended
                (6, 6, 0, 0),
                // Process 1st time out and commit: 2 in flight then consensused
                (6, 4, 2, 0),
                (6, 4, 0, 2),
                // Process 2nd time out and commit: 1 in flight then consensused
                // (max reached)
                (6, 3, 1, 2),
                (6, 3, 0, 3),
                // Process 3rd time out and commit: 0 in flight then consensused
                // (max reached)
                (6, 3, 0, 3),
                (6, 3, 0, 3)
            ]
        );
    }

    async fn new_test_node(seed_utxo: &[&str]) -> ComputeRaft {
        let compute_node = NodeSpec {
            address: "0.0.0.0:0".parse().unwrap(),
        };
        let compute_config = ComputeNodeConfig {
            compute_raft: 0,
            compute_node_idx: 0,
            compute_nodes: vec![compute_node],
            storage_nodes: vec![],
            user_nodes: vec![],
            compute_raft_tick_timeout: 10,
            compute_transaction_timeout: 50,
            compute_seed_utxo: seed_utxo.iter().map(|v| v.to_string()).collect(),
        };
        ComputeRaft::new(&compute_config).await
    }

    fn valid_transaction(
        intial_t_hashes: &[&str],
        receiver_addrs: &[&str],
        new_hashes: &mut BTreeMap<String, String>,
    ) -> BTreeMap<String, Transaction> {
        let (pk, sk) = sign::gen_keypair();

        let txs: Vec<_> = intial_t_hashes
            .iter()
            .copied()
            .zip(receiver_addrs.iter().copied())
            .map(|(hash, addr)| (create_valid_transaction(hash, addr, &pk, &sk), addr))
            .collect();

        new_hashes.extend(
            txs.iter()
                .map(|((h, _), addr)| (addr.to_string(), h.clone())),
        );
        txs.into_iter().map(|(tx, _)| tx).collect()
    }

    pub fn key_with_max_value<'a>(
        map: &BTreeMap<String, String>,
        key1: &'a str,
        key2: &'a str,
    ) -> &'a str {
        if map[key1] < map[key2] {
            key2
        } else {
            key1
        }
    }
}