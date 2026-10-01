//! Helix blocks as Mesh blocks.
//!
//! **Every operation is a balance change the node recorded** (#260), so a block's operations,
//! summed per account, are exactly how much each liquid balance moved in it — which is what Mesh
//! reconciliation checks, and why this service needs no balance exemptions. Nothing here is
//! computed from what a transaction *says* it does; the one derived step is splitting the fee out
//! of the sender's change, and only where the fee charged is provably the transaction's `fee`.

use helix_core::TxType;
use serde_json::json;

use crate::node;
use crate::types::{
    AccountIdentifier, Amount, Block, BlockIdentifier, Currency, Operation, OperationIdentifier,
    Transaction, TransactionIdentifier,
};

/// The fee a transaction paid.
pub const FEE: &str = "FEE";
/// What a transfer moved: taken from the sender, given to the recipient.
pub const TRANSFER: &str = "TRANSFER";
/// A validator's income: fee tips, the block reward, commission.
pub const REWARD: &str = "REWARD";
/// A transfer a smart contract made while a transaction ran.
pub const CONTRACT_TRANSFER: &str = "CONTRACT_TRANSFER";
/// A balance handed out in the genesis block.
pub const GENESIS: &str = "GENESIS";

/// The one status an operation here has: every operation is a change that happened.
pub const SUCCESS: &str = "SUCCESS";

/// The operation type for what a transaction of this type did to a balance, beyond its fee.
///
/// No `_` arm on purpose: a new transaction type does not compile until someone decides how Mesh
/// shows it.
pub fn op_type(tx_type: &TxType) -> &'static str {
    match tx_type {
        TxType::Transfer => TRANSFER,
        TxType::Stake => "STAKE",
        TxType::Unstake => "UNSTAKE",
        TxType::RegisterIdentity => "REGISTER_IDENTITY",
        TxType::RegisterName => "REGISTER_NAME",
        TxType::RegisterGuardians => "REGISTER_GUARDIANS",
        TxType::ApproveRecovery => "APPROVE_RECOVERY",
        TxType::DeployContract => "DEPLOY_CONTRACT",
        TxType::CallContract => "CALL_CONTRACT",
        TxType::CreateProposal => "CREATE_PROPOSAL",
        TxType::VoteProposal => "VOTE_PROPOSAL",
        TxType::ProvePersonhood => "PROVE_PERSONHOOD",
        TxType::ClaimUnbonded => "CLAIM_UNBONDED",
        TxType::CancelRecoveryRequest => "CANCEL_RECOVERY_REQUEST",
        TxType::SubmitDoubleSignEvidence => "SUBMIT_DOUBLE_SIGN_EVIDENCE",
        TxType::Delegate => "DELEGATE",
        TxType::Undelegate => "UNDELEGATE",
        TxType::Redelegate => "REDELEGATE",
        TxType::SetCommission => "SET_COMMISSION",
        TxType::Unjail => "UNJAIL",
        TxType::ProbationHeartbeat => "PROBATION_HEARTBEAT",
        TxType::SetRewardAddress => "SET_REWARD_ADDRESS",
    }
}

/// Every transaction type, in declaration order — what `/network/options` lists. Checked against
/// the enum itself by a test, so a variant left out here fails there.
pub const ALL_TX_TYPES: [TxType; 22] = [
    TxType::Transfer,
    TxType::Stake,
    TxType::Unstake,
    TxType::RegisterIdentity,
    TxType::RegisterName,
    TxType::RegisterGuardians,
    TxType::ApproveRecovery,
    TxType::DeployContract,
    TxType::CallContract,
    TxType::CreateProposal,
    TxType::VoteProposal,
    TxType::ProvePersonhood,
    TxType::ClaimUnbonded,
    TxType::CancelRecoveryRequest,
    TxType::SubmitDoubleSignEvidence,
    TxType::Delegate,
    TxType::Undelegate,
    TxType::Redelegate,
    TxType::SetCommission,
    TxType::Unjail,
    TxType::ProbationHeartbeat,
    TxType::SetRewardAddress,
];

/// Every operation type this service can emit.
pub fn operation_types() -> Vec<&'static str> {
    let mut types = vec![FEE, REWARD, CONTRACT_TRANSFER, GENESIS];
    types.extend(ALL_TX_TYPES.iter().map(op_type));
    types
}

/// Why a block cannot be shown.
#[derive(Debug, PartialEq, Eq)]
pub enum MapError {
    /// The node has no record of what the block did to balances: it executed it with a build
    /// before #260, or it pruned it. Retrying this node will not help.
    NoRecord(u64),
    /// The node answered something that is not a well-formed record.
    Malformed(String),
}

fn amount(delta: i128) -> Amount {
    Amount { value: delta.to_string(), currency: Currency::hlx() }
}

fn operation(index: usize, op_type: &str, account: &str, delta: i128, status: Option<&str>) -> Operation {
    Operation {
        operation_identifier: OperationIdentifier { index: index as u64 },
        op_type: op_type.to_string(),
        status: status.map(str::to_string),
        account: AccountIdentifier { address: account.to_string(), sub_account: None },
        amount: amount(delta),
    }
}

fn parse_delta(text: &str) -> Result<i128, MapError> {
    text.parse().map_err(|_| MapError::Malformed(format!("balance change {text:?} is not a number")))
}

fn parse_u64(text: &str, what: &str) -> Result<u64, MapError> {
    text.parse().map_err(|_| MapError::Malformed(format!("{what} {text:?} is not a number")))
}

/// The identifier of the pseudo-transaction that carries a block's own balance changes — its
/// reward. Not a transaction hash: prefixed so it can never be mistaken for one.
pub fn block_reward_id(block_hash: &str) -> String {
    format!("reward-{block_hash}")
}

/// The identifier of the pseudo-transaction that carries the genesis allocations.
pub fn genesis_id(block_hash: &str) -> String {
    format!("genesis-{block_hash}")
}

/// A block above genesis, from the node's view of it.
pub fn block(b: &node::Block) -> Result<Block, MapError> {
    let changes = b.balance_changes.as_ref().ok_or(MapError::NoRecord(b.height))?;
    let mut transactions = Vec::with_capacity(b.transactions.len() + 1);

    for (index, tx) in b.transactions.iter().enumerate() {
        let fee = parse_u64(&tx.fee_nano, "fee")? as i128;
        let mut ops = Vec::new();
        for change in changes.iter().filter(|c| c.tx_index == Some(index as u32)) {
            let delta = parse_delta(&change.delta_nano)?;
            match change.kind.as_str() {
                "reward" => ops.push((REWARD, change.account.as_str(), delta)),
                "contract" => ops.push((CONTRACT_TRANSFER, change.account.as_str(), delta)),
                "transaction" if change.account == tx.from && tx.status == "failed" => {
                    // A failed transaction moved nothing but its fee; what it charged is the fee.
                    ops.push((FEE, change.account.as_str(), delta));
                }
                "transaction" if change.account == tx.from && tx.status == "applied" && fee > 0 => {
                    // An applied transaction always paid its whole fee; the rest is its effect.
                    ops.push((FEE, change.account.as_str(), -fee));
                    let rest = delta + fee;
                    if rest != 0 {
                        ops.push((op_type(&tx.tx_type), change.account.as_str(), rest));
                    }
                }
                "transaction" => ops.push((op_type(&tx.tx_type), change.account.as_str(), delta)),
                other => return Err(MapError::Malformed(format!("unknown balance-change kind {other:?}"))),
            }
        }
        let operations = ops
            .into_iter()
            .enumerate()
            .map(|(i, (t, account, delta))| operation(i, t, account, delta, Some(SUCCESS)))
            .collect();
        transactions.push(Transaction {
            transaction_identifier: TransactionIdentifier { hash: tx.hash.clone() },
            operations,
            metadata: Some(json!({
                "tx_type": tx.tx_type,
                "status": tx.status,
                "error": tx.error,
                "nonce": tx.nonce,
                "amount_nano": tx.amount_nano,
                "fee_nano": tx.fee_nano,
                "memo": tx.memo,
            })),
        });
    }

    let rewards: Vec<Operation> = changes
        .iter()
        .filter(|c| c.tx_index.is_none())
        .enumerate()
        .map(|(i, c)| {
            if c.kind != "reward" {
                return Err(MapError::Malformed(format!("a block-level change of kind {:?}", c.kind)));
            }
            parse_delta(&c.delta_nano).map(|d| operation(i, REWARD, &c.account, d, Some(SUCCESS)))
        })
        .collect::<Result<_, _>>()?;
    if !rewards.is_empty() {
        transactions.push(Transaction {
            transaction_identifier: TransactionIdentifier { hash: block_reward_id(&b.hash) },
            operations: rewards,
            metadata: None,
        });
    }

    Ok(Block {
        block_identifier: BlockIdentifier { index: b.height, hash: b.hash.clone() },
        parent_block_identifier: BlockIdentifier {
            index: b.height.saturating_sub(1),
            hash: b.prev_hash.clone(),
        },
        timestamp: b.timestamp,
        transactions,
    })
}

/// The genesis block: its allocations are the balances everything else is reconciled from. Its
/// parent is itself, as Mesh expects of a chain's first block.
pub fn genesis_block(header: &node::Header, genesis: &node::Genesis) -> Block {
    let operations = genesis
        .allocations
        .iter()
        .enumerate()
        .map(|(i, a)| operation(i, GENESIS, &a.address, a.balance_nano as i128, Some(SUCCESS)))
        .collect::<Vec<_>>();
    let identifier = BlockIdentifier { index: 0, hash: header.hash.clone() };
    let transactions = if operations.is_empty() {
        Vec::new()
    } else {
        vec![Transaction {
            transaction_identifier: TransactionIdentifier { hash: genesis_id(&header.hash) },
            operations,
            metadata: None,
        }]
    };
    Block {
        block_identifier: identifier.clone(),
        parent_block_identifier: identifier,
        timestamp: header.timestamp,
        transactions,
    }
}

/// What a pending transaction will do, as far as it can be told before it runs: its fee, and for
/// a transfer the amount leaving and arriving. No status — nothing has happened yet.
pub fn pending(p: &node::Pending) -> Result<Transaction, MapError> {
    let fee = parse_u64(&p.fee_nano, "fee")? as i128;
    let amount = parse_u64(&p.amount_nano, "amount")? as i128;
    let mut ops = Vec::new();
    if fee > 0 {
        ops.push((FEE, p.from.as_str(), -fee));
    }
    if let (TxType::Transfer, Some(to)) = (&p.tx_type, &p.to) {
        if amount > 0 {
            ops.push((TRANSFER, p.from.as_str(), -amount));
            ops.push((TRANSFER, to.as_str(), amount));
        }
    }
    Ok(Transaction {
        transaction_identifier: TransactionIdentifier { hash: p.hash.clone() },
        operations: ops
            .into_iter()
            .enumerate()
            .map(|(i, (t, account, delta))| operation(i, t, account, delta, None))
            .collect(),
        metadata: Some(json!({ "tx_type": p.tx_type })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// `ALL_TX_TYPES` is checked against the variant count the enum's own `Deserialize` states,
    /// in order — not against a number kept by hand (the technique of #230).
    #[test]
    fn every_transaction_type_is_listed_once_in_declaration_order() {
        let mut declared = Vec::new();
        for index in 0u32.. {
            match bincode::deserialize::<TxType>(&index.to_le_bytes()) {
                Ok(variant) => declared.push(variant),
                Err(_) => break,
            }
        }
        assert_eq!(declared.len(), ALL_TX_TYPES.len(), "TxType has {} variants", declared.len());
        assert_eq!(declared, ALL_TX_TYPES.to_vec());
        let types = operation_types();
        let unique: std::collections::HashSet<_> = types.iter().collect();
        assert_eq!(unique.len(), types.len(), "operation types must be distinct: {types:?}");
    }

    fn change(tx_index: Option<u32>, account: &str, kind: &str, delta: i128) -> node::BalanceChange {
        node::BalanceChange {
            tx_index,
            account: account.into(),
            kind: kind.into(),
            delta_nano: delta.to_string(),
        }
    }

    fn tx(hash: &str, from: &str, to: &str, tx_type: TxType, amount: u64, fee: u64, status: &str) -> node::Tx {
        node::Tx {
            hash: hash.into(),
            from: from.into(),
            to: Some(to.into()),
            amount_nano: amount.to_string(),
            fee_nano: fee.to_string(),
            memo: None,
            tx_type,
            nonce: 0,
            status: status.into(),
            error: None,
        }
    }

    /// A block with an applied transfer, a failed one, a contract call that pays a third party,
    /// and the block reward — every change the node recorded, and nothing it did not.
    fn busy_block() -> node::Block {
        node::Block {
            hash: "b2".into(),
            height: 2,
            timestamp: 1_790_000_000_000,
            prev_hash: "b1".into(),
            transactions: vec![
                tx("t0", "alice", "bob", TxType::Transfer, 500, 20, "applied"),
                tx("t1", "alice", "bob", TxType::Transfer, 0, 20, "failed"),
                tx("t2", "carol", "contract", TxType::CallContract, 100, 30, "applied"),
            ],
            balance_changes: Some(vec![
                change(Some(0), "alice", "transaction", -520),
                change(Some(0), "bob", "transaction", 500),
                change(Some(0), "val", "reward", 7),
                change(Some(1), "alice", "transaction", -20),
                change(Some(1), "val", "reward", 5),
                change(Some(2), "carol", "transaction", -130),
                change(Some(2), "contract", "transaction", 100),
                change(Some(2), "contract", "contract", -40),
                change(Some(2), "dave", "contract", 40),
                change(Some(2), "val", "reward", 9),
                change(None, "val", "reward", 1_000_000_000),
            ]),
        }
    }

    fn net_by_account(ops: impl Iterator<Item = (String, i128)>) -> HashMap<String, i128> {
        let mut net = HashMap::new();
        for (account, delta) in ops {
            *net.entry(account).or_insert(0) += delta;
        }
        net
    }

    /// What Mesh reconciliation relies on: a block's operations, summed per account, are exactly
    /// the balance changes the node recorded.
    #[test]
    fn a_blocks_operations_add_up_to_its_balance_changes() {
        let node_block = busy_block();
        let block = block(&node_block).unwrap();
        let ops = block
            .transactions
            .iter()
            .flat_map(|t| &t.operations)
            .map(|o| (o.account.address.clone(), o.amount.value.parse::<i128>().unwrap()));
        let recorded = node_block
            .balance_changes
            .unwrap()
            .into_iter()
            .map(|c| (c.account, c.delta_nano.parse::<i128>().unwrap()));
        assert_eq!(net_by_account(ops), net_by_account(recorded));
        let all = operation_types();
        for op in block.transactions.iter().flat_map(|t| &t.operations) {
            assert!(all.contains(&op.op_type.as_str()), "{} is not announced", op.op_type);
            assert_eq!(op.status.as_deref(), Some(SUCCESS));
        }
    }

    #[test]
    fn the_fee_is_its_own_operation_and_the_rest_is_the_transactions() {
        let block = block(&busy_block()).unwrap();
        let summary = |i: usize| -> Vec<(String, String, String)> {
            block.transactions[i]
                .operations
                .iter()
                .map(|o| (o.op_type.clone(), o.account.address.clone(), o.amount.value.clone()))
                .collect()
        };
        let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
        assert_eq!(summary(0), vec![s(FEE, "alice", "-20"), s("TRANSFER", "alice", "-500"), s("TRANSFER", "bob", "500"), s(REWARD, "val", "7")]);
        assert_eq!(summary(1), vec![s(FEE, "alice", "-20"), s(REWARD, "val", "5")], "a failed transaction moved its fee only");
        assert_eq!(
            summary(2),
            vec![
                s(FEE, "carol", "-30"),
                s("CALL_CONTRACT", "carol", "-100"),
                s("CALL_CONTRACT", "contract", "100"),
                s(CONTRACT_TRANSFER, "contract", "-40"),
                s(CONTRACT_TRANSFER, "dave", "40"),
                s(REWARD, "val", "9"),
            ]
        );
        assert_eq!(block.transactions[3].transaction_identifier.hash, block_reward_id("b2"));
        assert_eq!(block.parent_block_identifier, BlockIdentifier { index: 1, hash: "b1".into() });
    }

    #[test]
    fn a_block_without_a_record_is_refused_not_shown_empty() {
        let mut b = busy_block();
        b.balance_changes = None;
        assert_eq!(block(&b), Err(MapError::NoRecord(2)));
    }

    /// The node's own answer, rendered by `helix-rpc` and read back through this crate's types —
    /// a field renamed on either side fails here.
    #[test]
    fn the_nodes_block_view_reads_as_this_services_block() {
        use helix_crypto::KeyPair;
        let kp = KeyPair::generate();
        let from = helix_crypto::Address::from_public_key(&kp.public);
        let to = helix_crypto::Address::from_public_key(&KeyPair::generate().public);
        let transfer = helix_core::Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: from.clone(),
            to: Some(to.clone()),
            amount: 5,
            fee: 3,
            nonce: 0,
            data: b"memo".to_vec(),
            crypto_version: kp.scheme,
            chain_id: helix_crypto::Hash::ZERO,
            signature: helix_crypto::Signature::from_bytes(vec![]),
            public_key: Some(kp.public.clone()),
        };
        let mut b = helix_core::genesis_block(from.clone(), kp.public.clone(), helix_crypto::Signature::from_bytes(vec![]), 0);
        b.header.height = 1;
        b.transactions = vec![transfer];
        let changes = vec![
            helix_executor::BalanceChange { tx_index: Some(0), account: from.to_string(), kind: helix_executor::BalanceChangeKind::Transaction, delta: -8 },
            helix_executor::BalanceChange { tx_index: Some(0), account: to.to_string(), kind: helix_executor::BalanceChangeKind::Transaction, delta: 5 },
        ];
        let view = helix_rpc::BlockResponse::new(&b, |_| ("applied".into(), None)).with_balance_changes(&b, Some(changes));
        let read: node::Block = serde_json::from_value(serde_json::to_value(&view).unwrap()).unwrap();
        let mapped = block(&read).unwrap();
        let ops: Vec<_> = mapped.transactions[0].operations.iter().map(|o| (o.op_type.as_str(), o.amount.value.as_str())).collect();
        assert_eq!(ops, vec![(FEE, "-3"), ("TRANSFER", "-5"), ("TRANSFER", "5")]);
        assert_eq!(read.transactions[0].memo.as_deref(), Some("memo"));
    }
}
