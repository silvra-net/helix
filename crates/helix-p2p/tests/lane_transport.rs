//! A vote must not wait behind a flood of transactions (#224).
//!
//! gossipsub keeps one unprioritised send queue per instance and connection. With transactions and
//! votes on the same instance, a vote published after a burst of transactions waited for all of
//! them to go out first — on the flood test's 890 KB/s links that stretched the block time from
//! under a second to seven. Transactions now travel on a gossipsub instance of their own
//! (`TRANSACTION_GOSSIP_PROTOCOL`), and this test measures what that buys on a slow link: the
//! vote has to arrive while the transactions sent before it are still coming in.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PCommand, P2PConfig, P2PEvent, P2PService};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

const X_PORT: u16 = 19791;
const Y_PORT: u16 = 19792;
const RELAY_PORT: u16 = 19793;

/// Bytes per second the relay lets through in each direction — slower than production's tunnel
/// (226 KB/s), so the backlog is unmistakable.
const LINK_BYTES_PER_SEC: u64 = 200_000;

/// The burst sent ahead of the vote: 60 transactions of ~20 KB, about six seconds of this link.
const BURST: u64 = 60;
const TX_PAYLOAD: usize = 20_000;

struct NoBlocks;

impl BlockProvider for NoBlocks {
    fn blocks<'a>(
        &'a self,
        _from_height: u64,
        _count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async { BlockSyncResponse::empty() })
    }
}

fn config(port: u16, seeds: Vec<u16>) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds
            .into_iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect(),
        enable_mdns: false,
        ..P2PConfig::default()
    }
}

fn spawn(cfg: P2PConfig) -> (mpsc::Sender<P2PCommand>, mpsc::Receiver<P2PEvent>) {
    let (service, commands, events) =
        P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    tokio::spawn(async move { service.run().await });
    (commands, events)
}

fn a_vote(height: u64) -> helix_consensus::Vote {
    use helix_crypto::{Address, Hash, PublicKey, Signature};
    let pk = PublicKey::from_bytes(vec![7; 32]);
    helix_consensus::Vote {
        vote_type: helix_consensus::VoteType::Prevote,
        height,
        round: 0,
        block_hash: Hash::digest(b"a block"),
        validator: Address::from_public_key(&pk),
        public_key: pk,
        crypto_version: helix_core::CryptoVersion::MlDsa,
        signature: Signature::from_bytes(vec![1; 32]),
    }
}

/// A transaction the size of a real one with a contract payload. Distinct per nonce, because
/// gossipsub will not publish the same bytes twice.
fn a_transaction(nonce: u64, payload: usize) -> helix_core::Transaction {
    use helix_crypto::{Address, CryptoScheme, Hash, PublicKey, Signature};
    helix_core::Transaction {
        version: 1,
        tx_type: helix_core::TxType::Transfer,
        from: Address::from_public_key(&PublicKey::from_bytes(vec![7; 32])),
        to: None,
        amount: 1,
        fee: 1,
        nonce,
        data: vec![0xab; payload],
        crypto_version: CryptoScheme::MlDsa,
        chain_id: Hash::digest(b"canary"),
        signature: Signature::from_bytes(vec![]),
        public_key: PublicKey::from_bytes(vec![7; 32]),
    }
}

/// A TCP relay in front of `target` that paces each direction to `bytes_per_sec` — a slow link,
/// where what is sent first arrives first and everything else waits.
async fn spawn_paced_relay(listen: u16, target: u16, bytes_per_sec: u64) {
    let listener = TcpListener::bind(("127.0.0.1", listen)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(upstream) = TcpStream::connect(("127.0.0.1", target)).await else {
                continue;
            };
            let (client_read, client_write) = client.into_split();
            let (upstream_read, upstream_write) = upstream.into_split();
            tokio::spawn(pump(client_read, upstream_write, bytes_per_sec));
            tokio::spawn(pump(upstream_read, client_write, bytes_per_sec));
        }
    });
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    bytes_per_sec: u64,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_micros(n as u64 * 1_000_000 / bytes_per_sec)).await;
    }
}

enum Arrival {
    Vote(u64),
    Transaction(u64),
}

#[tokio::test]
async fn a_vote_is_not_held_up_by_a_backlog_of_transactions() {
    let (_y_commands, mut y_events) = spawn(config(Y_PORT, vec![]));
    spawn_paced_relay(RELAY_PORT, Y_PORT, LINK_BYTES_PER_SEC).await;
    let (x_commands, mut x_events) = spawn(config(X_PORT, vec![RELAY_PORT]));

    // What reaches Y, and when. Tickets are dropped at once: this test is about arrival, and a
    // dropped ticket answers for itself without holding anything up.
    let (arrival_tx, mut arrivals) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = y_events.recv().await {
            let seen = match event {
                P2PEvent::NewVote(vote) => Arrival::Vote(vote.height),
                P2PEvent::NewTransaction(tx, _ticket) => Arrival::Transaction(tx.nonce),
                _ => continue,
            };
            let _ = arrival_tx.send((Instant::now(), seen));
        }
    });
    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(event) = x_events.recv().await {
            if matches!(event, P2PEvent::PeerConnected(_)) {
                return;
            }
        }
    })
    .await;
    assert!(
        connected.is_ok(),
        "X never connected to Y through the relay"
    );
    tokio::spawn(async move { while x_events.recv().await.is_some() {} });

    // Both lanes must be carrying before the measurement: probe each until Y hears it.
    let mut probe = 0u64;
    let (mut vote_lane, mut tx_lane) = (false, false);
    let ready_by = Instant::now() + Duration::from_secs(30);
    while !(vote_lane && tx_lane) {
        assert!(
            Instant::now() < ready_by,
            "a lane never carried a probe (votes {vote_lane}, transactions {tx_lane})"
        );
        probe += 1;
        if !vote_lane {
            x_commands
                .send(P2PCommand::BroadcastVote(a_vote(probe)))
                .await
                .unwrap();
        }
        if !tx_lane {
            x_commands
                .send(P2PCommand::BroadcastTransaction(a_transaction(probe, 16)))
                .await
                .unwrap();
        }
        let until = Instant::now() + Duration::from_secs(1);
        while let Ok(Some((_, seen))) = tokio::time::timeout_at(until, arrivals.recv()).await {
            match seen {
                Arrival::Vote(_) => vote_lane = true,
                Arrival::Transaction(_) => tx_lane = true,
            }
        }
    }
    // Let the probes drain before the burst.
    tokio::time::sleep(Duration::from_secs(2)).await;
    while arrivals.try_recv().is_ok() {}

    // The burst, then the vote, as fast as the commands go in.
    let sent = Instant::now();
    for i in 0..BURST {
        x_commands
            .send(P2PCommand::BroadcastTransaction(a_transaction(
                1_000 + i,
                TX_PAYLOAD,
            )))
            .await
            .unwrap();
    }
    const MEASURED: u64 = 5_000;
    x_commands
        .send(P2PCommand::BroadcastVote(a_vote(MEASURED)))
        .await
        .unwrap();

    let (mut vote_at, mut last_tx_at, mut txs) = (None, None, 0u64);
    let give_up = sent + Duration::from_secs(30);
    while let Ok(Some((at, seen))) = tokio::time::timeout_at(give_up, arrivals.recv()).await {
        match seen {
            Arrival::Vote(MEASURED) => vote_at = Some(at - sent),
            Arrival::Transaction(nonce) if nonce >= 1_000 => {
                txs += 1;
                last_tx_at = Some(at - sent);
            }
            _ => {}
        }
        if vote_at.is_some() && last_tx_at.is_some_and(|t| t > Duration::from_secs(8)) {
            break;
        }
    }

    let vote_at = vote_at.expect("the vote never arrived");
    let last_tx_at = last_tx_at.expect("none of the burst arrived");
    println!(
        "vote after {:.2}s · {txs} of {BURST} transactions, the last after {:.2}s",
        vote_at.as_secs_f64(),
        last_tx_at.as_secs_f64()
    );
    // Positive control: the backlog was real — the transactions sent before the vote were still
    // arriving seconds later. Without this the assertion below would pass on an idle link.
    assert!(
        last_tx_at >= Duration::from_secs(3),
        "the burst drained in {:.2}s — there was no backlog to jump",
        last_tx_at.as_secs_f64()
    );
    assert!(
        vote_at + Duration::from_secs(2) <= last_tx_at,
        "the vote arrived after {:.2}s, while the transactions sent before it were done after \
         {:.2}s: it waited behind them (#224)",
        vote_at.as_secs_f64(),
        last_tx_at.as_secs_f64()
    );
}
