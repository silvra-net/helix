//! A link that died on one side only, and a node that could not send a thing afterwards (#232).
//!
//! Measured on the production node on 2026-09-24: its only peer dropped at 02:01:18 and was back at
//! 02:01:27, and for the next hour every message it tried to publish — 778 proposals, 128 votes —
//! failed with `InsufficientPeers` while that peer stayed connected and its messages kept arriving.
//! The chain crawled at 20 blocks an hour, carried only by peers *pulling* this node's votes.
//!
//! The cause is two facts about `libp2p-gossipsub` (0.47, and unchanged in 0.51): a node sends its
//! topic subscriptions to a peer only on its *first* connection to that peer, and nothing in this
//! network notices a TCP connection whose other end has gone. So when one side loses a link the
//! other side still believes in, the side that lost it forgets the peer's subscriptions, redials,
//! and is — to the other side — only opening a *second* connection. The subscriptions never come
//! again, and a node that knows of no subscriber publishes to nobody.
//!
//! The relay in this test does to a link exactly what happened there: it closes it towards one node
//! and leaves it open and silent towards the other.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PCommand, P2PConfig, P2PEvent, P2PService};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex};

/// Ports per test — the two tests in this file run in parallel.
struct Ports {
    x: u16,
    y: u16,
    relay: u16,
}

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

/// `ping` is `(interval, timeout)`, in seconds instead of the production minutes so the tests do
/// not wait those out. The mechanism is the same: the second unanswered ping in a row closes the
/// connection.
fn config(port: u16, seeds: Vec<u16>, ping: (u64, u64)) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds
            .into_iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect(),
        enable_mdns: false,
        ping_interval: Duration::from_secs(ping.0),
        ping_timeout: Duration::from_secs(ping.1),
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

/// A TCP relay in front of `target`. `cut()` ends every link it is carrying at that moment in the
/// way a home router or a proxy does when it drops state: the dialing side's socket is closed —
/// that side sees the connection end — while the target's socket stays open and simply goes
/// quiet. Nothing is ever read from it or written to it again, so the target keeps believing in a
/// connection that leads nowhere. Links opened after a cut are relayed normally.
struct Relay {
    generation: watch::Sender<u64>,
}

impl Relay {
    async fn spawn(listen: u16, target: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", listen)).await.unwrap();
        let (generation, _) = watch::channel(0u64);
        let generations = generation.clone();
        // The target-side sockets of cut links. Held, never touched: dropping them would close
        // them, and a closed socket is exactly what the far end must *not* see.
        let silent: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let Ok(upstream) = TcpStream::connect(("127.0.0.1", target)).await else {
                    continue;
                };
                let mut cut = generations.subscribe();
                let born = *cut.borrow_and_update();
                let silent = silent.clone();
                tokio::spawn(async move {
                    let (mut client, mut upstream) = (client, upstream);
                    let (mut up_buf, mut down_buf) = (vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]);
                    loop {
                        tokio::select! {
                            n = client.read(&mut up_buf) => match n {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if upstream.write_all(&up_buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            },
                            n = upstream.read(&mut down_buf) => match n {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if client.write_all(&down_buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            },
                            changed = cut.changed() => {
                                if changed.is_err() { return }
                                if *cut.borrow() > born {
                                    drop(client);
                                    silent.lock().await.push(upstream);
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        Relay { generation }
    }

    fn cut(&self) {
        self.generation.send_modify(|g| *g += 1);
    }
}

/// Publish a fresh vote from X every `every` until Y has received one of them, or give up at
/// `within`. Fresh each time: gossipsub refuses to publish bytes it has published before, so
/// repeating one vote would test that cache instead of the link.
async fn x_reaches_y(
    x_commands: &mpsc::Sender<P2PCommand>,
    y_votes: &mut mpsc::UnboundedReceiver<u64>,
    first_height: u64,
    every: Duration,
    within: Duration,
) -> Option<Duration> {
    let started = tokio::time::Instant::now();
    let mut height = first_height;
    while started.elapsed() < within {
        x_commands
            .send(P2PCommand::BroadcastVote(a_vote(height)))
            .await
            .unwrap();
        height += 1;
        let wait_until = tokio::time::Instant::now() + every;
        while let Ok(Some(h)) = tokio::time::timeout_at(wait_until, y_votes.recv()).await {
            if h >= first_height {
                return Some(started.elapsed());
            }
        }
    }
    None
}

/// X and Y connected through a relay; the relay drops the link on X's side only; X redials. Returns
/// how long after the cut X reached Y again, or panics after 180s saying whether X had at least
/// reconnected — not reconnecting at all is a different bug from reconnecting and reaching nobody.
///
/// `y_ping` decides the race the two halves of the fix exist for: whether Y gives up its dead half
/// before X's redial arrives (a fast ping), or only after (the production case — V1 redialed nine
/// seconds after losing the link; a ping at production settings takes minutes to condemn one).
///
/// `x_links_per_peer` is how many connections X may hold to Y. With two, X's startup redial opens
/// a second one, both die in the cut, and Y — holding two dead halves, its per-peer limit — turns
/// X's redials away until its ping has closed them, so X comes back as a *first* connection
/// whatever else happens. With one, Y holds a single dead half and admits the redial beside it,
/// which is what the production node's reconnect at 02:01:27 shows: it was let in at once.
async fn x_reaches_y_again_after_a_one_sided_cut(
    ports: Ports,
    y_ping: (u64, u64),
    x_links_per_peer: u32,
) -> Duration {
    let (_y_commands, mut y_events) = spawn(config(ports.y, vec![], y_ping));
    let relay = Relay::spawn(ports.relay, ports.y).await;
    let (x_commands, mut x_events) = spawn(P2PConfig {
        max_established_per_peer: x_links_per_peer,
        ..config(ports.x, vec![ports.relay], (1, 2))
    });

    // Y's event loop must be drained or its swarm blocks on a full channel; the votes it hears are
    // what this test is about.
    let (vote_tx, mut y_votes) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = y_events.recv().await {
            if let P2PEvent::NewVote(vote) = event {
                let _ = vote_tx.send(vote.height);
            }
        }
    });
    let (x_link_tx, mut x_link) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = x_events.recv().await {
            match event {
                P2PEvent::PeerConnected(_) => {
                    let _ = x_link_tx.send(true);
                }
                P2PEvent::PeerDisconnected(_) => {
                    let _ = x_link_tx.send(false);
                }
                _ => {}
            }
        }
    });

    // Positive control: the link works before it is cut, so a failure below is about the cut and
    // not about a relay or a mesh that never carried anything.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(20), x_link.recv())
            .await
            .ok()
            .flatten(),
        Some(true),
        "X never connected to Y through the relay"
    );
    let before = x_reaches_y(
        &x_commands,
        &mut y_votes,
        1,
        Duration::from_secs(1),
        Duration::from_secs(20),
    )
    .await;
    assert!(
        before.is_some(),
        "X could not reach Y even before the link was cut"
    );

    relay.cut();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(20), x_link.recv())
            .await
            .ok()
            .flatten(),
        Some(false),
        "X did not notice its side of the link closing"
    );

    match x_reaches_y(
        &x_commands,
        &mut y_votes,
        1_000,
        Duration::from_secs(2),
        Duration::from_secs(180),
    )
    .await
    {
        Some(took) => {
            println!(
                "X reached Y again {:.1}s after its side of the link closed",
                took.as_secs_f64()
            );
            took
        }
        None => {
            let mut reconnected = false;
            while let Ok(up) = x_link.try_recv() {
                reconnected |= up;
            }
            panic!(
                "X never reached Y again in 180s after the link died on X's side only \
                 (X reconnected since: {reconnected}) — X redials, but to Y that is a second \
                 connection, Y never re-sends its subscriptions over it, and X publishes to nobody \
                 (#232)"
            )
        }
    }
}

/// Y's ping condemns its dead half within seconds, before X's redial (every 30s) arrives — so the
/// redial is Y's first connection again and brings the subscriptions with it. This is the half of
/// the fix that `ping` carries: without it Y keeps the dead half for as long as it pleases, which
/// on the production node was close to an hour.
#[tokio::test]
async fn a_node_can_publish_again_once_its_peer_has_given_up_the_dead_half() {
    x_reaches_y_again_after_a_one_sided_cut(
        Ports {
            x: 19781,
            y: 19782,
            relay: 19783,
        },
        (1, 2),
        2,
    )
    .await;
}

/// The production order of events: X redials *before* Y has given up its dead half (here Y's ping
/// needs about a minute, X redials within 30s), and Y holds only that one dead half, so it admits
/// the redial beside it. The redial is Y's second connection and brings no subscriptions; Y's ping
/// later closes the dead half, which leaves Y with one working connection and still no reason to
/// send them. Only X can notice — connected, and not one topic known for the peer — and drop it so
/// the next redial finds Y with no connection at all.
///
/// Before #232 this was the state the production node sat in from 02:01 to 02:59 on 2026-09-24.
#[tokio::test]
async fn a_node_can_publish_again_when_its_redial_beat_the_peers_ping() {
    x_reaches_y_again_after_a_one_sided_cut(
        Ports {
            x: 19784,
            y: 19785,
            relay: 19786,
        },
        (10, 20),
        1,
    )
    .await;
}
