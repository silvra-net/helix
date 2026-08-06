import { useCallback, useEffect, useState } from "react";
import { api, DEFAULT_NODE, LOCAL_NODE, isLocalNode } from "./api";
import { nextNode } from "./nodeChoice";
import type { NetworkStatus, WalletMeta } from "./types";
import { shortAddr } from "./format";
import Setup from "./views/Setup";
import Unlock from "./views/Unlock";
import Overview from "./views/Overview";
import Send from "./views/Send";
import Receive from "./views/Receive";
import Validate from "./views/Validate";
import Earn from "./views/Earn";
import Identity from "./views/Identity";
import Governance from "./views/Governance";
import Settings from "./views/Settings";
import MnemonicReveal from "./views/MnemonicReveal";

// Send and Receive sit in the sidebar rather than only behind buttons on Home: they are the two
// things a holder does most, and burying the most common actions one level down to keep the nav
// "clean" reads as tidy and behaves as friction. Validate/Earn/Identity replace the old flat
// Node/Staking/Names/Recovery split; see each file's own doc comment for the grouping.
type Route = "home" | "send" | "receive" | "validate" | "earn" | "identity" | "governance" | "settings";

export default function App() {
  const [meta, setMeta] = useState<WalletMeta | null>(null);
  const [node, setNode] = useState<string>(localStorage.getItem("helix-node") || DEFAULT_NODE);
  const [route, setRoute] = useState<Route>("home");
  const [net, setNet] = useState<NetworkStatus | null>(null);
  const [newMnemonic, setNewMnemonic] = useState<string | null>(null);

  const refreshMeta = useCallback(async () => {
    try {
      setMeta(await api.walletStatus());
    } catch {
      setMeta({ exists: false, unlocked: false, encrypted: false, address: null });
    }
  }, []);

  useEffect(() => {
    refreshMeta();
  }, [refreshMeta]);

  // Use a node already running on this machine, unless the user has chosen one themselves.
  //
  // The wallet only ever switched to the local node when *it* started the bundled one (Validate).
  // A node started any other way — systemd, pm2, `helix start` in a terminal, or the bundled one
  // left running from a previous session — went unnoticed, and every balance was read off our
  // server anyway. Running your own node and still asking a stranger is the wrong way round.
  //
  // Deliberately not persisted: an address the user never typed must not outlive the node it
  // points at. Writing it to localStorage would turn a detection into a stated preference, and a
  // wallet that kept asking a stopped node forever would be worse than one that never looked.
  // Runs once, before the wallet is unlocked, so an existing node is already in use by the time
  // the first balance is drawn. The polling effect below applies the same rule from then on —
  // through `nextNode` in both places, so there is one definition of when the wallet switches
  // rather than two that can drift apart.
  useEffect(() => {
    if (localStorage.getItem("helix-node")) return; // they answered this already
    let alive = true;
    (async () => {
      let localIsUp = false;
      try {
        await api.getNetwork(LOCAL_NODE);
        localIsUp = true;
      } catch {
        // No node here — the public endpoint stays, which is what makes a fresh install work.
      }
      if (!alive) return;
      const target = nextNode({ current: node, stated: false, misses: 0, localIsUp });
      if (target) setNode(target);
    })();
    return () => {
      alive = false;
    };
  }, []);

  // Poll network status while a wallet is open, so the header stays live — and keep asking which
  // node we ought to be reading from, rather than deciding that once at startup.
  //
  // The startup probe above answers "is there a node right now?". It cannot answer "is there one
  // *yet*?", which is the ordinary case: people open the wallet and then start their node. Nor
  // can it notice a detected node going away, which left every screen erroring against an
  // endpoint that no longer existed. Both rules live in `nextNode`; this only supplies the facts.
  useEffect(() => {
    if (!meta?.unlocked) return;
    let alive = true;
    let misses = 0;

    const tick = async () => {
      let answered = true;
      try {
        const s = await api.getNetwork(node);
        if (!alive) return;
        setNet(s);
      } catch {
        if (!alive) return;
        setNet(null);
        answered = false;
      }
      misses = answered ? 0 : misses + 1;

      const stated = localStorage.getItem("helix-node") !== null;
      // Only probe when the answer could change something: on a stated preference nothing may
      // move, and while already reading from the local node there is nothing to discover.
      const shouldProbeLocal = !stated && !isLocalNode(node);
      let localIsUp = false;
      if (shouldProbeLocal) {
        try {
          await api.getNetwork(LOCAL_NODE);
          localIsUp = true;
        } catch {
          localIsUp = false;
        }
      }
      if (!alive) return;

      const target = nextNode({ current: node, stated, misses, localIsUp });
      if (target && target !== node) {
        // `false` — automatic housekeeping, never a stated preference. Persisting an address the
        // user never typed would outlive the node it points at and switch off detection for good.
        onNodeChange(target, false);
      }
    };

    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [meta?.unlocked, node]);

  /// Switch which node the wallet reads from.
  ///
  /// `persist` separates a *stated preference* from *housekeeping*. Typing an address in Settings
  /// is the user answering the question, and must survive a restart and suppress auto-detection.
  /// The Validate screen switching away from a node it just stopped is not an answer — persisting
  /// that would record "I want the public endpoint" and permanently disable detection of any node
  /// started later by other means, which is the very thing this is meant to notice.
  const onNodeChange = (v: string, persist = true) => {
    setNode(v);
    if (persist) localStorage.setItem("helix-node", v);
    else localStorage.removeItem("helix-node");
  };

  const lock = async () => {
    await api.lockWallet();
    setNet(null);
    refreshMeta();
  };

  if (!meta) return <div className="center muted">Loading…</div>;

  if (newMnemonic) {
    return (
      <MnemonicReveal
        mnemonic={newMnemonic}
        onDone={() => {
          setNewMnemonic(null);
          refreshMeta();
        }}
      />
    );
  }

  if (!meta.exists) {
    return (
      <Setup
        onCreated={(mnemonic) => setNewMnemonic(mnemonic)}
        onRestored={refreshMeta}
      />
    );
  }

  if (!meta.unlocked) {
    return <Unlock encrypted={meta.encrypted} onUnlocked={refreshMeta} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden>⛓</span>
          <span>Helix Wallet</span>
        </div>
        {/* Grouped by how often you actually need it, not by how the features were built.
            Send and Receive were previously reachable only as buttons inside Home, while
            Validate — which most holders never touch — sat second in the list. What someone
            does weekly belongs at the top; running a node belongs with the other operator
            tools at the bottom. */}
        <nav>
          <NavItem label="Overview" active={route === "home"} onClick={() => setRoute("home")} />
          <NavItem label="Send" active={route === "send"} onClick={() => setRoute("send")} />
          <NavItem label="Receive" active={route === "receive"} onClick={() => setRoute("receive")} />

          <div className="nav-group">Grow</div>
          <NavItem label="Earn" active={route === "earn"} onClick={() => setRoute("earn")} />
          <NavItem label="Identity" active={route === "identity"} onClick={() => setRoute("identity")} />
          <NavItem label="Governance" active={route === "governance"} onClick={() => setRoute("governance")} />

          <div className="nav-group">Run a node</div>
          <NavItem label="Validate" active={route === "validate"} onClick={() => setRoute("validate")} />
          <NavItem label="Settings" active={route === "settings"} onClick={() => setRoute("settings")} />
        </nav>
        <div className="sidebar-foot">
          <div className="key-note">Key stays in the app, never in the browser</div>
          <button className="ghost" onClick={lock}>Lock</button>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div className="net">
            <span className={`dot ${net ? "ok" : "off"}`} aria-hidden />
            <input
              className="node-input"
              value={node}
              spellCheck={false}
              onChange={(e) => onNodeChange(e.target.value)}
              aria-label="Node URL"
            />
            {net && (
              <span className="net-meta">
                {isLocalNode(node) && <span title="Reading from a node on this machine">your node · </span>}
                height {net.height.toLocaleString()} · base fee {net.base_fee_per_byte}
              </span>
            )}
          </div>
          <span className="testnet-badge" title="HLX on the public testnet is a valueless test token.">
            ⚠ Testnet · test token, no value
          </span>
        </header>

        {net?.is_syncing && (
          // Progress rather than a blackout. A wallet that shows a balance from thousands of
          // blocks ago with no indication is lying by omission — the number is real, it is just
          // not now. `sync_target_height` can be absent when no peer has announced a tip yet, in
          // which case the height alone still says more than silence.
          <div className="sync-banner" role="status">
            {typeof net.sync_target_height === "number" && net.sync_target_height > net.height
              ? `Your node is catching up — ${net.height.toLocaleString()} of ${net.sync_target_height.toLocaleString()} blocks (${((net.height / net.sync_target_height) * 100).toFixed(1)}%). Balances may be out of date.`
              : `Your node is catching up (at block ${net.height.toLocaleString()}). Balances may be out of date.`}
          </div>
        )}

        <section className="view">
          {route === "home" && <Overview node={node} height={net?.height} onSend={() => setRoute("send")} onReceive={() => setRoute("receive")} />}
          {route === "send" && <Send node={node} baseFee={net?.base_fee_per_byte} onDone={() => setRoute("home")} />}
          {route === "receive" && <Receive address={meta.address ?? ""} />}
          {route === "validate" && <Validate node={node} net={net} onNodeChange={onNodeChange} walletEncrypted={meta.encrypted} />}
          {route === "earn" && <Earn node={node} />}
          {route === "identity" && <Identity node={node} address={meta.address ?? ""} />}
          {route === "governance" && <Governance node={node} />}
          {route === "settings" && <Settings address={meta.address ?? ""} />}
        </section>

        <footer className="statusbar">
          <span>{shortAddr(meta.address)}</span>
          {net && <span className="muted">node v{net.version} · {net.peer_count} peers</span>}
        </footer>
      </main>
    </div>
  );
}

function NavItem({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      {label}
    </button>
  );
}
