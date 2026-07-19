import { useCallback, useEffect, useState } from "react";
import { api, DEFAULT_NODE } from "./api";
import type { NetworkStatus, WalletMeta } from "./types";
import { shortAddr } from "./format";
import Setup from "./views/Setup";
import Unlock from "./views/Unlock";
import Overview from "./views/Overview";
import Send from "./views/Send";
import Receive from "./views/Receive";
import Staking from "./views/Staking";
import Names from "./views/Names";
import Recovery from "./views/Recovery";
import Governance from "./views/Governance";
import Settings from "./views/Settings";
import MnemonicReveal from "./views/MnemonicReveal";

type Route = "overview" | "send" | "receive" | "staking" | "names" | "recovery" | "governance" | "settings";

export default function App() {
  const [meta, setMeta] = useState<WalletMeta | null>(null);
  const [node, setNode] = useState<string>(localStorage.getItem("helix-node") || DEFAULT_NODE);
  const [route, setRoute] = useState<Route>("overview");
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

  // Poll network status while a wallet is open, so the header stays live.
  useEffect(() => {
    if (!meta?.unlocked) return;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api.getNetwork(node);
        if (alive) setNet(s);
      } catch {
        if (alive) setNet(null);
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [meta?.unlocked, node]);

  const onNodeChange = (v: string) => {
    setNode(v);
    localStorage.setItem("helix-node", v);
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
        <nav>
          <NavItem label="Overview" active={route === "overview"} onClick={() => setRoute("overview")} />
          <NavItem label="Send" active={route === "send"} onClick={() => setRoute("send")} />
          <NavItem label="Receive" active={route === "receive"} onClick={() => setRoute("receive")} />
          <NavItem label="Staking" active={route === "staking"} onClick={() => setRoute("staking")} />
          <NavItem label="Names" active={route === "names"} onClick={() => setRoute("names")} />
          <NavItem label="Recovery" active={route === "recovery"} onClick={() => setRoute("recovery")} />
          <NavItem label="Governance" active={route === "governance"} onClick={() => setRoute("governance")} />
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
                height {net.height.toLocaleString()} · base fee {net.base_fee_per_byte}
              </span>
            )}
          </div>
          <span className="testnet-badge" title="HLX on the public testnet is a valueless test token.">
            ⚠ Testnet · test token, no value
          </span>
        </header>

        <section className="view">
          {route === "overview" && <Overview node={node} onSend={() => setRoute("send")} onReceive={() => setRoute("receive")} />}
          {route === "send" && <Send node={node} baseFee={net?.base_fee_per_byte} onDone={() => setRoute("overview")} />}
          {route === "receive" && <Receive address={meta.address ?? ""} />}
          {route === "staking" && <Staking node={node} height={net?.height ?? 0} />}
          {route === "names" && <Names node={node} />}
          {route === "recovery" && <Recovery node={node} address={meta.address ?? ""} />}
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
