import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { api } from "../api";
import { getThemePref, setThemePref, type ThemePref } from "../theme";
import { newPassphraseProblem } from "../passphraseChange";

// Settings: the deliberate backup path. A wallet created before you wrote the 24 words down would
// otherwise have no recovery — here you can re-reveal the phrase (re-authenticating with the
// passphrase), and read the address / public key you hand to guardians for social recovery.
export default function Settings({
  address,
  encrypted,
  onPassphraseChanged,
}: {
  address: string;
  encrypted: boolean;
  onPassphraseChanged: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  // The passphrase form (#226) — separate from the reveal field above, which asks for the
  // current passphrase for a different purpose.
  const [currentPass, setCurrentPass] = useState("");
  const [nextPass, setNextPass] = useState("");
  const [repeatPass, setRepeatPass] = useState("");
  const [passBusy, setPassBusy] = useState(false);
  const [passError, setPassError] = useState<string | null>(null);
  const [passDone, setPassDone] = useState<string | null>(null);
  const [words, setWords] = useState<string[] | null>(null);
  const [pubkey, setPubkey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [logDir, setLogDir] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemePref>(getThemePref());

  const chooseTheme = (pref: ThemePref) => {
    setThemePref(pref);
    setTheme(pref);
  };

  useEffect(() => {
    api.logDirPath().then(setLogDir).catch(() => setLogDir(null));
    // Read at runtime from the compiled binary (Tauri's own app-info API), not a string typed
    // into the UI somewhere — the number a bug report needs is the one this specific install was
    // actually built with, which is now synced from the workspace version at every build (see
    // gui/scripts/sync-version.mjs) instead of the three-file manual bump that used to drift.
    getVersion().then(setAppVersion).catch(() => setAppVersion(null));
  }, []);

  const reveal = async () => {
    setBusy(true);
    setError(null);
    try {
      const m = await api.revealMnemonic(passphrase);
      setWords(m.trim().split(/\s+/));
      setPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const passProblem = newPassphraseProblem(nextPass, repeatPass);

  const changePassphrase = async () => {
    setPassBusy(true);
    setPassError(null);
    setPassDone(null);
    try {
      await api.changePassphrase(currentPass, nextPass);
      setPassDone(
        encrypted
          ? "Passphrase changed. From now on only the new one opens this wallet."
          : "Passphrase set. From now on this wallet opens only with it."
      );
      onPassphraseChanged();
    } catch (e) {
      setPassError(String(e));
    } finally {
      // Never left in the fields, whatever happened.
      setCurrentPass("");
      setNextPass("");
      setRepeatPass("");
      setPassBusy(false);
    }
  };

  const showPubkey = async () => {
    setError(null);
    try {
      setPubkey(await api.myPublicKey());
    } catch (e) {
      setError(String(e));
    }
  };

  const copy = async (what: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(what);
      setTimeout(() => setCopied(null), 1200);
    } catch {
      // Clipboard access can be refused (permissions / insecure context) — the value stays on
      // screen to copy by hand, which matters most for the recovery phrase. Don't crash on it.
    }
  };

  return (
    <div className="stack">
      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="section-title">Recovery phrase</div>
        {words ? (
          <>
            <div className="warn-inline">
              Anyone who reads these 24 words owns this wallet. Reveal them only somewhere private.
            </div>
            <ol className="mnemonic-grid">
              {words.map((w, i) => (
                <li key={i}>
                  <span className="idx">{i + 1}</span>
                  <span className="word">{w}</span>
                </li>
              ))}
            </ol>
            <div className="row-actions end">
              <button className="ghost" onClick={() => setWords(null)}>Hide</button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small" style={{ marginTop: -4 }}>
              Re-show the 24-word phrase for this wallet — your only backup if you lose the device.
              Enter your passphrase to confirm (leave blank if you didn't set one).
            </p>
            <div className="row-actions" style={{ gap: 8 }}>
              <input
                type="password"
                className="node-input"
                style={{ width: 220 }}
                value={passphrase}
                placeholder="passphrase"
                onChange={(e) => setPassphrase(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !busy && reveal()}
              />
              <button className="primary" disabled={busy} onClick={reveal}>
                {busy ? "…" : "Reveal recovery phrase"}
              </button>
            </div>
          </>
        )}
      </div>

      <div className="card">
        <div className="section-title">Passphrase</div>
        {encrypted ? (
          <p className="muted small" style={{ marginTop: -4 }}>
            This wallet is protected by a passphrase and locks itself after 10 minutes without use.
          </p>
        ) : (
          <div className="warn-inline">
            This wallet has no passphrase. It still locks itself after 10 minutes without use, but
            unlocking it is a single click — anyone at this computer can send from it. Set a
            passphrase to make the lock mean something.
          </div>
        )}
        {passDone && <div className="notice">{passDone}</div>}
        {passError && <div className="error">{passError}</div>}
        {encrypted && (
          <label className="field">
            <span>Current passphrase</span>
            <input type="password" value={currentPass} onChange={(e) => setCurrentPass(e.target.value)} />
          </label>
        )}
        <label className="field">
          <span>New passphrase</span>
          <input type="password" value={nextPass} onChange={(e) => setNextPass(e.target.value)} />
        </label>
        <label className="field">
          <span>New passphrase, again</span>
          <input
            type="password"
            value={repeatPass}
            onChange={(e) => setRepeatPass(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !passBusy && passProblem == null && changePassphrase()}
          />
        </label>
        {nextPass !== "" && repeatPass !== "" && passProblem && (
          <p className="muted small">{passProblem}</p>
        )}
        <p className="muted small">
          A forgotten passphrase cannot be reset — only the 24-word phrase above brings the wallet
          back. Make sure you have it written down first.
        </p>
        <div className="row-actions end">
          <button className="primary" disabled={passBusy || passProblem != null} onClick={changePassphrase}>
            {passBusy ? "…" : encrypted ? "Change passphrase" : "Set passphrase"}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="section-title">Appearance</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          Follow the system setting, or lock the wallet to light or dark.
        </p>
        <div className="theme-choice">
          {(["system", "light", "dark"] as ThemePref[]).map((p) => (
            <button
              key={p}
              className={theme === p ? "theme-opt active" : "theme-opt"}
              onClick={() => chooseTheme(p)}
            >
              {p === "system" ? "System" : p === "light" ? "Light" : "Dark"}
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="section-title">Wallet identity</div>
        <div className="kv">
          <span className="muted">Address</span>
          <span className="mono" style={{ wordBreak: "break-all", textAlign: "right" }}>{address}</span>
        </div>
        <div className="row-actions end">
          <button onClick={() => copy("address", address)}>{copied === "address" ? "Copied" : "Copy address"}</button>
        </div>

        {pubkey ? (
          <>
            <div className="kv" style={{ marginTop: 10 }}>
              <span className="muted">Public key</span>
              <span className="mono small" style={{ wordBreak: "break-all", textAlign: "right", maxWidth: "70%" }}>{pubkey}</span>
            </div>
            <p className="muted small">Hand this to your guardians when recovering a lost account — it is the key they rotate the account to. Safe to share.</p>
            <div className="row-actions end">
              <button onClick={() => copy("pubkey", pubkey)}>{copied === "pubkey" ? "Copied" : "Copy public key"}</button>
            </div>
          </>
        ) : (
          <div className="row-actions" style={{ marginTop: 10 }}>
            <button onClick={showPubkey}>Show public key</button>
          </div>
        )}
      </div>

      <div className="card">
        <div className="section-title">Diagnostics</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          If something goes wrong, this file has the details — attach it when reporting a bug.
          It never contains your passphrase, mnemonic, or private key.
        </p>
        <div className="kv">
          <span className="muted">Wallet app version</span>
          <span className="mono">{appVersion ?? "…"}</span>
        </div>
        {logDir ? (
          <>
            <div className="kv">
              <span className="muted">Log folder</span>
              <span className="mono small" style={{ wordBreak: "break-all", textAlign: "right", maxWidth: "70%" }}>{logDir}</span>
            </div>
            <div className="row-actions end">
              <button onClick={() => copy("logdir", logDir)}>{copied === "logdir" ? "Copied" : "Copy path"}</button>
            </div>
          </>
        ) : (
          <p className="muted small">Log folder unavailable.</p>
        )}
      </div>
    </div>
  );
}
