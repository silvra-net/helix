import { useMemo, useState } from "react";

// Shown once, right after a wallet is created. The words are never persisted — the user writes
// them down here or loses the only backup.
//
// A checkbox alone does not establish that anyone wrote anything down: it is one click away from
// "yes yes, continue", and the cost of that click only becomes visible months later when the
// phrase is needed and does not exist. So the confirmation is a short quiz on three of the words.
// This is the one screen in the wallet where friction is the feature — every hardware wallet
// does the same thing, for the same reason.
const CHECKS = 3;

export default function MnemonicReveal({ mnemonic, onDone }: { mnemonic: string; onDone: () => void }) {
  const words = useMemo(() => mnemonic.trim().split(/\s+/), [mnemonic]);
  const [stage, setStage] = useState<"show" | "verify">("show");
  const [answers, setAnswers] = useState<string[]>(Array(CHECKS).fill(""));
  const [wrong, setWrong] = useState(false);

  // Drawn once per wallet, spread across the list so a glance at the first line is not enough.
  const asked = useMemo(() => {
    const picked = new Set<number>();
    while (picked.size < Math.min(CHECKS, words.length)) {
      picked.add(Math.floor(Math.random() * words.length));
    }
    return [...picked].sort((a, b) => a - b);
  }, [words]);

  const check = () => {
    const ok = asked.every((idx, i) => answers[i].trim().toLowerCase() === words[idx].toLowerCase());
    if (ok) onDone();
    else setWrong(true);
  };

  if (stage === "verify") {
    return (
      <div className="onboarding">
        <div className="card onboard-card">
          <h1>Check your copy</h1>
          <p className="muted">
            Read these back from what you just wrote down — not from memory. If they don't match,
            go back and copy the phrase again; there is no second chance at this after you leave.
          </p>

          {asked.map((idx, i) => (
            <label className="field" key={idx}>
              <span>Word {idx + 1}</span>
              <input
                className="mono"
                value={answers[i]}
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="none"
                onChange={(e) => {
                  const next = [...answers];
                  next[i] = e.target.value;
                  setAnswers(next);
                  setWrong(false);
                }}
              />
            </label>
          ))}

          {wrong && (
            <div className="error">
              That does not match. Check your notes — the order matters as much as the words.
            </div>
          )}

          <div className="row-actions end">
            <button className="ghost" onClick={() => { setStage("show"); setWrong(false); }}>
              Show the phrase again
            </button>
            <button
              className="primary"
              disabled={answers.some((a) => a.trim() === "")}
              onClick={check}
            >
              Confirm
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="onboarding">
      <div className="card onboard-card">
        <h1>Write down your recovery phrase</h1>
        <p className="muted">
          These 24 words are your wallet. Anyone who reads them owns it, and this is the only time
          they are shown. Write them on paper — not a screenshot, not a file. Nobody, including
          us, can recover them for you.
        </p>

        <ol className="mnemonic-grid">
          {words.map((w, i) => (
            <li key={i}>
              <span className="idx">{i + 1}</span>
              <span className="word">{w}</span>
            </li>
          ))}
        </ol>

        <button className="primary" onClick={() => setStage("verify")}>
          I've written them down
        </button>
      </div>
    </div>
  );
}
