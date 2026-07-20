import { useState } from "react";
import { api } from "../api";
import type { SubmitResult } from "../types";
import { shortAddr } from "../format";

// Shared by Validate.tsx (stake/unstake/commission — actions on your own validator) and
// Earn.tsx (delegate/undelegate/redelegate — actions on someone else's). One panel because
// they're the same shape (amount + optional validator address + sign-and-submit), and a wallet
// should feel like one consistent way of doing a state-changing action, not six bespoke forms.
export type StakeAction =
  | { kind: "stake" }
  | { kind: "unstake" }
  | { kind: "delegate" }
  | { kind: "undelegate"; validator: string }
  | { kind: "redelegate"; validator: string }
  | { kind: "commission" };

export function StakeActionPanel({
  action,
  node,
  onCancel,
  onRun,
}: {
  action: StakeAction;
  node: string;
  onCancel: () => void;
  onRun: (fn: () => Promise<SubmitResult>) => void;
}) {
  const [amount, setAmount] = useState("");
  const [toValidator, setToValidator] = useState("");
  const [validator, setValidator] = useState("");
  const [percent, setPercent] = useState("");

  const amt = Number(amount);
  const amtValid = amount.trim() !== "" && Number.isFinite(amt) && amt > 0;

  const title: Record<StakeAction["kind"], string> = {
    stake: "Stake HLX",
    unstake: "Unstake HLX",
    delegate: "Delegate to a validator",
    undelegate: "Undelegate",
    redelegate: "Move delegation to another validator",
    commission: "Set commission",
  };

  let canSubmit = false;
  let submit: () => Promise<SubmitResult> = async () => ({ tx_hash: "", status: "" });

  switch (action.kind) {
    case "stake":
      canSubmit = amtValid;
      submit = () => api.stake(node, amt);
      break;
    case "unstake":
      canSubmit = amtValid;
      submit = () => api.unstake(node, amt);
      break;
    case "delegate":
      canSubmit = amtValid && validator.trim().startsWith("hlx");
      submit = () => api.delegate(node, validator.trim(), amt);
      break;
    case "undelegate":
      canSubmit = amtValid;
      submit = () => api.undelegate(node, action.validator, amt);
      break;
    case "redelegate":
      canSubmit = amtValid && toValidator.trim().startsWith("hlx");
      submit = () => api.redelegate(node, action.validator, toValidator.trim(), amt);
      break;
    case "commission": {
      const p = Number(percent);
      canSubmit = percent.trim() !== "" && Number.isFinite(p) && p >= 0 && p <= 50;
      submit = () => api.setCommission(node, Math.round(p * 100));
      break;
    }
  }

  return (
    <div className="card action-panel">
      <div className="section-title">{title[action.kind]}</div>

      {action.kind === "delegate" && (
        <label className="field">
          <span>Validator address</span>
          <input className="mono" value={validator} spellCheck={false} placeholder="hlx…" onChange={(e) => setValidator(e.target.value)} />
        </label>
      )}

      {(action.kind === "undelegate" || action.kind === "redelegate") && (
        <div className="kv"><span className="muted">From validator</span><span className="mono">{shortAddr(action.validator)}</span></div>
      )}

      {action.kind === "redelegate" && (
        <label className="field">
          <span>To validator</span>
          <input className="mono" value={toValidator} spellCheck={false} placeholder="hlx…" onChange={(e) => setToValidator(e.target.value)} />
        </label>
      )}

      {action.kind === "commission" ? (
        <label className="field">
          <span>Commission (%, max 50)</span>
          <input inputMode="decimal" value={percent} placeholder="10" onChange={(e) => setPercent(e.target.value)} />
        </label>
      ) : (
        <label className="field">
          <span>Amount (HLX)</span>
          <input inputMode="decimal" value={amount} placeholder="0.0" onChange={(e) => setAmount(e.target.value)} />
        </label>
      )}

      {action.kind === "redelegate" && (
        <p className="muted small">The moved stake keeps earning at the new validator immediately, but stays slashable for the one you left for 7 days.</p>
      )}

      <div className="row-actions end">
        <button className="ghost" onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={!canSubmit} onClick={() => onRun(submit)}>Sign and submit</button>
      </div>
    </div>
  );
}
