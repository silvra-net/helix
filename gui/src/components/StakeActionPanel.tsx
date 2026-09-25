import { useEffect, useState } from "react";
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
  | { kind: "commission" }
  // Where this validator's own share and commission go (#229). `current` is null while they go
  // to this wallet.
  | { kind: "rewardAddress"; current: string | null };

import { ValidatorPicker } from "./ValidatorPicker";

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
  const [payout, setPayout] = useState("");
  const [backToWallet, setBackToWallet] = useState(false);
  const [payoutValid, setPayoutValid] = useState<boolean | undefined>(undefined);

  // The payout address is checked as it is typed, checksum and all — a validator's income goes
  // wherever this says, and a character off is somebody else's address or nobody's. Debounced,
  // like the recipient in Send.
  const payoutTrimmed = payout.trim();
  useEffect(() => {
    if (action.kind !== "rewardAddress" || payoutTrimmed === "") {
      setPayoutValid(undefined);
      return;
    }
    let alive = true;
    const id = setTimeout(async () => {
      const ok = await api.isValidAddress(payoutTrimmed).catch(() => false);
      if (alive) setPayoutValid(ok);
    }, 250);
    return () => {
      alive = false;
      clearTimeout(id);
    };
  }, [action.kind, payoutTrimmed]);

  const amt = Number(amount);
  const amtValid = amount.trim() !== "" && Number.isFinite(amt) && amt > 0;

  const title: Record<StakeAction["kind"], string> = {
    stake: "Stake HLX",
    unstake: "Unstake HLX",
    delegate: "Delegate to a validator",
    undelegate: "Undelegate",
    redelegate: "Move delegation to another validator",
    commission: "Set commission",
    rewardAddress: "Where your rewards go",
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
    case "rewardAddress":
      canSubmit = backToWallet ? action.current != null : payoutValid === true;
      submit = () => api.setRewardAddress(node, backToWallet ? null : payoutTrimmed);
      break;
  }

  return (
    <div className="card action-panel">
      <div className="section-title">{title[action.kind]}</div>

      {action.kind === "delegate" && (
        <ValidatorPicker node={node} value={validator} onChange={setValidator} />
      )}

      {(action.kind === "undelegate" || action.kind === "redelegate") && (
        <div className="kv"><span className="muted">From validator</span><span className="mono">{shortAddr(action.validator)}</span></div>
      )}

      {action.kind === "redelegate" && (
        <ValidatorPicker
          node={node}
          value={toValidator}
          onChange={setToValidator}
          exclude={action.validator}
        />
      )}

      {action.kind === "rewardAddress" ? (
        <>
          <div className="kv">
            <span className="muted">Now paid to</span>
            <span className="mono" style={{ wordBreak: "break-all", textAlign: "right" }}>
              {action.current ?? "this wallet"}
            </span>
          </div>
          {action.current && (
            <label className="checkbox">
              <input type="checkbox" checked={backToWallet} onChange={(e) => setBackToWallet(e.target.checked)} />
              <span>Pay them to this wallet again</span>
            </label>
          )}
          {!backToWallet && (
            <label className="field">
              <span>Pay to address</span>
              <input className="mono" value={payout} placeholder="hlx…" onChange={(e) => setPayout(e.target.value)} />
            </label>
          )}
          {!backToWallet && payoutValid === false && (
            <p className="text-warn small">
              Not a valid Helix address — the checksum does not match, so a character is off.
              Names are not accepted here: this is where your income goes.
            </p>
          )}
          <p className="muted small">
            Your own share of the rewards and your commission go to this address — for example a
            wallet whose key never touches the machine that runs your node. Your delegators keep
            their share either way.
          </p>
        </>
      ) : action.kind === "commission" ? (
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

      {action.kind === "undelegate" && (
        <p className="muted small">Amount is the current HLX value to withdraw (your delegation plus whatever it has compounded). It enters a 7-day unbonding period before you can claim it — during that window it earns nothing and still shares the validator's slashing risk.</p>
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
