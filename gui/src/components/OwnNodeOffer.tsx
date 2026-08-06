import { rememberNodeOfferAnswered } from "../nodePrompt";

/**
 * Offers to run a node, once, without getting in the way.
 *
 * Bitcoin Core has no equivalent because there the node *is* the application — you cannot use the
 * wallet without one. Ours reads from the public network by default so a fresh install works, and
 * the cost of that convenience is that nobody is ever asked. This asks, exactly once.
 *
 * It does not start the node itself. "Set it up" goes to Validate, which already has the
 * passphrase field, the start button, the log console and the sync progress — sending people there
 * gives them the controls and the feedback in one place, and keeps the node-launching sequence in
 * one file rather than two that drift.
 */
export default function OwnNodeOffer({
  onSetUp,
  onDismiss,
}: {
  onSetUp: () => void;
  onDismiss: () => void;
}) {
  const setUp = () => {
    rememberNodeOfferAnswered();
    onSetUp();
  };
  const decline = () => {
    // Declining records only that the question was asked. It must not touch the node preference:
    // someone who says "not now" and starts a node next week should still be picked up
    // automatically.
    rememberNodeOfferAnswered();
    onDismiss();
  };

  return (
    <div className="card own-node-offer">
      <div className="own-node-offer-text">
        <strong>Run your own node?</strong>
        <p className="muted">
          Right now this wallet reads balances and history from a public Helix server. That works,
          but it means trusting someone else's answer about your own money. Your own node checks
          every block itself.
        </p>
        <p className="muted">
          It downloads the chain's history once, which takes a few minutes and some disk space.
          While it catches up the wallet shows its data with a notice at the top, so you can see
          when figures may still be out of date.
        </p>
      </div>
      <div className="row-actions">
        <button className="primary" onClick={setUp}>
          Set up my node
        </button>
        <button className="ghost" onClick={decline}>
          Not now
        </button>
      </div>
      <p className="muted tiny">
        You can change this any time under Validate — and if you start a node yourself, the wallet
        will notice and use it.
      </p>
    </div>
  );
}
