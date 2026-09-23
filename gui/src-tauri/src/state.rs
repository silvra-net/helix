use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use helix_crypto::KeyPair;

/// How long an unlocked wallet waits for anyone to use it before it locks itself: 10 minutes.
///
/// Long enough that nothing a person does *at* the wallet trips it — composing a send, copying an
/// address, reading history all produce input, and a single keystroke or mouse movement restarts
/// the count. Short enough to be over before a lunch break or a meeting, which is the case it
/// exists for: a machine left on a desk with the wallet open, where anyone passing can press Send.
/// It is also the order of the screen-lock defaults people already live with, so it neither
/// surprises nor nags. Waiting without touching anything (watching a node sync on Validate) is
/// the one honest use it cuts short; unlocking again costs a passphrase, a lost wallet costs
/// everything in it.
pub const IDLE_LOCK_AFTER: Duration = Duration::from_secs(10 * 60);

/// How often the backend checks whether the wallet has been idle long enough to lock. A mutex
/// and a clock read — cheap enough to do often, so the lock lands within seconds of the limit.
pub const IDLE_SWEEP_EVERY: Duration = Duration::from_secs(5);

/// The event the frontend listens for to leave the unlocked screens when the backend locked by
/// itself. Payload: `IDLE_LOCK_AFTER` in minutes, for the notice on the unlock screen.
pub const WALLET_LOCKED_EVENT: &str = "wallet-locked";

/// What a refused signature says when the wallet had already sat idle past `IDLE_LOCK_AFTER`.
pub const LOCKED_FOR_INACTIVITY: &str =
    "the wallet locked itself after 10 minutes without use — unlock it again to continue";

/// A point in time, read from two clocks — see [`Moment::since`] for why one is not enough.
#[derive(Clone, Copy, Debug)]
pub struct Moment {
    monotonic: Instant,
    wall: SystemTime,
}

impl Moment {
    pub fn now() -> Self {
        Moment {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// How long ago `earlier` was: the longer of what the two clocks say.
    ///
    /// The monotonic clock does not advance while the machine sleeps (`Instant` is
    /// `CLOCK_MONOTONIC` on Linux and `CLOCK_UPTIME_RAW` on macOS). Measured on it alone, a laptop
    /// closed with the wallet open would wake the next morning still unlocked — and closing the
    /// lid is exactly how people walk away from a laptop. The wall clock counts the sleep. It can
    /// also be set backwards; then `duration_since` fails, the monotonic answer stands, and moving
    /// the clock back can never stretch an unlock beyond the time that really passed.
    pub fn since(&self, earlier: &Moment) -> Duration {
        let monotonic = self.monotonic.saturating_duration_since(earlier.monotonic);
        let wall = self
            .wall
            .duration_since(earlier.wall)
            .unwrap_or(Duration::ZERO);
        monotonic.max(wall)
    }

    #[cfg(test)]
    fn later(&self, monotonic: Duration, wall: Duration) -> Self {
        Moment {
            monotonic: self.monotonic + monotonic,
            wall: self.wall + wall,
        }
    }

    #[cfg(test)]
    fn with_wall_set_back(&self, monotonic: Duration, wall_back: Duration) -> Self {
        Moment {
            monotonic: self.monotonic + monotonic,
            wall: self.wall - wall_back,
        }
    }
}

/// The unlocked wallet, held **only** in the Rust backend.
///
/// The `KeyPair` carries the secret seed. It is never serialized to the webview: every command
/// hands the frontend addresses, amounts and statuses — never key bytes. The passphrase the
/// user types to unlock is a transient input that decrypts the on-disk `KeyFile` in memory here
/// and is then dropped; it is not stored. This is the entire reason the GUI is a Tauri app and
/// not a page served by the node (where signing would have to happen in the browser).
pub struct UnlockedWallet {
    pub keypair: KeyPair,
    pub address: String,
    last_activity: Moment,
}

impl UnlockedWallet {
    /// A wallet unlocked just now — which is itself activity.
    pub fn new(keypair: KeyPair, address: String) -> Self {
        UnlockedWallet {
            keypair,
            address,
            last_activity: Moment::now(),
        }
    }
}

/// The wallet, and when it may lock itself.
///
/// **The backend enforces the idle lock; the frontend only reports that someone is there**
/// (`touch`). A timer in the webview would depend on JavaScript timers the operating system may
/// throttle or suspend for a window in the background — then the key would stay in memory with
/// nothing counting. Here a thread started at launch sweeps every few seconds (`lock_if_idle`),
/// and every signature checks the deadline itself (`begin_signing`), so an idle wallet signs
/// nothing even in the seconds before the sweep reaches it.
///
/// **A transaction in flight never has its outcome hidden** by the lock, and not because anything
/// holds the lock off: the start and the end of every send count as activity (`begin_signing`,
/// `SigningGuard`), so the sweep cannot fire until ten minutes after the person saw the result.
/// Locking mid-send would not stop the transaction — it is past the key — but it would hide
/// "sent", and a person who never saw it sends again, with a fresh nonce, and pays twice. The one
/// send the lock can overtake is one that has been in flight for ten minutes: that is a hung
/// connection (the RPC client has no timeout), and keeping the key in memory for as long as a
/// dead socket stays open would be the worse trade.
pub struct WalletState {
    pub inner: Mutex<Option<UnlockedWallet>>,
    /// `Moment::now` in the app. A parameter so tests can move time — including for the `Drop`
    /// of a `SigningGuard`, which a test using the real clock cannot observe.
    clock: Box<dyn Fn() -> Moment + Send + Sync>,
}

impl Default for WalletState {
    fn default() -> Self {
        WalletState {
            inner: Mutex::new(None),
            clock: Box::new(Moment::now),
        }
    }
}

impl WalletState {
    /// Address of the currently-unlocked wallet, if any. Cloned out under a short lock so
    /// callers never hold the guard across an `.await`.
    pub fn address(&self) -> Option<String> {
        self.inner.lock().unwrap().as_ref().map(|w| w.address.clone())
    }

    /// Somebody used the wallet. Nothing happens if it is locked — reporting activity must never
    /// be a way to keep, or bring back, a key.
    pub fn touch(&self) {
        let now = (self.clock)();
        if let Some(wallet) = self.inner.lock().unwrap().as_mut() {
            wallet.last_activity = now;
        }
    }

    /// Lock the wallet if nobody has used it for `IDLE_LOCK_AFTER`. Returns whether it locked, so
    /// the caller can tell the frontend.
    pub fn lock_if_idle(&self) -> bool {
        let now = (self.clock)();
        let mut guard = self.inner.lock().unwrap();
        let idle = match guard.as_ref() {
            Some(wallet) => now.since(&wallet.last_activity) >= IDLE_LOCK_AFTER,
            None => return false,
        };
        if idle {
            *guard = None; // the `KeyPair`'s secret zeroizes on drop
        }
        idle
    }

    /// Take the key to sign a transaction, for as long as the returned guard lives.
    ///
    /// Refuses if the wallet has already been idle past the limit: whoever clicks Send on a
    /// wallet nobody touched for ten minutes is not presumed to be its owner, even in the seconds
    /// before the sweep locks it. It refuses without locking, so that locking for inactivity has
    /// exactly one author — the sweep, which also tells the frontend; a lock taken here would
    /// leave the screens showing an open wallet on which every action fails. Otherwise counts as
    /// activity now, and again when the guard drops — so the person who sent gets the full ten
    /// minutes to read the result (see the note on `WalletState`).
    pub fn begin_signing(&self) -> Result<SigningGuard<'_>, String> {
        let now = (self.clock)();
        let mut guard = self.inner.lock().unwrap();
        let wallet = guard.as_mut().ok_or("wallet is locked")?;
        if now.since(&wallet.last_activity) >= IDLE_LOCK_AFTER {
            return Err(LOCKED_FOR_INACTIVITY.into());
        }
        wallet.last_activity = now;
        Ok(SigningGuard { state: self })
    }
}

/// Lives for as long as a transaction is being signed and submitted; its end counts as activity,
/// so the result the person is waiting for arrives with the full idle window ahead of it.
pub struct SigningGuard<'a> {
    state: &'a WalletState,
}

impl Drop for SigningGuard<'_> {
    fn drop(&mut self) {
        self.state.touch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const MINUTE: Duration = Duration::from_secs(60);

    /// A wallet unlocked at `start`, and a hand on its clock.
    struct Scene {
        state: WalletState,
        start: Moment,
        now: Arc<Mutex<Moment>>,
    }

    impl Scene {
        fn new() -> Self {
            let start = Moment::now();
            let now = Arc::new(Mutex::new(start));
            let clock = now.clone();
            let state = WalletState {
                inner: Mutex::new(None),
                clock: Box::new(move || *clock.lock().unwrap()),
            };
            let mut wallet = UnlockedWallet::new(KeyPair::generate(), "hlxTest".into());
            wallet.last_activity = start;
            *state.inner.lock().unwrap() = Some(wallet);
            Scene { state, start, now }
        }

        /// Both clocks moved forward by `minutes`.
        fn at_minute(&self, minutes: u32) {
            *self.now.lock().unwrap() = self.start.later(minutes * MINUTE, minutes * MINUTE);
        }

        fn set(&self, moment: Moment) {
            *self.now.lock().unwrap() = moment;
        }

        fn is_unlocked(&self) -> bool {
            self.state.inner.lock().unwrap().is_some()
        }

        /// A lock is two claims — the sweep says it locked, and the key is gone. A test that
        /// believed the first alone stayed green while nothing was cleared (red run R1).
        fn assert_locks(&self, why: &str) {
            assert!(self.state.lock_if_idle(), "{why}: the sweep did not lock");
            assert!(
                !self.is_unlocked(),
                "{why}: the sweep said it locked but the key is still held"
            );
        }

        fn assert_stays_open(&self, why: &str) {
            assert!(!self.state.lock_if_idle(), "{why}: the sweep locked");
            assert!(self.is_unlocked(), "{why}: the key is gone");
        }
    }

    #[test]
    fn a_wallet_left_alone_past_the_limit_is_actually_cleared() {
        let scene = Scene::new();
        scene.at_minute(9);
        scene.assert_stays_open("nine minutes is not ten");
        scene.at_minute(10);
        scene.assert_locks("ten minutes untouched");
        // Not hidden — gone: the backend holds no key, whatever the frontend shows.
        assert_eq!(
            scene.state.begin_signing().err().as_deref(),
            Some("wallet is locked")
        );
    }

    #[test]
    fn activity_restarts_the_count() {
        let scene = Scene::new();
        scene.at_minute(8);
        scene.state.touch();
        scene.at_minute(12);
        scene.assert_stays_open("four minutes since the last input");
        scene.at_minute(18);
        scene.assert_locks("ten minutes since the last input");
    }

    /// The laptop lid. The monotonic clock stands still while the machine sleeps; a night asleep
    /// looks like a minute to it. The wall clock saw the night.
    #[test]
    fn a_machine_that_slept_through_the_limit_wakes_locked() {
        let scene = Scene::new();
        scene.set(scene.start.later(MINUTE, 8 * 60 * MINUTE));
        scene.assert_locks("asleep all night");
    }

    /// And the wall clock cannot stretch an unlock: set it back and the monotonic clock still
    /// counts the real time.
    #[test]
    fn setting_the_clock_back_does_not_keep_the_wallet_open() {
        let scene = Scene::new();
        scene.set(scene.start.with_wall_set_back(11 * MINUTE, 60 * MINUTE));
        scene.assert_locks("eleven real minutes, wall clock set back an hour");
    }

    /// The case the task named: a send in progress when the idle limit would pass. Its start
    /// counts as activity, so no sweep can hide its outcome; and its end counts again, so the
    /// result gets the full window. Nine idle minutes, a send that takes until minute eighteen,
    /// and the person reading its result at minute twenty-seven is still looking at it.
    #[test]
    fn a_send_counts_as_activity_when_it_starts_and_when_it_ends() {
        let scene = Scene::new();
        scene.at_minute(9);
        let sending = scene.state.begin_signing().unwrap();
        scene.at_minute(15);
        scene.assert_stays_open("six minutes into a send");

        scene.at_minute(18);
        drop(sending); // the result reaches the person now
        scene.at_minute(27);
        scene.assert_stays_open("nine minutes after the result arrived");
        scene.at_minute(28);
        scene.assert_locks("ten minutes after the result arrived");
    }

    /// The one send the lock may overtake: one in flight for ten minutes is a connection that
    /// hung (the RPC client has no timeout). Nothing holds the key for as long as a dead socket.
    #[test]
    fn a_send_that_hangs_does_not_keep_the_key_in_memory() {
        let scene = Scene::new();
        let _hung = scene.state.begin_signing().unwrap();
        scene.at_minute(10);
        scene.assert_locks("a send ten minutes in flight");
    }

    /// Whoever clicks Send on a wallet nobody touched for ten minutes is not presumed to be its
    /// owner — even in the seconds before the sweep locks it. The refusal does not count as
    /// activity, so the sweep still finds the wallet idle, locks it, and tells the frontend.
    #[test]
    fn a_signature_asked_for_after_the_limit_is_refused_and_the_sweep_still_locks() {
        let scene = Scene::new();
        scene.at_minute(11);
        assert_eq!(
            scene.state.begin_signing().err().as_deref(),
            Some(LOCKED_FOR_INACTIVITY)
        );
        scene.assert_locks("the refused attempt must not reset the count");
    }

    /// Both names live twice — here and in the frontend's `api.ts` — and a typo on either side
    /// compiles on both: the backend would lock and announce it to nobody, or the frontend would
    /// report activity to a command that does not exist, and the wallet would lock under someone
    /// using it. Cheap to pin.
    #[test]
    fn the_frontend_uses_the_names_this_backend_answers_to() {
        let api = include_str!("../../src/api.ts");
        assert!(
            api.contains(&format!("\"{WALLET_LOCKED_EVENT}\"")),
            "event name drifted"
        );
        assert!(api.contains("\"touch_wallet\""), "command name drifted");
    }

    /// Reporting activity is never a way to keep or bring back a key.
    #[test]
    fn touching_a_locked_wallet_changes_nothing() {
        let state = WalletState::default();
        state.touch();
        assert!(state.inner.lock().unwrap().is_none());
        assert!(!state.lock_if_idle());
    }
}
