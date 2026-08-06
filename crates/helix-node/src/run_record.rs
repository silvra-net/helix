//! Telling an operator how the node's *previous* run ended.
//!
//! A node that stops answering is the single most common failure an operator faces, and today
//! nothing anywhere says why. The log ends mid-sentence and that is all there is: a clean
//! `systemctl stop`, a panic, an OOM kill and a `kill -9` are indistinguishable afterwards. So the
//! honest answer to "why does my node keep dying?" has been "nobody can tell", which is the worst
//! possible answer to give someone running infrastructure for you.
//!
//! The mechanism is deliberately crude, because the failure it reports on is one where nothing
//! sophisticated survives: a small file is written at startup saying "running", refreshed while
//! the node lives, and marked clean on an orderly shutdown. If the next startup finds it still
//! saying "running", the previous run did not get to finish — and the record carries how long it
//! lasted, what height it reached, and how much memory it was using when it was last seen.
//!
//! That last figure is the point. An OOM kill leaves *nothing* in the process's own log — the
//! kernel takes the decision and the process never runs again — and it has already cost this
//! project a validator once (backlog #118: redb's 1 GiB default cache pushed a node to 1.5 GB RSS
//! on a machine that did not have it). A last-seen RSS next to the machine's total memory turns
//! that from an unanswerable mystery into a number an operator can act on.
//!
//! Beside the chain database, never inside it: this has to survive exactly the situations where
//! the database write did not.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// What one run of the node recorded about itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunRecord {
    pub version: String,
    pub started_at_unix: u64,
    /// Refreshed while the node runs, so a crashed run still says roughly when it was last alive
    /// — the timestamp an operator needs to line this up against `dmesg` or the system journal.
    pub last_seen_unix: u64,
    pub height: u64,
    /// Resident memory at `last_seen_unix`, in KB. Zero when unavailable.
    pub rss_kb: u64,
    /// Set only by an orderly shutdown. Its absence is the whole signal.
    pub clean_exit: bool,
}

impl RunRecord {
    fn new(version: String, now: u64, height: u64) -> Self {
        RunRecord {
            version,
            started_at_unix: now,
            last_seen_unix: now,
            height,
            rss_kb: current_rss_kb(),
            clean_exit: false,
        }
    }
}

/// Read the previous run's record, then claim the file for this run.
///
/// Returns whatever the previous run left behind, so the caller can report it. Any read failure is
/// treated as "no previous record": this is diagnostics, and a node that refused to start because
/// it could not parse its own breadcrumb would be a worse bug than the one it reports on.
pub fn begin_run(path: &Path, version: &str, height: u64) -> Option<RunRecord> {
    let previous = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<RunRecord>(&raw).ok());
    write(path, &RunRecord::new(version.to_string(), now_unix(), height));
    previous
}

/// Refresh the record while the node is alive. Cheap enough for the health loop's cadence.
///
/// Carries the existing record forward for the same reason as `mark_clean`: the start time and
/// version belong to the run that wrote them, and re-deriving them here is how a refresh quietly
/// turns into a different run. Without this the record's timestamp never moves, so a crashed run
/// could say nothing about *when* it stopped — which is the field an operator lines up against
/// their system log.
pub fn touch(path: &Path, height: u64) {
    let Some(mut record) = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<RunRecord>(&raw).ok())
    else {
        return;
    };
    record.last_seen_unix = now_unix();
    record.height = height;
    record.rss_kb = current_rss_kb();
    write(path, &record);
}

/// Mark this run as having ended on purpose.
///
/// Reads the record this run already wrote rather than taking its start time as an argument: the
/// startup and shutdown paths live in different functions, and threading a timestamp between them
/// is one more thing that can be wired up wrongly and then silently report every clean stop as a
/// crash. If there is no record to update, there is nothing to claim, so nothing is written.
pub fn mark_clean(path: &Path, height: u64) {
    let Some(mut record) = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<RunRecord>(&raw).ok())
    else {
        return;
    };
    record.last_seen_unix = now_unix();
    record.height = height;
    record.rss_kb = current_rss_kb();
    record.clean_exit = true;
    write(path, &record);
}

fn write(path: &Path, record: &RunRecord) {
    let Ok(encoded) = serde_json::to_string_pretty(record) else {
        return;
    };
    // Write-then-rename: a crash mid-write must not leave a file that the next start cannot read,
    // because the next start is exactly when this matters.
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, encoded).and_then(|_| std::fs::rename(&tmp, path)).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// The file this node writes, beside its chain database.
pub fn path_beside(db_path: &Path) -> PathBuf {
    db_path.with_file_name("helix-last-run.json")
}

/// What to tell the operator about the previous run, if anything.
///
/// Split out as a pure function because the wording *is* the feature — this is the line somebody
/// reads at 3am when their validator has stopped twice, and it has to distinguish "you stopped it"
/// from "something killed it" without asserting more than the record supports.
pub fn previous_run_report(previous: Option<&RunRecord>, machine_total_kb: u64) -> Option<String> {
    let prev = previous?;
    if prev.clean_exit {
        // Worth saying, quietly: it rules out a crash, which is half of any diagnosis.
        return Some(format!(
            "Previous run (v{}) shut down cleanly at height {} after {}.",
            prev.version,
            prev.height,
            human_duration(prev.last_seen_unix.saturating_sub(prev.started_at_unix))
        ));
    }

    let ran_for = human_duration(prev.last_seen_unix.saturating_sub(prev.started_at_unix));
    let mut msg = format!(
        "Previous run (v{}) did NOT shut down cleanly. It ran {}, last seen at height {} \
         ({}), using {} of memory. Something ended it without warning — a crash, an OOM kill, \
         `kill -9`, or the machine going down. Check the system log around that time \
         (`journalctl -k --since` or `dmesg -T`) before assuming the node is at fault.",
        prev.version,
        ran_for,
        prev.height,
        unix_to_local(prev.last_seen_unix),
        human_mem(prev.rss_kb),
    );

    // Only claimed when the numbers actually support it. "It was probably memory" is a useful
    // hint and a terrible guess — an operator who chases RAM because of a spurious note is worse
    // off than one who was told nothing.
    if machine_total_kb > 0 && prev.rss_kb > 0 {
        let share = prev.rss_kb as f64 / machine_total_kb as f64;
        if share >= 0.7 {
            msg.push_str(&format!(
                " Note: that was {:.0}% of this machine's {} of RAM, so an out-of-memory kill is \
                 the first thing to rule out.",
                share * 100.0,
                human_mem(machine_total_kb)
            ));
        }
    }
    Some(msg)
}

/// Log the previous run's fate at the right level: a crash is a warning, an orderly stop is not.
pub fn report_previous_run(previous: Option<&RunRecord>) {
    let Some(text) = previous_run_report(previous, machine_total_kb()) else {
        return;
    };
    match previous.map(|p| p.clean_exit) {
        Some(true) => info!("{}", text),
        _ => warn!("{}", text),
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// This process's resident set size in KB, or 0 where that cannot be read.
fn current_rss_kb() -> u64 {
    read_kb_field("/proc/self/status", "VmRSS:")
}

/// The machine's total RAM in KB, or 0 where that cannot be read.
pub fn machine_total_kb() -> u64 {
    read_kb_field("/proc/meminfo", "MemTotal:")
}

fn read_kb_field(path: &str, field: &str) -> u64 {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    text.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn human_mem(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1} GB", kb as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} MB", kb / 1024)
    }
}

fn human_duration(secs: u64) -> String {
    match secs {
        0..=90 => format!("{secs}s"),
        91..=5400 => format!("{} min", secs / 60),
        _ => format!("{:.1} h", secs as f64 / 3600.0),
    }
}

fn unix_to_local(unix: u64) -> String {
    // No chrono in this crate's dependency set, and pulling one in for a log line is not worth it.
    // The raw epoch second is what an operator pastes into `journalctl --since=@<n>` anyway.
    format!("epoch {unix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(clean: bool, rss_kb: u64) -> RunRecord {
        RunRecord {
            version: "0.10.1".into(),
            started_at_unix: 1_000_000,
            last_seen_unix: 1_007_200, // two hours later
            height: 36_119,
            rss_kb,
            clean_exit: clean,
        }
    }

    /// The case this exists for. An operator whose node vanished must be told that it vanished,
    /// rather than being left to compare timestamps by hand.
    #[test]
    fn a_run_that_was_killed_is_reported_as_not_shutting_down_cleanly() {
        let text = previous_run_report(Some(&record(false, 500_000)), 8_000_000).unwrap();
        assert!(text.contains("did NOT shut down cleanly"), "{text}");
        assert!(text.contains("36119"), "must say how far it got: {text}");
        assert!(text.contains("2.0 h"), "must say how long it lasted: {text}");
        assert!(text.contains("dmesg") || text.contains("journalctl"), "must say where to look: {text}");
    }

    /// The control. An orderly stop must not be dressed up as an incident, or the warning above
    /// becomes noise and stops being read — the same way the unconditional "restart" advice did.
    #[test]
    fn an_orderly_shutdown_is_not_reported_as_a_crash() {
        let text = previous_run_report(Some(&record(true, 500_000)), 8_000_000).unwrap();
        assert!(text.contains("shut down cleanly"), "{text}");
        assert!(!text.contains("NOT"), "{text}");
        assert!(!text.contains("OOM"), "{text}");
    }

    /// A first run has nothing to report and must say nothing at all.
    #[test]
    fn a_first_run_says_nothing() {
        assert!(previous_run_report(None, 8_000_000).is_none());
    }

    /// The memory hint is the most actionable line in the whole message — and the easiest to get
    /// wrong. It may only appear when the numbers support it.
    #[test]
    fn the_memory_hint_appears_only_when_memory_was_actually_tight() {
        let tight = previous_run_report(Some(&record(false, 7_000_000)), 8_000_000).unwrap();
        assert!(tight.contains("out-of-memory"), "87% of RAM must raise it: {tight}");

        let roomy = previous_run_report(Some(&record(false, 500_000)), 8_000_000).unwrap();
        assert!(
            !roomy.contains("out-of-memory"),
            "6% of RAM must NOT raise it — a spurious memory hunt is worse than no hint: {roomy}"
        );
    }

    /// Unknown machine memory must not produce a percentage of nothing.
    #[test]
    fn an_unknown_machine_size_suppresses_the_memory_hint() {
        let text = previous_run_report(Some(&record(false, 7_000_000)), 0).unwrap();
        assert!(!text.contains("out-of-memory"), "{text}");
        assert!(text.contains("did NOT shut down cleanly"), "the rest must survive: {text}");
    }

    /// A crashed run leaves the file saying "running"; the next start has to find exactly that.
    #[test]
    fn a_run_that_never_finished_is_still_there_for_the_next_start() {
        let dir = std::env::temp_dir().join(format!("helix-runrec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helix-last-run.json");

        assert!(begin_run(&path, "0.10.1", 100).is_none(), "no previous run on a first start");
        touch(&path, 200);
        // No mark_clean — this is the crash.

        let previous = begin_run(&path, "0.10.1", 200).expect("the record must survive");
        assert!(!previous.clean_exit, "an unfinished run must not look orderly");
        assert_eq!(previous.height, 200, "and must carry how far it got");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half: an orderly stop has to be recorded as one, or every restart would be
    /// reported as a crash and the signal would be worthless.
    #[test]
    fn an_orderly_stop_is_recorded_as_orderly() {
        let dir = std::env::temp_dir().join(format!("helix-runrec-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helix-last-run.json");

        begin_run(&path, "0.10.1", 100);
        mark_clean(&path, 300);

        let previous = begin_run(&path, "0.10.1", 300).expect("record must exist");
        assert!(previous.clean_exit);
        assert_eq!(previous.height, 300);

        std::fs::remove_dir_all(&dir).ok();
    }
}
