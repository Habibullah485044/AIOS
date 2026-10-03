//! Task Ledger Control — data model (T-00014, Rust port).
//!
//! Byte- and behavior-compatible port of `tools/task_ledger.py`:
//!   - atomic state pointer updates (tmp + rename) for `TASK_STATE.json`
//!   - append-only completion event log (`COMPLETIONS.jsonl`, fsync'd)
//!   - strict no-skip enforcement with mechanical refusal
//!   - block / unblock / skip with explicit audit events
//!   - state rebuild from the event log (Fowler complete-rebuild)
//!   - ledger invariant validation (`check`)
//!
//! Single-writer assumption (D3): advisory `flock` guards against
//! accidental concurrent runs on the same host.

use serde_json::{json, Map, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u64 = 2;
pub const VALID_EVENTS: &[&str] = &["completed", "blocked", "unblocked", "pointer_reset"];
pub const RULE: &str = "Execute ONLY next_task. Advance by exactly 1 via tools/complete_task.py. Never skip.";

/// Resolve `docs/tasks` (spec T-00022 §5, fixes SPEC-TASK-LEDGER L2):
/// 1. `$AIOSH_TASKS_DIR` when set and non-empty;
/// 2. else walk ancestors of `current_exe()`'s directory looking for
///    `docs/tasks/MASTER_TASK_LEDGER.jsonl`; first hit wins;
/// 3. else Err("cannot locate docs/tasks (set AIOSH_TASKS_DIR)") —
///    loud failure, never a wrong-directory guess.
pub fn tasks_dir() -> Result<PathBuf, String> {
    if let Ok(d) = std::env::var("AIOSH_TASKS_DIR") {
        if !d.is_empty() {
            return Ok(PathBuf::from(d));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(found) = find_ancestor_tasks_dir(parent) {
                return Ok(found);
            }
        }
    }
    Err("cannot locate docs/tasks (set AIOSH_TASKS_DIR)".into())
}

/// Walk `start` and its ancestors looking for a repo root that carries
/// `docs/tasks/MASTER_TASK_LEDGER.jsonl`; returns `<root>/docs/tasks`.
pub fn find_ancestor_tasks_dir(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let marker = dir
            .join("docs")
            .join("tasks")
            .join("MASTER_TASK_LEDGER.jsonl");
        if marker.exists() {
            return Some(dir.join("docs").join("tasks"));
        }
        cur = dir.parent();
    }
    None
}

pub fn paths() -> Result<LedgerPaths, String> {
    let dir = tasks_dir()?;
    Ok(LedgerPaths {
        dir: dir.clone(),
        ledger: dir.join("MASTER_TASK_LEDGER.jsonl"),
        state: dir.join("TASK_STATE.json"),
        events: dir.join("COMPLETIONS.jsonl"),
        lock: dir.join(".TASK_STATE.lock"),
        evidence: dir.join("evidence"),
    })
}

#[derive(Debug, Clone)]
pub struct LedgerPaths {
    pub dir: PathBuf,
    pub ledger: PathBuf,
    pub state: PathBuf,
    pub events: PathBuf,
    pub lock: PathBuf,
    pub evidence: PathBuf,
}

pub fn utcnow_iso() -> String {
    // `%Y-%m-%dT%H:%M:%SZ` — matches the Python `_utcnow_iso`.
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ---------------------------------------------------------------------
// Size caps (T-00018 hardening): bound untrusted file reads so a
// pathological ledger/event/state file can't exhaust memory.
// ---------------------------------------------------------------------

// T-00054: the three file caps and the lock timeout are CONFIGURABLE
// via AIOSH_LEDGER_* env vars (see ledger_config.rs). The constants
// below are the DEFAULTS, kept for tests and documentation.
pub const MAX_LEDGER_FILE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
pub const MAX_EVENTS_FILE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
pub const MAX_STATE_FILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

fn config() -> Result<crate::ledger_config::LedgerConfig, String> {
    crate::ledger_config::LedgerConfig::from_env()
}

fn read_capped(path: &Path, cap: u64) -> Result<String, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {}", path.display(), e))?;
    if meta.len() > cap {
        return Err(format!(
            "{} too large ({} bytes > cap {} bytes)",
            path.display(),
            meta.len(),
            cap
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------
// Event log
// ---------------------------------------------------------------------

pub fn read_events(events_path: &Path) -> Result<Vec<Value>, String> {
    let mut events = Vec::new();
    let content = match std::fs::metadata(events_path) {
        Ok(_) => read_capped(events_path, config()?.max_events_bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(events),
        Err(e) => return Err(format!("stat events: {}", e)),
    };
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => events.push(v),
            Err(e) => return Err(format!("corrupt event log line {}: {}", i + 1, e)),
        }
    }
    Ok(events)
}

fn open_options_644() -> OpenOptions {
    #[allow(unused_mut)]
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    {
        opts.mode(0o644);
    }
    opts
}

/// Append one JSONL event line (flush + fsync), assigning seq.
pub fn append_event(
    events_path: &Path,
    mut event: Value,
    expected_task_id: Option<u64>,
) -> Result<Value, String> {
    let kind = event.get("event").and_then(|v| v.as_str()).unwrap_or("");
    if !VALID_EVENTS.contains(&kind) {
        return Err(format!("invalid event type: {:?}", kind));
    }
    if let Some(expected) = expected_task_id {
        if event.get("task_id").and_then(|v| v.as_u64()) != Some(expected) {
            return Err(format!(
                "event task_id {:?} != expected {}",
                event.get("task_id"),
                expected
            ));
        }
    }
    let existing = read_events(events_path)?;
    let seq = existing.last().and_then(|e| e.get("seq")).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
    let mut record = Map::new();
    record.insert("seq".into(), json!(seq));
    record.insert("ts".into(), json!(utcnow_iso()));
    if let Value::Object(m) = &mut event {
        record.extend(std::mem::take(m));
    } else {
        return Err("event must be an object".into());
    }
    let record = Value::Object(record);
    let line = serde_json::to_string(&record).map_err(|e| e.to_string())? + "\n";
    let mut f = open_options_644()
        .create(true)
        .append(true)
        .open(events_path)
        .map_err(|e| format!("open events: {}", e))?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(record)
}

fn count_ledger_lines(ledger_path: &Path) -> Result<u64, String> {
    let content = read_capped(ledger_path, config()?.max_ledger_bytes)?;
    Ok(content.lines().filter(|l| !l.trim().is_empty()).count() as u64)
}

// ---------------------------------------------------------------------
// State pointer
// ---------------------------------------------------------------------

/// The shape of `TASK_STATE.json`. Field order matches the Python dict
/// insertion order for human readability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskState {
    pub schema_version: u64,
    pub ledger: String,
    pub total_tasks: u64,
    pub next_task: Option<u64>,
    pub completed: Vec<u64>,
    pub blocked: Vec<u64>,
    pub skipped: Vec<u64>,
    pub last_completed_at: Option<String>,
    pub last_event_seq: u64,
    pub rule: String,
}

/// Load `TASK_STATE.json`, migrating v1 → v2 on read (spec §2.3).
pub fn load_state(state_path: &Path, events_path: &Path) -> Result<Value, String> {
    let content = read_capped(state_path, config()?.max_state_bytes)?;
    let mut raw: Map<String, Value> = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    let ver = raw.get("schema_version").and_then(|v| v.as_u64()).unwrap_or(1);
    if ver >= SCHEMA_VERSION {
        return Ok(Value::Object(raw));
    }
    // v1 → v2 migration: add missing fields.
    let events = read_events(events_path)?;
    raw.insert("schema_version".into(), json!(SCHEMA_VERSION));
    raw.entry(String::from("blocked")).or_insert_with(|| json!([]));
    raw.entry(String::from("skipped")).or_insert_with(|| json!([]));
    let last_seq = events
        .last()
        .and_then(|e| e.get("seq"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    raw.insert("last_event_seq".into(), json!(last_seq));
    raw.insert("rule".into(), json!(RULE));
    Ok(Value::Object(raw))
}

/// Remove stale `<state>.tmp.<pid>` leftovers from crashed/interrupted
/// writers (T-00018: no temp-file leaks on the error path). Only our
/// own pattern is removed — never the live state file.
fn cleanup_stale_tmp(state_path: &Path) {
    let dir = match state_path.parent() {
        Some(d) => d.to_path_buf(),
        None => return,
    };
    let base = match state_path.file_name().and_then(|s| s.to_str()) {
        Some(b) => b.to_string(),
        None => return,
    };
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("{}.tmp.", base)) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Write state to `<path>.tmp.<pid>` then rename (spec §3).
pub fn save_state_atomic(state: &Value, state_path: &Path) -> Result<(), String> {
    // Clear any stale temp from a previous crashed writer so `create_new`
    // below can never collide with a dead pid's leftover.
    cleanup_stale_tmp(state_path);
    let tmp = format!("{}.tmp.{}", state_path.display(), std::process::id());
    let data = serde_json::to_string_pretty(state).map_err(|e| e.to_string())? + "\n";
    let mut f = open_options_644()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("open tmp state: {}", e))?;
    let write = f.write_all(data.as_bytes()).and_then(|_| f.sync_all());
    drop(f);
    // On any write error, remove our own temp so no orphan is left.
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write tmp state: {}", e));
    }
    std::fs::rename(&tmp, state_path).map_err(|e| format!("rename state: {}", e))?;
    Ok(())
}

/// Core deterministic replay shared by rebuild_state and validate_state
/// (pointer semantics per spec T-00022 §6). Returns
/// (completed, blocked, skipped, next_pointer, last_ts).
fn replay_events(
    events: &[Value],
) -> (Vec<u64>, Vec<u64>, Vec<u64>, u64, Option<String>) {
    let mut completed: Vec<u64> = Vec::new();
    let mut blocked: Vec<u64> = Vec::new();
    let mut skipped: Vec<u64> = Vec::new();
    let mut last_ts: Option<String> = None;
    let mut next_pointer: u64 = 1;
    for ev in events {
        let tid = ev.get("task_id").and_then(|v| v.as_u64());
        let kind = ev.get("event").and_then(|v| v.as_str());
        match (kind, tid) {
            (Some("completed"), Some(t)) => {
                completed.push(t);
                last_ts = ev.get("ts").and_then(|v| v.as_str()).map(|s| s.to_string());
                next_pointer = t + 1;
            }
            (Some("blocked"), Some(t)) => {
                if !blocked.contains(&t) {
                    blocked.push(t);
                }
            }
            (Some("unblocked"), Some(t)) => {
                blocked.retain(|b| b != &t);
                next_pointer = t;
            }
            (Some("pointer_reset"), Some(t)) => {
                skipped.push(t);
                next_pointer = t + 1;
            }
            _ => {}
        }
    }
    (completed, blocked, skipped, next_pointer, last_ts)
}

/// Recompute `TASK_STATE.json` from the append-only event log.
///
/// Pointer semantics (spec T-00022 §6, fixes SPEC-TASK-LEDGER L3):
/// deterministic event-order replay reproducing live transitions —
/// `completed t` ⇒ next = t+1; `unblocked t` ⇒ next = t (retry);
/// `pointer_reset t` ⇒ next = t+1; `blocked` never moves the pointer.
/// A pointer past `total_tasks` collapses to `None` (end of ledger).
pub fn rebuild_state(p: &LedgerPaths) -> Result<Value, String> {
    let events = read_events(&p.events)?;
    let (completed, blocked, skipped, next_pointer, last_ts) =
        replay_events(&events);
    let total = count_ledger_lines(&p.ledger)?;
    let next = if next_pointer > total { None } else { Some(next_pointer) };
    let last_seq = events
        .last()
        .and_then(|e| e.get("seq"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let state = json!({
        "schema_version": SCHEMA_VERSION,
        "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": total,
        "next_task": next,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "last_completed_at": last_ts,
        "last_event_seq": last_seq,
        "rule": RULE,
    });
    save_state_atomic(&state, &p.state)?;
    Ok(state)
}

// ---------------------------------------------------------------------
// Ledger access
// ---------------------------------------------------------------------

/// Stream-scan the ledger for the task with the given id.
pub fn find_task_in_ledger(ledger_path: &Path, task_id: u64) -> Result<Option<Value>, String> {
    let content = read_capped(ledger_path, config()?.max_ledger_bytes)?;
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Err(format!("ledger line {} unparseable: {}", i + 1, e)),
        };
        if rec.get("id").and_then(|v| v.as_u64()) == Some(task_id) {
            return Ok(Some(rec));
        }
    }
    Ok(None)
}

/// Validate ledger invariants (spec §2.1): sequential ids, linear deps,
/// next_task linkage.
pub fn assert_ledger_invariants(ledger_path: &Path) -> Result<Value, String> {
    let content = read_capped(ledger_path, config()?.max_ledger_bytes)?;
    let mut prev_id: u64 = 0;
    let mut count: u64 = 0;
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: Value = serde_json::from_str(line).map_err(|e| format!("parse: {}", e))?;
        let tid = rec.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        if tid != prev_id + 1 {
            return Ok(json!({
                "ok": false, "line": i + 1,
                "error": format!("id gap: expected {}, got {}", prev_id + 1, tid),
            }));
        }
        let deps = rec.get("depends_on").and_then(|v| v.as_array());
        if tid > 1 {
            let ok = deps.map(|d| d.len() == 1 && d[0].as_u64() == Some(tid - 1)).unwrap_or(false);
            if !ok {
                return Ok(json!({
                    "ok": false, "line": i + 1,
                    "error": format!("depends_on {:?} != [{}]", deps, tid - 1),
                }));
            }
        }
        let nxt = rec.get("next_task").and_then(|v| v.as_u64());
        if let Some(n) = nxt {
            if n != tid + 1 {
                return Ok(json!({
                    "ok": false, "line": i + 1,
                    "error": format!("next_task {} != {}", n, tid + 1),
                }));
            }
        }
        prev_id = tid;
        count += 1;
    }
    Ok(json!({ "ok": true, "total_tasks": count }))
}

// ---------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------

fn fmt_task(tid: Option<u64>) -> String {
    match tid {
        Some(t) => format!("T-{:05}", t),
        None => "None".into(),
    }
}

fn state_from_value(v: &Value) -> Result<TaskState, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("bad state: {}", e))
}

/// Spec §4: complete the current next_task and advance the pointer.
pub fn complete_task(
    p: &LedgerPaths,
    task_id: u64,
    note: &str,
    evidence: &[String],
) -> Result<Value, String> {
    let _lock = acquire_lock(&p.lock)?;
    let state_val = load_state(&p.state, &p.events)?;
    let mut state = state_from_value(&state_val)?;
    if state.next_task != Some(task_id) {
        return Err(format!(
            "NO-SKIP violation: attempted to complete T-{:05} but next_task is {}. Complete {} first.",
            task_id,
            fmt_task(state.next_task),
            fmt_task(state.next_task),
        ));
    }
    let task = find_task_in_ledger(&p.ledger, task_id)?
        .ok_or_else(|| format!("task {} not found in ledger", task_id))?;
    let mut ev = Map::new();
    ev.insert("event".into(), json!("completed"));
    ev.insert("task_id".into(), json!(task_id));
    ev.insert("note".into(), json!(note));
    if !evidence.is_empty() {
        ev.insert(
            "evidence".into(),
            json!(evidence.iter().map(|s| s.clone()).collect::<Vec<_>>()),
        );
    }
    append_event(&p.events, Value::Object(ev), Some(task_id))?;
    state.completed.push(task_id);
    state.next_task = if task_id < state.total_tasks {
        Some(task_id + 1)
    } else {
        None
    };
    state.last_completed_at = Some(utcnow_iso());
    state.last_event_seq += 1;
    let saved = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    save_state_atomic(&saved, &p.state)?;
    let ev_file = ensure_evidence_stub(p, task_id, &task)?;
    Ok(json!({
        "ok": true,
        "completed": task_id,
        "title": task.get("title"),
        "next_task": state.next_task,
        "evidence": ev_file,
    }))
}

/// Spec §5: mark the current task blocked; pointer does NOT advance.
pub fn block_task(p: &LedgerPaths, task_id: u64, reason: &str) -> Result<Value, String> {
    if reason.is_empty() {
        return Err("block requires a non-empty reason".into());
    }
    let _lock = acquire_lock(&p.lock)?;
    let state_val = load_state(&p.state, &p.events)?;
    let mut state = state_from_value(&state_val)?;
    if state.next_task != Some(task_id) {
        return Err(format!(
            "can only block next_task ({}), got T-{:05}",
            fmt_task(state.next_task),
            task_id
        ));
    }
    append_event(
        &p.events,
        json!({ "event": "blocked", "task_id": task_id, "note": reason }),
        None,
    )?;
    if !state.blocked.contains(&task_id) {
        state.blocked.push(task_id);
    }
    state.last_event_seq += 1;
    let saved = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    save_state_atomic(&saved, &p.state)?;
    Ok(json!({ "ok": true, "blocked": task_id, "next_task": state.next_task }))
}

/// Spec §5: unblock a previously blocked task (retry).
pub fn unblock_task(p: &LedgerPaths, task_id: u64, reason: &str) -> Result<Value, String> {
    if reason.is_empty() {
        return Err("unblock requires a non-empty reason".into());
    }
    let _lock = acquire_lock(&p.lock)?;
    let state_val = load_state(&p.state, &p.events)?;
    let mut state = state_from_value(&state_val)?;
    if !state.blocked.contains(&task_id) {
        return Err(format!("task {} is not in blocked list", task_id));
    }
    append_event(
        &p.events,
        json!({ "event": "unblocked", "task_id": task_id, "note": reason }),
        None,
    )?;
    state.blocked.retain(|b| b != &task_id);
    state.next_task = Some(task_id);
    state.last_event_seq += 1;
    let saved = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    save_state_atomic(&saved, &p.state)?;
    Ok(json!({ "ok": true, "unblocked": task_id, "next_task": task_id }))
}

/// Spec §5: human override — skip with mandatory reason.
pub fn skip_task(p: &LedgerPaths, task_id: u64, reason: &str) -> Result<Value, String> {
    if reason.is_empty() {
        return Err("skip requires a non-empty reason".into());
    }
    let _lock = acquire_lock(&p.lock)?;
    let state_val = load_state(&p.state, &p.events)?;
    let mut state = state_from_value(&state_val)?;
    if state.next_task != Some(task_id) {
        return Err(format!(
            "can only skip next_task ({}), got T-{:05}",
            fmt_task(state.next_task),
            task_id
        ));
    }
    append_event(
        &p.events,
        json!({ "event": "pointer_reset", "task_id": task_id, "note": reason }),
        Some(task_id),
    )?;
    if !state.skipped.contains(&task_id) {
        state.skipped.push(task_id);
    }
    state.blocked.retain(|b| b != &task_id);
    state.next_task = if task_id < state.total_tasks {
        Some(task_id + 1)
    } else {
        None
    };
    state.last_event_seq += 1;
    let saved = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    save_state_atomic(&saved, &p.state)?;
    Ok(json!({
        "ok": true,
        "skipped": task_id,
        "next_task": state.next_task,
        "reason": reason,
    }))
}

/// Create `<task>-completion.md` in the evidence dir if absent
/// (mirrors `_ensure_evidence_stub` — never overwrites real evidence).
fn ensure_evidence_stub(p: &LedgerPaths, task_id: u64, task: &Value) -> Result<String, String> {
    std::fs::create_dir_all(&p.evidence).map_err(|e| e.to_string())?;
    let path = p.evidence.join(format!("T-{:05}-completion.md", task_id));
    if !path.exists() {
        let title = task.get("title").and_then(|v| v.as_str()).unwrap_or("");
        let mut lines = format!("# T-{:05} — {}\n\n", task_id, title);
        lines.push_str(&format!("Completed: {}\n\nAcceptance criteria:\n", utcnow_iso()));
        if let Some(acc) = task.get("acceptance").and_then(|v| v.as_array()) {
            for a in acc {
                if let Some(s) = a.as_str() {
                    lines.push_str(&format!("- [x] {}\n", s));
                }
            }
        }
        std::fs::write(&path, lines).map_err(|e| e.to_string())?;
    }
    Ok(path.to_string_lossy().to_string())
}

// ---------------------------------------------------------------------
// Locking (single-writer assumption D3)
// ---------------------------------------------------------------------

/// How long a writer waits for `.TASK_STATE.lock` before failing loudly
/// (T-00028 hardening: previously `flock(LOCK_EX)` could block forever
/// on a stuck holder, hanging the CLI or the MCP server).
pub const LOCK_TIMEOUT_SECS: u64 = 5; // DEFAULT; overridden by AIOSH_LEDGER_LOCK_TIMEOUT_SECS
#[allow(dead_code)]
const LOCK_POLL_MS: u64 = 50;

#[allow(dead_code)]
struct FileLock(File);

#[cfg(unix)]
fn acquire_lock_timeout(lock_path: &Path, timeout: std::time::Duration) -> Result<FileLock, String> {
    let f = open_options_644()
        .create(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| format!("open lock: {}", e))?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // Non-blocking attempt; poll until the deadline so a stuck
        // holder produces an explicit auditable error, never a hang.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(FileLock(f));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(format!("flock failed: {}", err));
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "ledger lock busy after {}ms (another writer holds .TASK_STATE.lock?)",
                timeout.as_millis()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(LOCK_POLL_MS));
    }
}

#[cfg(windows)]
mod win_lock {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::{Duration, Instant};

    pub const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x00000001;
    pub const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x00000002;
    pub const ERROR_LOCK_VIOLATION: i32 = 33;

    #[repr(C)]
    pub struct Overlapped {
        pub internal: usize,
        pub internal_high: usize,
        pub offset: u32,
        pub offset_high: u32,
        pub h_event: *mut std::ffi::c_void,
    }

    extern "system" {
        pub fn LockFileEx(
            hFile: *mut std::ffi::c_void,
            dwFlags: u32,
            dwReserved: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
            lpOverlapped: *mut Overlapped,
        ) -> i32;

        pub fn UnlockFileEx(
            hFile: *mut std::ffi::c_void,
            dwReserved: u32,
            nNumberOfBytesToUnlockLow: u32,
            nNumberOfBytesToUnlockHigh: u32,
            lpOverlapped: *mut Overlapped,
        ) -> i32;
    }

    pub fn acquire_lock_timeout(
        lock_path: &Path,
        timeout: Duration,
    ) -> Result<super::FileLock, String> {
        let f = super::open_options_644()
            .create(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| format!("open lock: {}", e))?;
        let handle = f.as_raw_handle() as *mut std::ffi::c_void;
        let deadline = Instant::now() + timeout;
        loop {
            let mut overlapped: Overlapped = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            };
            if rc != 0 {
                return Ok(super::FileLock(f));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_LOCK_VIOLATION) {
                return Err(format!("LockFileEx failed: {}", err));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "ledger lock busy after {}ms (another writer holds .TASK_STATE.lock?)",
                    timeout.as_millis()
                ));
            }
            std::thread::sleep(Duration::from_millis(super::LOCK_POLL_MS));
        }
    }

    pub fn unlock_file(file: &File) {
        let handle = file.as_raw_handle() as *mut std::ffi::c_void;
        let mut overlapped: Overlapped = unsafe { std::mem::zeroed() };
        unsafe {
            UnlockFileEx(handle, 0, 1, 0, &mut overlapped);
        }
    }
}

#[cfg(windows)]
fn acquire_lock_timeout(lock_path: &Path, timeout: std::time::Duration) -> Result<FileLock, String> {
    win_lock::acquire_lock_timeout(lock_path, timeout)
}

#[cfg(not(any(unix, windows)))]
fn acquire_lock_timeout(lock_path: &Path, _timeout: std::time::Duration) -> Result<FileLock, String> {
    let f = open_options_644()
        .create(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| format!("open lock: {}", e))?;
    Ok(FileLock(f))
}

fn acquire_lock(lock_path: &Path) -> Result<FileLock, String> {
    let secs = crate::ledger_config::LedgerConfig::from_env()?.lock_timeout_secs;
    acquire_lock_timeout(lock_path, std::time::Duration::from_secs(secs))
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
        #[cfg(windows)]
        {
            win_lock::unlock_file(&self.0);
        }
    }
}

// serde derives for the state struct.
use serde::{Deserialize, Serialize};

// ----------------------------------------------------------------------
// Validation (recovery & validation component, T-00103 scaffold)
// ----------------------------------------------------------------------

/// Read-only integrity report: live `TASK_STATE.json` vs deterministic
/// event-log replay. Contract: docs/tasks/evidence/T-00102-spec.md.
/// Report-only by design — `rebuild_state` remains the only repair path.
/// (T-00103 scaffold: typed interface only; body fails loudly until
/// T-00104.)
/// Read-only integrity report: live `TASK_STATE.json` vs deterministic
/// event-log replay. Contract: docs/tasks/evidence/T-00102-spec.md §4.
/// Report-only by design — `rebuild_state` remains the only repair path.
/// Never mutates state, events, or evidence. The findings key set is the
/// cross-substrate parity contract (Python == Rust == MCP == CLI).
pub fn validate_state(p: &LedgerPaths) -> Result<Value, String> {
    let live_val = load_state(&p.state, &p.events)?;
    let events = read_events(&p.events)?;
    let total = count_ledger_lines(&p.ledger)?;
    let (completed_r, blocked_r, skipped_r, next_pointer, _ts) =
        replay_events(&events);
    let replay_next: Option<u64> =
        if next_pointer > total { None } else { Some(next_pointer) };

    // G1 — drift between live state and replay.
    let mut drift_fields: Vec<String> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    for (field, rv) in [
        ("next_task", json!(replay_next)),
        ("completed", json!(completed_r)),
        ("blocked", json!(blocked_r)),
        ("skipped", json!(skipped_r)),
    ] {
        let lv = live_val.get(field).cloned().unwrap_or(Value::Null);
        if lv != rv {
            drift_fields.push(field.to_string());
            details.push(format!("{field} live={lv} replay={rv}"));
        }
    }
    let checks_state = json!({
        "status": if drift_fields.is_empty() { "ok" } else { "fatal" },
        "detail": if details.is_empty() { Value::Null }
                  else { Value::String(details.join("; ")) },
        "fields": drift_fields,
    });

    // G2 — event log seq integrity (contiguous 1..N) + last_event_seq.
    let mut seq_detail: Option<String> = None;
    for (i, ev) in events.iter().enumerate() {
        let want = (i + 1) as u64;
        match ev.get("seq").and_then(|v| v.as_u64()) {
            Some(s) if s == want => {}
            other => {
                seq_detail = Some(format!(
                    "event {}: seq={:?} expected={}",
                    i + 1, other, want
                ));
                break;
            }
        }
    }
    let live_seq = live_val.get("last_event_seq").and_then(|v| v.as_u64());
    if seq_detail.is_none()
        && live_seq != Some(events.len() as u64)
    {
        seq_detail = Some(format!(
            "last_event_seq live={:?} events={}",
            live_seq,
            events.len()
        ));
    }
    let checks_seq = json!({
        "status": if seq_detail.is_none() { "ok" } else { "fatal" },
        "detail": seq_detail.map(Value::String).unwrap_or(Value::Null),
    });

    // G5 — pointer range sanity on the REPLAYED pointer.
    let ptr_detail: Option<String> = match replay_next {
        None => None,
        Some(n) if completed_r.contains(&n) => {
            Some(format!("next_task {n} is already completed"))
        }
        Some(n) if blocked_r.contains(&n) => {
            Some(format!("next_task {n} is currently blocked"))
        }
        Some(n) if n > total => {
            Some(format!("next_task {n} beyond total_tasks {total}"))
        }
        Some(_) => None,
    };
    let checks_ptr = json!({
        "status": if ptr_detail.is_none() { "ok" } else { "fatal" },
        "detail": ptr_detail.map(Value::String).unwrap_or(Value::Null),
    });

    // G3+G4 — evidence existence + orphans (warnings, never fatal).
    let mut missing: Vec<String> = Vec::new();
    let repo_root = p
        .dir
        .parent()
        .map(|x| x.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));
    for ev in &events {
        if ev.get("event").and_then(|v| v.as_str()) != Some("completed") {
            continue;
        }
        if let Some(list) = ev.get("evidence").and_then(|v| v.as_array()) {
            for rel in list {
                if let Some(rels) = rel.as_str() {
                    // T-00108 hardening (finding F-1): a path is
                    // satisfiable ONLY if relative and never escapes the
                    // two intended bases (tasks dir / repo root).
                    // Absolute or ".."-containing strings are classified
                    // missing (suspicious), never satisfied — an
                    // event-controlled string must not attest arbitrary
                    // disk locations. Existence checks read nothing.
                    let suspicious = rels.starts_with('/')
                        || rels.split('/').any(|c| c == "..");
                    let cand_tasks = p.dir.join(rels);
                    let cand_repo = repo_root.join(rels);
                    if !suspicious
                        && (cand_tasks.exists() || cand_repo.exists())
                    {
                        continue;
                    }
                    let tid = ev.get("task_id").and_then(|v| v.as_u64()).unwrap_or(0);
                    missing.push(format!("T-{tid:05}:{rels}"));
                } else {
                    let tid = ev.get("task_id").and_then(|v| v.as_u64()).unwrap_or(0);
                    missing.push(format!("T-{tid:05}:{rel}"));
                }
            }
        }
    }
    let mut orphans: Vec<String> = Vec::new();
    let completed_set: std::collections::BTreeSet<u64> =
        completed_r.iter().copied().collect();
    if let Ok(entries) = std::fs::read_dir(p.dir.join("evidence")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            // T-XXXXX-completion.md
            let stem = name.strip_suffix("-completion.md");
            if let Some(stem) = stem {
                if let Some(num) = stem.strip_prefix("T-") {
                    if num.len() == 5 && num.chars().all(|c| c.is_ascii_digit()) {
                        let id: u64 = num.parse().unwrap_or(0);
                        if !completed_set.contains(&id) {
                            orphans.push(name);
                        }
                    }
                }
            }
        }
    }
    orphans.sort();
    let checks_ev = json!({
        "status": if missing.is_empty() && orphans.is_empty() { "ok" } else { "warning" },
        "missing": missing,
        "orphans": orphans,
    });

    let fatal = [&checks_state, &checks_seq, &checks_ptr]
        .iter()
        .any(|c| c["status"] == "fatal");
    Ok(json!({
        "ok": true,
        "action": "validate",
        "consistent": !fatal,
        "checks": {
            "state_vs_events": checks_state,
            "event_seq": checks_seq,
            "pointer_range": checks_ptr,
            "evidence": checks_ev,
        },
        "replay": {
            "next_task": replay_next,
            "completed": completed_r.len(),
            "blocked": blocked_r.len(),
            "skipped": skipped_r.len(),
            "events": events.len(),
            "total_tasks": total,
        },
        "live": {
            "next_task": live_val.get("next_task").cloned().unwrap_or(Value::Null),
            "completed": live_val.get("completed").and_then(|v| v.as_array())
                .map(|a| a.len()).unwrap_or(0),
            "blocked": live_val.get("blocked").and_then(|v| v.as_array())
                .map(|a| a.len()).unwrap_or(0),
            "skipped": live_val.get("skipped").and_then(|v| v.as_array())
                .map(|a| a.len()).unwrap_or(0),
            "last_event_seq": live_seq,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env() -> (tempfile::TempDir, LedgerPaths) {
        let tmp = tempfile::tempdir().unwrap();
        let p = LedgerPaths {
            dir: tmp.path().to_path_buf(),
            ledger: tmp.path().join("MASTER_TASK_LEDGER.jsonl"),
            state: tmp.path().join("TASK_STATE.json"),
            events: tmp.path().join("COMPLETIONS.jsonl"),
            lock: tmp.path().join(".TASK_STATE.lock"),
            evidence: tmp.path().join("evidence"),
        };
        // Minimal well-formed ledger (10 tasks).
        let mut lines = String::new();
        for i in 1..=10u64 {
            let next = if i < 10 { Some(i + 1) } else { None };
            lines.push_str(&format!(
                "{{\"id\":{},\"title\":\"t{}\",\"depends_on\":{},\"next_task\":{},\"instructions\":[\"i\"],\"acceptance\":[\"a\"]}}\n",
                i,
                i,
                if i == 1 { "[]".to_string() } else { format!("[{}]", i - 1) },
                if let Some(n) = next { n.to_string() } else { "null".to_string() },
            ));
        }
        std::fs::write(&p.ledger, lines).unwrap();
        let state = json!({
            "schema_version": 2,
            "ledger": "MASTER_TASK_LEDGER.jsonl",
            "total_tasks": 10,
            "next_task": 1,
            "completed": [],
            "blocked": [],
            "skipped": [],
            "last_completed_at": null,
            "last_event_seq": 0,
            "rule": RULE,
        });
        save_state_atomic(&state, &p.state).unwrap();
        (tmp, p)
    }

    #[test]
    fn validate_state_clean_repo_is_consistent() {
        let (_t, p) = test_env();
        complete_task(&p, 1, "a", &[]).unwrap();
        let r = validate_state(&p).unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["consistent"], json!(true));
        for k in ["state_vs_events", "event_seq", "pointer_range", "evidence"] {
            assert!(r["checks"].get(k).is_some(), "missing check {k}");
        }
        assert_eq!(r["replay"]["next_task"], json!(2));
    }

    #[test]
    fn validate_state_detects_drift_without_mutating() {
        let (_t, p) = test_env();
        complete_task(&p, 1, "a", &[]).unwrap();
        // Hand-edit the pointer to simulate drift / a hand-tampered state.
        let mut st: Value =
            serde_json::from_str(&std::fs::read_to_string(&p.state).unwrap()).unwrap();
        st["next_task"] = json!(5);
        std::fs::write(&p.state, serde_json::to_string_pretty(&st).unwrap()).unwrap();
        let before = std::fs::read_to_string(&p.state).unwrap();
        let r = validate_state(&p).unwrap();
        assert_eq!(r["consistent"], json!(false));
        assert_eq!(r["checks"]["state_vs_events"]["status"], json!("fatal"));
        let fields: Vec<String> = r["checks"]["state_vs_events"]["fields"]
            .as_array().unwrap()
            .iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(fields.contains(&"next_task".to_string()), "{fields:?}");
        // Report-only: the state file must be untouched.
        assert_eq!(std::fs::read_to_string(&p.state).unwrap(), before);
    }

    #[test]
    fn validate_state_detects_seq_gap() {
        let (_t, p) = test_env();
        complete_task(&p, 1, "a", &[]).unwrap();
        complete_task(&p, 2, "b", &[]).unwrap();
        // Renumber event 2's seq to 3 -> gap (1,3) without changing what
        // the events MEAN, so only the integrity check can fire.
        let mut lines: Vec<String> = std::fs::read_to_string(&p.events).unwrap()
            .lines().map(|s| s.to_string()).collect();
        let mut ev2: Value = serde_json::from_str(&lines[1]).unwrap();
        ev2["seq"] = json!(3);
        lines[1] = ev2.to_string();
        std::fs::write(&p.events, lines.join("\n") + "\n").unwrap();
        // Align the live pointer fields with replay so ONLY the seq
        // integrity check is fatal (last_event_seq == count = 2).
        let mut st: Value =
            serde_json::from_str(&std::fs::read_to_string(&p.state).unwrap()).unwrap();
        st["last_event_seq"] = json!(2);
        std::fs::write(&p.state, serde_json::to_string_pretty(&st).unwrap()).unwrap();
        let r = validate_state(&p).unwrap();
        assert_eq!(r["consistent"], json!(false), "{r}");
        assert_eq!(r["checks"]["event_seq"]["status"], json!("fatal"));
        assert!(r["checks"]["event_seq"]["detail"].as_str().unwrap()
            .contains("expected=2"), "{r}");
    }

    #[test]
    fn complete_advances_pointer_exactly_one() {
        let (_t, p) = test_env();
        let r = complete_task(&p, 1, "test", &[]).unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["next_task"], json!(2));
        let st = load_state(&p.state, &p.events).unwrap();
        assert_eq!(st["completed"], json!([1]));
        assert_eq!(st["next_task"], json!(2));
        // Event log has exactly one event, seq 1.
        let events = read_events(&p.events).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["seq"], json!(1));
        assert_eq!(events[0]["event"], json!("completed"));
        // Evidence stub created.
        assert!(p.evidence.join("T-00001-completion.md").exists());
    }

    #[test]
    fn no_skip_rejects_out_of_order() {
        let (_t, p) = test_env();
        let err = complete_task(&p, 2, "x", &[]).unwrap_err();
        assert!(err.contains("NO-SKIP violation"), "{}", err);
        // Pointer unchanged.
        let st = load_state(&p.state, &p.events).unwrap();
        assert_eq!(st["next_task"], json!(1));
    }

    #[test]
    fn block_unblock_skip_flow() {
        let (_t, p) = test_env();
        let r = block_task(&p, 1, "waiting on research").unwrap();
        assert_eq!(r["blocked"], json!(1));
        assert_eq!(r["next_task"], json!(1)); // pointer does NOT advance
        let r = unblock_task(&p, 1, "research done").unwrap();
        assert_eq!(r["next_task"], json!(1));
        let r = skip_task(&p, 1, "out of scope").unwrap();
        assert_eq!(r["skipped"], json!(1));
        assert_eq!(r["next_task"], json!(2));
        let st = load_state(&p.state, &p.events).unwrap();
        assert_eq!(st["skipped"], json!([1]));
    }

    #[test]
    fn rebuild_recomputes_from_events() {
        let (_t, p) = test_env();
        complete_task(&p, 1, "a", &[]).unwrap();
        complete_task(&p, 2, "b", &[]).unwrap();
        // Corrupt the state file, then rebuild from the event log.
        std::fs::write(&p.state, "{}").unwrap();
        let st = rebuild_state(&p).unwrap();
        assert_eq!(st["next_task"], json!(3));
        assert_eq!(st["completed"], json!([1, 2]));
        assert_eq!(st["last_event_seq"], json!(2));
    }

    #[test]
    fn rebuild_replays_skip_and_unblock_pointers() {
        let (_t, p) = test_env();
        complete_task(&p, 1, "a", &[]).unwrap(); // next=2
        block_task(&p, 2, "wait").unwrap(); // pointer held at 2
        unblock_task(&p, 2, "retry").unwrap(); // next=2 again
        skip_task(&p, 2, "out of scope").unwrap(); // next=3
        complete_task(&p, 3, "c", &[]).unwrap(); // next=4
        std::fs::write(&p.state, "{}").unwrap();
        let st = rebuild_state(&p).unwrap();
        assert_eq!(st["next_task"], json!(4));
        assert_eq!(st["completed"], json!([1, 3]));
        assert_eq!(st["skipped"], json!([2]));
        assert_eq!(st["blocked"], json!([]));
    }

    #[test]
    fn rebuild_clamps_pointer_at_end_of_ledger() {
        let (_t, p) = test_env();
        for i in 1..=9u64 {
            complete_task(&p, i, "fill", &[]).unwrap();
        }
        skip_task(&p, 10, "last").unwrap(); // live: next_task = null
        std::fs::write(&p.state, "{}").unwrap();
        let st = rebuild_state(&p).unwrap();
        assert_eq!(st["next_task"], json!(null));
        assert_eq!(st["skipped"], json!([10]));
    }

    #[test]
    fn ancestor_walk_finds_repo_tasks_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("docs/tasks")).unwrap();
        std::fs::write(root.join("docs/tasks/MASTER_TASK_LEDGER.jsonl"), "{}\n").unwrap();
        let deep = root.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        let found = find_ancestor_tasks_dir(&deep).unwrap();
        assert_eq!(found, root.join("docs/tasks"));
        let empty = tempfile::tempdir().unwrap();
        assert!(find_ancestor_tasks_dir(empty.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn lock_contention_times_out_with_explicit_error() {
        use std::os::unix::io::AsRawFd;
        let (_t, p) = test_env();
        // A separate open file description holds the lock — same-process
        // contention, exactly the stuck-writer case.
        let holder = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&p.lock)
            .unwrap();
        let rc = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(rc, 0);
        let start = std::time::Instant::now();
        let err = match acquire_lock_timeout(&p.lock, std::time::Duration::from_millis(150)) {
            Err(e) => e,
            Ok(_) => panic!("lock acquisition should have timed out"),
        };
        assert!(err.contains("ledger lock busy"), "{}", err);
        assert!(start.elapsed() >= std::time::Duration::from_millis(140));
        // Once released, acquisition succeeds again.
        drop(holder);
        let _g = acquire_lock_timeout(&p.lock, std::time::Duration::from_millis(150)).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn lock_contention_times_out_with_explicit_error() {
        use std::os::windows::io::AsRawHandle;
        let (_t, p) = test_env();
        let holder = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&p.lock)
            .unwrap();
        let mut overlapped: win_lock::Overlapped = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            win_lock::LockFileEx(
                holder.as_raw_handle() as *mut std::ffi::c_void,
                win_lock::LOCKFILE_EXCLUSIVE_LOCK | win_lock::LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        assert_ne!(rc, 0);
        let start = std::time::Instant::now();
        let err = match acquire_lock_timeout(&p.lock, std::time::Duration::from_millis(150)) {
            Err(e) => e,
            Ok(_) => panic!("lock acquisition should have timed out"),
        };
        assert!(err.contains("ledger lock busy"), "{}", err);
        assert!(start.elapsed() >= std::time::Duration::from_millis(140));
        drop(holder);
        let _g = acquire_lock_timeout(&p.lock, std::time::Duration::from_millis(150)).unwrap();
    }

    #[test]
    fn stale_tmp_files_are_cleaned_on_save() {
        let (_t, p) = test_env();
        let stale = p.state.with_extension("json.tmp.99999");
        std::fs::write(&stale, "garbage").unwrap();
        assert!(stale.exists());
        complete_task(&p, 1, "x", &[]).unwrap();
        assert!(!stale.exists(), "stale tmp must be removed by save_state_atomic");
        // The live state file is untouched.
        assert!(p.state.exists());
    }

    #[test]
    fn events_size_cap_rejects_oversized_log() {
        let (_t, p) = test_env();
        // Grow the events file past the 16 MiB cap.
        let mut f = OpenOptions::new().create(true).append(true).open(&p.events).unwrap();
        f.write_all(&vec![b'x'; (MAX_EVENTS_FILE_BYTES as usize) + 1]).unwrap();
        drop(f);
        let err = rebuild_state(&p).unwrap_err();
        assert!(err.contains("too large"), "{}", err);
    }

    #[test]
    fn invariants_check_passes_and_detects_gaps() {
        let (_t, p) = test_env();
        let r = assert_ledger_invariants(&p.ledger).unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["total_tasks"], json!(10));
        // Break the ledger: rewrite task 3 with a corrupted depends_on.
        let content = std::fs::read_to_string(&p.ledger).unwrap();
        let bad: String = content
            .lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                if v.get("id").and_then(|x| x.as_u64()) == Some(3) {
                    let mut m = v.as_object().unwrap().clone();
                    m.insert("depends_on".into(), json!([9]));
                    serde_json::to_string(&Value::Object(m)).unwrap()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&p.ledger, bad).unwrap();
        let r = assert_ledger_invariants(&p.ledger).unwrap();
        assert_eq!(r["ok"], json!(false));
    }
}
