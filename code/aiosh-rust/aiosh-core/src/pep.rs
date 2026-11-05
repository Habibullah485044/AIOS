//! PEP (Policy Enforcement Point) grant tokens.
//!
//! Port of `code/aiosh-cli/src/pep.ts` + the Python grant helpers in
//! `audit_client.py`. Grants live in their own table in the audit WAL
//! database; grant creation/revocation are themselves audit rows.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;

use crate::canonical::{canonical, sha256_hex};
use crate::types::{GrantScope, PathScope};

/// Match a tool name against a scope-tools glob, e.g. "pentest.nmap"
/// against ["pentest.*"] → true.
pub fn tool_glob_match(tool: &str, globs: &[String]) -> bool {
    if globs.is_empty() {
        return false;
    }
    for glob in globs {
        if glob == tool {
            return true;
        }
        // "git.*" covers "git" and "git.x", never "github.delete_repo" or "git_x": the match must end
        // on a dot boundary, as in Python `audit_client.tool_glob_match` and TS `toolGlobMatch`
        // (security audit 2026-11-05 #3a; Rust found unfixed in T-03363 research).
        if let Some(prefix) = glob.strip_suffix(".*") {
            if tool == prefix || tool.starts_with(&glob[..glob.len() - 1]) {
                return true;
            }
        }
    }
    false
}

/// Lexically normalize path to collapse redundant slashes and `.` / `..` traversal components.
///
/// A **relative** path that collapses to nothing (`.`, `./`, `a/..`) names the current
/// directory, and is returned as `.` — never as the empty string. The empty string is not a
/// usable key: as a `scope.paths` entry it made the containment test
/// `key_target.starts_with("/")`, which every absolute POSIX key satisfies, so a `.` entry
/// authorized the whole filesystem — while on Windows the same entry matched nothing at all
/// and refused its own directory (T-01539 §6.21).
///
/// A leading `..` is likewise kept rather than dropped: with nothing above it to cancel, it
/// names the real parent directory, and quietly resolving it to the current directory would
/// let `deny: [".."]` miss the parent entirely.
pub fn normalize_path_str(p: &str) -> String {
    let p_clean = p.replace('\\', "/");
    let is_abs = p_clean.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p_clean.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            // `..` cancels the last real component; with none left (or only other `..`s)
            // there is nothing above it to cancel, so on a relative path it survives.
            if matches!(parts.last(), Some(&last) if last != "..") {
                parts.pop();
            } else if !is_abs {
                parts.push("..");
            }
            continue;
        }
        parts.push(seg);
    }
    let joined = parts.join("/");
    if is_abs {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Attempts `resolve_existing_prefix` will make before keying a path lexically.
/// Each attempt is one `canonicalize` that fails fast once the path stops existing, so
/// this only bounds the work a hostile, very deep path can ask for.
const MAX_CANONICAL_ASCENTS: usize = 64;

/// Canonical, comparable form of a path for `scope.paths` matching.
///
/// The allow/deny lists are strings, so a deny entry only survives contact with an
/// adversary if both sides are first reduced to the form the **filesystem** resolves them
/// to. Otherwise one directory can be spelled several ways and the denied spelling loses
/// (T-01537 S-18/S-19):
///
/// * **case** — a case-insensitive filesystem has one `C:\Secret`, not two;
/// * **8.3 short names** — `C:\PROGRA~1` *is* `C:\Program Files`;
/// * **trailing dots/spaces** — Windows drops them from a component;
/// * **symlinks/junctions** — a link to a denied directory is that directory;
/// * **device/extended prefixes** — `\\?\C:\Secret\x` and `C:\Secret\x` are one file.
///
/// The longest **existing** prefix is therefore resolved through the filesystem, and only
/// the tail that does not exist yet is kept lexically — and that tail is the normal case,
/// because a `store_path` usually names a file that is about to be created. Case folding
/// and dot/space stripping are applied **only** where the platform aliases them: POSIX
/// paths stay case- and space-sensitive, so no legitimate Linux or macOS name is refused
/// on Windows' account.
///
/// Deliberately stricter than the write path in one place: trailing dots/spaces are
/// stripped from *every* component, including intermediate ones Windows would treat as
/// distinct names, and a component that is nothing but dots or spaces is dropped outright
/// (see [`fold_windows_component_aliases`]). Over-matching a deny entry fails closed, which
/// is the safe direction; the traversal components `.` and `..` are exempt, because they are
/// not names.
///
/// One consequence of keying the way the filesystem resolves a path: a relative spelling
/// keys to the absolute location it resolves to, so an entry and an argument no longer have
/// to be spelled in the same frame (`demo` vs `demo/store.json` vs an absolute path under
/// either) to compare equal. A spelling that collapses to nothing keys to the working
/// directory, never to the empty string — an empty key is not a path, and as a policy entry
/// it would cover the whole filesystem on POSIX (T-01539 §6.21).
///
/// Returns `None` when the spelling cannot be mapped into the filesystem namespace at all
/// (see [`strip_device_prefix`]); callers must treat that as **denied**, never as "no
/// entry matched".
pub fn canonical_path_key(p: &str) -> Option<String> {
    let stripped = strip_device_prefix(p)?;
    #[cfg(windows)]
    let stripped = fold_windows_component_aliases(&stripped);
    let key = normalize_path_str(&stripped);
    let key = anchor_relative_key(key);
    let key = resolve_existing_prefix(&key);
    #[cfg(windows)]
    {
        return Some(key.to_lowercase());
    }
    #[cfg(not(windows))]
    Some(key)
}

/// Anchor a key that does not name a location on its own to the working directory.
///
/// The OS resolves a relative spelling against the process working directory, so
/// `store.json` and `<working directory>/store.json` are one file and must key alike. Without
/// this, a `.` entry keys to the working directory while a relative argument stays relative,
/// and the entry refuses the very files it names — the frames-must-match trap.
///
/// Drive-relative spellings (`C:store.json`) are deliberately left alone: Windows resolves
/// those against the current directory *of that drive*, which is not the working directory in
/// general, and anchoring them here would name a location the caller never meant.
///
/// The working directory is only consulted for a relative spelling, and if it cannot be read
/// at all the key is left relative (and so matched only by an equally relative entry) — the
/// pre-existing fail-closed behaviour.
fn anchor_relative_key(key: String) -> String {
    if is_self_contained_key(&key) {
        return key;
    }
    match std::env::current_dir() {
        Ok(dir) => normalize_path_str(&format!("{}/{}", dir.to_string_lossy(), key)),
        Err(_) => key,
    }
}

/// True when a normalized key names its location without help: root-relative (`/x`) or
/// drive-prefixed (`C:/x`, `C:x`). A bare relative key (`x`, `.`, `..`) is not self-contained;
/// see [`anchor_relative_key`].
fn is_self_contained_key(key: &str) -> bool {
    let b = key.as_bytes();
    if matches!(b.first(), Some(b'/') | Some(b'\\')) {
        return true;
    }
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Fold the component aliases Windows itself folds, so two spellings of one name key alike:
/// a component's trailing dots and spaces are not part of its name (`DenyDir. ` is
/// `DenyDir`). Case folding is applied later, to the whole resolved key.
///
/// Two kinds of component are deliberately left alone:
///
/// * `.` and `..` are traversal components, not names. Folding them turned `.` into the
///   empty key — the T-01539 §6.21 defect — and would turn `..`, the parent, into the
///   current directory.
/// * a component that is nothing *but* dots or spaces names nothing at all, so it is
///   **dropped** rather than kept as an empty segment. Keeping it injected a doubled
///   separator into the key (`a/.../b` stopped keying like `a/b`), so the padded spelling of
///   a denied location walked past the deny entry — the spelling-evasion class T-01537
///   S-22/S-23 closed. Dropping is the fail-closed direction: the key collapses onto the
///   location the filesystem would have resolved, so it can only match *more* deny entries.
#[cfg(windows)]
fn fold_windows_component_aliases(p: &str) -> String {
    let slashed = p.replace('\\', "/");
    let (prefix, rest) = match slashed.strip_prefix('/') {
        Some(rest) => ("/", rest),
        None => ("", slashed.as_str()),
    };
    let folded: Vec<&str> = rest
        .split('/')
        .filter_map(|seg| {
            if seg == "." || seg == ".." {
                return Some(seg);
            }
            let trimmed = seg.trim_end_matches(['.', ' ']);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect();
    format!("{}{}", prefix, folded.join("/"))
}

/// Canonical key for the **physical destination** a layout-store staged file belongs to.
/// Re-exported at the crate root as `fs_layout_service_key` so the residue cap and the
/// policy matcher share one implementation of "what is this path's physical identity".
/// shared with `fs_layout_service::staged_siblings` so one destination has one residue
/// budget however it is spelled (the T-01539 adversarial finding: case variants, 8.3 short
/// names, trailing dot/space and a nesting prefix pooled 32 staged files around one
/// destination under an 8-file cap). Deliberately *not* anchored: a staged file may name a
/// destination that does not exist yet, where working-directory anchoring would be a guess,
/// and callers always pass absolute paths from a directory listing. [`canonical_path_key`]
/// stays anchored for policy matching; this is the un-anchored core of it.
///
/// The empty key cannot occur (a spelling that collapses to nothing returns `.`), and a
/// `None` (unmappable device path) is "count nothing", which fails closed.
pub fn canonical_store_key(p: &Path) -> Option<String> {
    canonical_key_unanchored(&p.to_string_lossy())
}

/// Recover the implied original destination of one `.<name>.tmp.<pid>.<nanos>.<n>` staged
/// file, as a canonical key in `dir`. The staged-name shape is owned by
/// `fs_layout_service::create_exclusive_temp`; this is its exact inverse, so a nested
/// spelling is not misattributed: the last three dot-separated fields must be numeric
/// (pid, nanos, attempt), the field before them must be the `tmp` marker, and everything
/// before that is the destination's own name - dots included (`s.json` staged for one
/// destination and `s.json.tmp` staged for another parse to two different destinations).
/// Names not of the staged shape yield `None` and are ignored.
pub fn staged_file_destination(staged_name: &str, dir: &Path) -> Option<String> {
    let body = staged_name.strip_prefix('.')?;
    let comps: Vec<&str> = body.split('.').collect();
    if comps.len() < 5 {
        return None;
    }
    let numeric =
        |c: &&str| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit());
    if !comps[comps.len() - 3..].iter().all(numeric) {
        return None;
    }
    let before = &comps[..comps.len() - 3];
    if *before.last()? != "tmp" {
        return None;
    }
    let stem_comps = &before[..before.len() - 1];
    if stem_comps.is_empty() {
        return None;
    }
    canonical_key_unanchored(&dir.join(stem_comps.join(".")).to_string_lossy())
}

/// [`canonical_path_key`] without [`anchor_relative_key`]: policy matching anchors a
/// relative spelling to the working directory because the OS resolves it there; residue
/// accounting does not, because a staged file's destination is passed absolute from a
/// directory listing and a nonexistent destination has no location to anchor to.
fn canonical_key_unanchored(p: &str) -> Option<String> {
    let stripped = strip_device_prefix(p)?;
    #[cfg(windows)]
    let stripped = fold_windows_component_aliases(&stripped);
    let key = normalize_path_str(&stripped);
    let key = resolve_existing_prefix(&key);
    #[cfg(windows)]
    {
        return Some(key.to_lowercase());
    }
    #[cfg(not(windows))]
    Some(key)
}

/// The device/extended-length prefixes a caller may supply, longest first, all lowercase
/// because the input is lowercased before matching. Windows accepts `/` and `\`
/// interchangeably in each, so both spellings are listed.
const DEVICE_PREFIXES: [&str; 8] = [
    "\\\\?\\unc\\",
    "\\\\.\\unc\\",
    "//?/unc/",
    "//./unc/",
    "\\\\?\\",
    "\\\\.\\",
    "//?/",
    "//./",
];

/// Reduce a caller-supplied device/extended-length spelling to its ordinary form.
///
/// `std::fs::canonicalize` *returns* `\\?\`-prefixed paths and [`canonical_to_key`] strips
/// that prefix from its **output** — but nothing stripped the mirror-image prefix a
/// **caller** could *supply*. `\\?\C:\DenyDir\x.json` therefore normalized to
/// `/?/C:/DenyDir/x.json`, which can never resolve, so the lexical fallback in
/// [`resolve_existing_prefix`] compared that mangled key against the *resolved* key of a
/// real deny entry, failed to match, and authorized the call — which then wrote into the
/// denied directory (T-01537 S-22/S-23). Stripping the prefix on input puts both
/// spellings in one namespace, so `\\?\C:\d\x`, `\\.\C:\d\x`, `\\?\UNC\s\sh\x` and
/// the plain `C:\d\x` / `\\s\sh\x` all key alike, matching the only namespace
/// `std::fs::canonicalize` knows.
///
/// Returns `None` for a path that is *still* in the device namespace once the prefixes are
/// gone — `\\.\PhysicalDrive0`, `\\.\GLOBALROOT\Device\HarddiskVolume2\x`,
/// `\\?\PIPE\name`. Those name no location a `scope.paths` entry could ever describe, so
/// leaving them to fall through as an unmatchable key is exactly the fail-open this closes.
/// A path that never had a device prefix is passed through unchanged, including a relative
/// one, whose existing lexical behaviour is deliberate.
fn strip_device_prefix(p: &str) -> Option<String> {
    let mut current = p.to_string();
    let mut stripped = false;
    // Loop because the prefixes stack (`\\?\\\?\C:\x`): each pass shortens the string, so
    // this terminates, and a single blind strip would leave the inner one to mangle the key.
    loop {
        let lower = current.to_ascii_lowercase();
        let Some(prefix) = DEVICE_PREFIXES.iter().find(|pre| lower.starts_with(**pre)) else {
            break;
        };
        let rest = current[prefix.len()..].to_string();
        let rest_lower = rest.to_ascii_lowercase();
        // `\\?\UNC\server\share\...` is the extended spelling of `\\server\share\...`.
        current = if rest_lower.starts_with("unc/") || rest_lower.starts_with("unc\\") {
            format!("\\\\{}", &rest[4..])
        } else {
            rest
        };
        stripped = true;
    }
    if stripped && !is_filesystem_addressable(&current) {
        return None;
    }
    Some(current)
}

/// True when a stripped path still names something in the filesystem namespace rather than
/// in the device namespace: absolute (`\dir` or `/dir`), or drive-absolute (`C:\dir`).
/// A bare device name (`PhysicalDrive0`), a `GLOBALROOT` escape or a pipe is not.
fn is_filesystem_addressable(p: &str) -> bool {
    let b = p.as_bytes();
    if matches!(b.first(), Some(b'/') | Some(b'\\')) {
        return true;
    }
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\')
}

/// Replace the longest existing prefix of an already separator-normalized path with its
/// filesystem-resolved form, re-appending the non-existent tail. Returns the input
/// unchanged when nothing along the path resolves (which is why a purely lexical
/// comparison still holds for paths that do not exist yet on either side).
fn resolve_existing_prefix(normalized: &str) -> String {
    let mut tail: Vec<String> = Vec::new();
    let mut head = normalized.to_string();
    for _ in 0..MAX_CANONICAL_ASCENTS {
        if let Ok(real) = std::fs::canonicalize(&head) {
            let mut out = canonical_to_key(&real.to_string_lossy());
            for seg in tail.iter().rev() {
                if !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(seg);
            }
            return out;
        }
        // Ascend one component, but never above a root or a drive prefix: `C:` alone
        // means "current directory on C:", which is not the same place as `C:\`.
        match head.rfind('/') {
            Some(i) if i > 0 && !head[..i].ends_with(':') => {
                tail.push(head[i + 1..].to_string());
                head.truncate(i);
            }
            _ => break,
        }
    }
    normalized.to_string()
}

/// Strip the extended-length prefix `std::fs::canonicalize` returns on Windows and
/// normalize separators, so keys from resolved and unresolved paths stay comparable.
fn canonical_to_key(real: &str) -> String {
    let s = real.replace('\\', "/");
    if let Some(rest) = s.strip_prefix("//?/UNC/") {
        format!("//{rest}")
    } else if let Some(rest) = s.strip_prefix("//?/") {
        rest.to_string()
    } else {
        s
    }
}

/// Path-based allow/deny check. Deny always wins.
///
/// Comparison happens on [`canonical_path_key`], so spelling the same location differently
/// (case, 8.3 short name, trailing dot/space, symlink) cannot move it across a deny entry.
pub fn path_allowed(target: Option<&str>, paths: &PathScope) -> bool {
    if paths.allow.is_empty() && paths.deny.is_empty() {
        return true;
    }
    let target = match target {
        Some(t) => t,
        None => return false,
    };
    // An unmappable spelling names no location a `scope.paths` entry could describe, so it
    // cannot be shown to sit inside an allowed directory: fail closed (T-01537 S-22).
    let key_target = match canonical_path_key(target) {
        Some(k) => k,
        None => return false,
    };
    for p in &paths.deny {
        let key_p = match canonical_path_key(p) {
            Some(k) => k,
            None => continue,
        };
        if key_covers_target(&key_target, &key_p) {
            return false;
        }
    }
    if paths.allow.is_empty() {
        // Deny-only policy: any non-denied target is allowed.
        return true;
    }
    for p in &paths.allow {
        let key_p = match canonical_path_key(p) {
            Some(k) => k,
            None => continue,
        };
        if key_covers_target(&key_target, &key_p) {
            return true;
        }
    }
    false
}

/// Does one `scope.paths` entry key cover a target key — that is, is the target the entry's
/// own directory, or something below it?
///
/// An empty key covers **nothing**, in either direction. That is the second half of the
/// T-01539 §6.21 defect: containment on an empty entry degenerates to
/// `key_target.starts_with("/")`, which on POSIX every absolute key satisfies, so one `.`
/// entry authorized the whole filesystem. [`canonical_path_key`] no longer produces an empty
/// key; this keeps the wildcard unreachable even if some future spelling does.
fn key_covers_target(key_target: &str, key_entry: &str) -> bool {
    if key_target.is_empty() || key_entry.is_empty() {
        return false;
    }
    key_target == key_entry
        || key_target.starts_with(&format!("{}/", key_entry.trim_end_matches('/')))
}

/// CIDR-aware network scope check. Hostname entries are exact-match.
pub fn network_allowed(target: Option<&str>, networks: &[String]) -> bool {
    if networks.is_empty() {
        return true;
    }
    let target = match target {
        Some(t) => t,
        None => return false,
    };
    // Try parsing as IP address.
    if let Ok(addr) = target.parse::<std::net::IpAddr>() {
        for item in networks {
            if let Ok(net) = item.parse::<ipnet::IpNet>() {
                if net.contains(&addr) {
                    return true;
                }
            } else if target == item {
                return true;
            }
        }
        return false;
    }
    // Hostname: exact match only.
    networks.iter().any(|n| n == target)
}

pub fn is_irreversible(tool: &str) -> bool {
    // Read-only reconnaissance and discovery tools are reversible / non-destructive
    if tool == "pentest.network.interfaces"
        || tool == "pentest.wifi.scan"
        || tool == "pentest.arp.scan"
        || tool == "pentest.tshark"
        || tool.starts_with("network.")
        || tool.starts_with("wifi.scan")
        || tool.starts_with("aios.network.")
        || tool.starts_with("aios.wifi.scan")
    {
        return false;
    }

    tool.starts_with("fs.write")
        || tool.starts_with("pentest.")
        || tool.starts_with("aios.backup.")
        || tool.starts_with("aios.release.")
        || tool.starts_with("aios.toolchain.set")
        || tool.starts_with("toolchain.set")
        || tool.starts_with("aios.doc.set")
        || tool.starts_with("doc.set")
        || tool.starts_with("aios.evidence.record")
        || tool.starts_with("evidence.record")
        || tool.starts_with("aios.evidence.set")
        || tool.starts_with("evidence.set")
        || tool.starts_with("aios.session.action")
        || tool.starts_with("session.action")
        || tool.starts_with("aios.session.create")
        || tool.starts_with("session.create")
        // T-01537 S-3: the four state-changing Filesystem Layout tools persist to a
        // caller-named store, so they belong to the irreversible family. They were
        // reachable *only* because every call site also passes `require_grant = true`;
        // listing them here makes the PEP itself refuse an unauthenticated mutation
        // instead of depending on each caller remembering the flag. The read-only
        // `aios.fs_layout.*` tools stay reversible, so they are matched exactly.
        || tool == "aios.fs_layout.register"
        || tool == "aios.fs_layout.set_active"
        || tool == "aios.fs_layout.remove"
        || tool == "aios.fs_layout.import_fstab"
        || tool == "system.reboot"
        || tool == "system.shutdown"
}

#[derive(Debug, Clone)]
pub struct PepGrant {
    pub grant_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub issued_to: String,
    pub constitution_rev: String,
    pub scope: GrantScope,
}

pub struct PepStore {
    conn: Connection,
}

impl PepStore {
    pub fn new(conn: Connection) -> rusqlite::Result<Self> {
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn init(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(crate::audit::PEP_SCHEMA)?;
        Ok(())
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn create(
        &self,
        scope: &GrantScope,
        ttl_seconds: i64,
        issued_to: &str,
        constitution_rev: &str,
    ) -> rusqlite::Result<PepGrant> {
        let ttl = if ttl_seconds <= 0 { 3600 } else { ttl_seconds };
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(ttl);
        let grant_id = format!("gr_{}", random_hex(8)?);
        let scope_json = serde_json::to_string(scope).unwrap_or_else(|_| "{}".into());
        let scope_hash = sha256_hex(&canonical(&scope_to_json(scope)));

        self.conn.execute(
            r#"INSERT INTO pep_grants
               (grant_id, issued_at, expires_at, issued_to,
                constitution_rev, scope_json, scope_hash)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                grant_id,
                now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
                expires.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
                issued_to,
                constitution_rev,
                scope_json,
                scope_hash,
            ],
        )?;
        Ok(PepGrant {
            grant_id,
            issued_at: now.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            expires_at: expires.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            issued_to: issued_to.into(),
            constitution_rev: constitution_rev.into(),
            scope: scope.clone(),
        })
    }

    pub fn revoke(&self, grant_id: &str) -> rusqlite::Result<bool> {
        let n = self
            .conn
            .execute(
                "UPDATE pep_grants SET revoked_at = ?1 WHERE grant_id = ?2 AND revoked_at IS NULL",
                params![Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(), grant_id],
            )?;
        Ok(n > 0)
    }

    pub fn get(&self, grant_id: &str) -> rusqlite::Result<Option<PepGrant>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM pep_grants WHERE grant_id = ?1",
                params![grant_id],
                |r| {
                    Ok((
                        r.get::<_, String>("grant_id")?,
                        r.get::<_, String>("issued_at")?,
                        r.get::<_, String>("expires_at")?,
                        r.get::<_, String>("issued_to")?,
                        r.get::<_, String>("constitution_rev")?,
                        r.get::<_, String>("scope_json")?,
                        r.get::<_, Option<String>>("revoked_at")?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, issued, expires, to, con_rev, scope_json, revoked)) => {
                if revoked.is_some() {
                    return Ok(None);
                }
                let scope: GrantScope =
                    serde_json::from_str(&scope_json).unwrap_or_default();
                Ok(Some(PepGrant {
                    grant_id: id,
                    issued_at: issued,
                    expires_at: expires,
                    issued_to: to,
                    constitution_rev: con_rev,
                    scope,
                }))
            }
        }
    }

    pub fn list(&self, active_only: bool) -> rusqlite::Result<Vec<PepGrant>> {
        let sql = if active_only {
            "SELECT * FROM pep_grants WHERE revoked_at IS NULL ORDER BY issued_at DESC"
        } else {
            "SELECT * FROM pep_grants ORDER BY issued_at DESC"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>("grant_id")?,
                    r.get::<_, String>("issued_at")?,
                    r.get::<_, String>("expires_at")?,
                    r.get::<_, String>("issued_to")?,
                    r.get::<_, String>("constitution_rev")?,
                    r.get::<_, String>("scope_json")?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .map(|(id, issued, expires, to, con_rev, scope_json)| PepGrant {
                grant_id: id,
                issued_at: issued,
                expires_at: expires,
                issued_to: to,
                constitution_rev: con_rev,
                scope: serde_json::from_str(&scope_json).unwrap_or_default(),
            })
            .collect())
    }

    /// Authoritative gate. Returns Ok(()) or Err(reason).
    ///
    /// [`check`](Self::check) for the common case where the call touches no
    /// filesystem path of its own. See [`check_with_paths`](Self::check_with_paths)
    /// for why that distinction exists.
    pub fn check(
        &self,
        grant_id: Option<&str>,
        tool: &str,
        target: Option<&str>,
    ) -> Result<(), String> {
        self.check_with_paths(grant_id, tool, target, &[])
    }

    /// Authoritative gate, extended with the **filesystem paths the call will
    /// actually touch** (T-01537 S-1).
    ///
    /// `target` is the value the audit rows are attributed to, and for tools whose
    /// operated-on object *is* a path (e.g. `pentest.aircrack-ng --capture`) it is
    /// also what `scope.paths` governs. That conflates two different things, and the
    /// `fs_layout` mutation surface is where the conflation bites: its audit target is
    /// a layout **id** (spec §9), so a `scope.paths` allow-list could never constrain
    /// the layout **store file** the call writes — and for `register`'s `spec` form the
    /// target is `None`, which skipped the path check entirely, so the same grant
    /// refused the inline form and silently authorized the spec form.
    ///
    /// `path_subjects` therefore carries the paths that identify themselves, and the
    /// rule is deliberately either/or: **if a call declares subjects, `scope.paths`
    /// governs those and `target` is treated as an attribution label, not a path.** A
    /// call that declares none keeps the historical reading of `target` unchanged. The
    /// alternative — checking both — is incoherent, because an opaque id such as
    /// `aios-uefi-standard-v1` can never be inside a directory allow-list, so a
    /// path-scoped grant would refuse `set_active`/`remove`/`import_fstab` no matter how
    /// correct their store path was. A grant with no `scope.paths` set is unaffected
    /// either way, because `path_allowed` treats an empty allow+deny list as
    /// unrestricted.
    pub fn check_with_paths(
        &self,
        grant_id: Option<&str>,
        tool: &str,
        target: Option<&str>,
        path_subjects: &[&str],
    ) -> Result<(), String> {
        match grant_id {
            None => {
                if is_irreversible(tool) {
                    Err(format!(
                        "irreversible tool '{}' requires explicit PEP grant",
                        tool
                    ))
                } else {
                    Ok(())
                }
            }
            Some(id) => {
                let g = self
                    .get(id)
                    .map_err(|e| format!("grant lookup failed: {}", e))?
                    .ok_or_else(|| format!("unknown or revoked grant: {}", id))?;
                // Expiry — fail CLOSED: a malformed timestamp refuses the
                // grant rather than silently treating it as unexpired.
                let now = Utc::now();
                let expires =
                    chrono::DateTime::parse_from_rfc3339(&g.expires_at)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|_| ())
                        .and_then(|d| if d < now { Err(()) } else { Ok(d) });
                match expires {
                    Err(()) => {
                        return Err(format!(
                            "grant {} expired or has malformed expires_at",
                            id
                        ))
                    }
                    Ok(_) => {}
                }
                // Tool scope.
                if !tool_glob_match(tool, &g.scope.tools) {
                    return Err(format!(
                        "tool '{}' not in grant scope.tools={}",
                        tool,
                        serde_json::to_string(&g.scope.tools).unwrap_or_default()
                    ));
                }
                // Network targets use scope.networks; paths otherwise.
                let is_network_target = tool.starts_with("pentest.") || tool.starts_with("network.");
                if target.is_some() && is_network_target && !g.scope.networks.is_empty() {
                    if !network_allowed(target, &g.scope.networks) {
                        return Err(format!(
                            "target '{}' blocked by grant scope.networks",
                            target.unwrap()
                        ));
                    }
                } else if target.is_some()
                    && path_subjects.is_empty()
                    && !path_allowed(target, &g.scope.paths)
                {
                    return Err(format!(
                        "target '{}' blocked by grant scope.paths",
                        target.unwrap()
                    ));
                }
                // The paths this call will really write or read. Checked even when
                // `target` is `None` (register's `spec` form), which is exactly the
                // hole this closes.
                for subject in path_subjects {
                    if !path_allowed(Some(subject), &g.scope.paths) {
                        return Err(format!(
                            "path subject '{}' blocked by grant scope.paths",
                            subject
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

fn scope_to_json(scope: &GrantScope) -> Value {
    serde_json::json!({
        "tools": scope.tools,
        "networks": scope.networks,
        "paths": {
            "allow": scope.paths.allow,
            "deny": scope.paths.deny,
        },
        "max_irreversible": scope.max_irreversible,
    })
}

/// Random hex string of `bytes` bytes (16 hex chars for gr_ ids).
///
/// Grant ids are bearer tokens authorizing irreversible actions — they
/// MUST come from the OS CSPRNG, never from a userspace PRNG seeded
/// with time/addresses.
fn random_hex(bytes: usize) -> Result<String, rusqlite::Error> {
    let mut buf = vec![0u8; bytes];
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                e.kind(),
                format!("grant id entropy unavailable (/dev/urandom): {e}"),
            )))
        })?;
        f.read_exact(&mut buf).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                e.kind(),
                format!("grant id entropy read failed: {e}"),
            )))
        })?;
    }
    #[cfg(not(unix))]
    {
        // OS CSPRNG via SQLite's underlying CryptGenRandom / BCryptGenRandom implementation
        unsafe {
            rusqlite::ffi::sqlite3_randomness(
                bytes as libc::c_int,
                buf.as_mut_ptr() as *mut libc::c_void,
            );
        }
    }
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn store() -> PepStore {
        PepStore::new(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn scope(tools: &[&str]) -> GrantScope {
        GrantScope {
            tools: tools.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn create_get_revoke() {
        let s = store();
        let g = s
            .create(&scope(&["pentest.*"]), 3600, "agent:test", "abc123")
            .unwrap();
        assert!(g.grant_id.starts_with("gr_"));
        assert!(s.get(&g.grant_id).unwrap().is_some());
        assert!(s.revoke(&g.grant_id).unwrap());
        assert!(s.get(&g.grant_id).unwrap().is_none());
    }

    #[test]
    fn check_requires_grant_for_pentest() {
        let s = store();
        let r = s.check(None, "pentest.nmap", Some("10.0.0.5"));
        assert!(r.is_err());
        let r = s.check(None, "aios.audit.tail", None);
        assert!(r.is_ok());
    }

    #[test]
    fn check_enforces_tool_scope() {
        let s = store();
        let g = s
            .create(&scope(&["pentest.nmap"]), 3600, "agent:test", "abc123")
            .unwrap();
        assert!(s.check(Some(&g.grant_id), "pentest.nmap", Some("10.0.0.5")).is_ok());
        assert!(s.check(Some(&g.grant_id), "pentest.nikto", Some("10.0.0.5")).is_err());
    }

    #[test]
    fn check_enforces_network_scope() {
        let s = store();
        let mut sc = scope(&["pentest.*"]);
        sc.networks = vec!["10.0.0.0/8".into()];
        let g = s.create(&sc, 3600, "agent:test", "abc123").unwrap();
        assert!(s.check(Some(&g.grant_id), "pentest.nmap", Some("10.1.2.3")).is_ok());
        assert!(s.check(Some(&g.grant_id), "pentest.nmap", Some("192.168.1.1")).is_err());
        assert!(s.check(Some(&g.grant_id), "pentest.nmap", Some("shodan.io")).is_err());
    }

    #[test]
    fn check_enforces_paths() {
        let s = store();
        let mut sc = scope(&["pentest.aircrack-ng"]);
        sc.paths.allow = vec!["/tmp/captures".into()];
        let g = s.create(&sc, 3600, "agent:test", "abc123").unwrap();
        assert!(s
            .check(Some(&g.grant_id), "pentest.aircrack-ng", Some("/tmp/captures/a.pcap"))
            .is_ok());
        assert!(s
            .check(Some(&g.grant_id), "pentest.aircrack-ng", Some("/etc/passwd"))
            .is_err());
    }

    // ---- T-01537 S-1: path subjects are checked, not just the audit target ----

    fn fs_layout_grant(paths: PathScope) -> (PepStore, String) {
        let s = store();
        let sc = GrantScope {
            tools: vec!["aios.fs_layout.*".into()],
            paths,
            ..Default::default()
        };
        let g = s.create(&sc, 3600, "agent:test", "abc123").unwrap();
        (s, g.grant_id)
    }

    #[test]
    fn path_subjects_are_blocked_outside_allow_list() {
        let (s, gid) = fs_layout_grant(PathScope {
            allow: vec!["/srv/layouts".into()],
            deny: vec![],
        });
        // The write target of a mutation is a policy subject.
        assert!(s
            .check_with_paths(
                Some(&gid),
                "aios.fs_layout.register",
                None,
                &["/srv/layouts/store.json"]
            )
            .is_ok());
        assert!(s
            .check_with_paths(
                Some(&gid),
                "aios.fs_layout.register",
                None,
                &["/etc/evil.json"]
            )
            .is_err());
        // A denied subject wins even when an allowed sibling is present.
        assert!(s
            .check_with_paths(
                Some(&gid),
                "aios.fs_layout.import_fstab",
                Some("layout-id"),
                &["/srv/layouts/store.json", "/root/secrets.json"]
            )
            .is_err());
        // With subjects declared, those govern: an in-scope store is allowed even
        // though the audit target is a layout id that is not a path. Checking both
        // would make every path-scoped grant unusable for this surface.
        assert!(s
            .check_with_paths(
                Some(&gid),
                "aios.fs_layout.set_active",
                Some("aios-uefi-standard-v1"),
                &["/srv/layouts/store.json"]
            )
            .is_ok());
        // Documented pre-fix hole, pinned so it cannot silently return: with no
        // subjects and a `None` target the path check is skipped entirely.
        assert!(s
            .check_with_paths(Some(&gid), "aios.fs_layout.register", None, &[])
            .is_ok());
    }

    #[test]
    fn path_subjects_leave_unscoped_grants_alone() {
        let (s, gid) = fs_layout_grant(PathScope::default());
        assert!(s
            .check_with_paths(
                Some(&gid),
                "aios.fs_layout.register",
                None,
                &["/anywhere/at/all/store.json"]
            )
            .is_ok());
        // The legacy 3-arg entry point keeps its exact behaviour.
        assert!(s.check(Some(&gid), "aios.fs_layout.register", None).is_ok());
    }

    // ---- T-01537 S-3: fs_layout mutations are irreversible to the PEP itself ----

    #[test]
    fn fs_layout_mutations_require_a_grant_without_the_call_site_flag() {
        let s = store();
        for tool in [
            "aios.fs_layout.register",
            "aios.fs_layout.set_active",
            "aios.fs_layout.remove",
            "aios.fs_layout.import_fstab",
        ] {
            assert!(
                s.check(None, tool, None).is_err(),
                "{} must be irreversible",
                tool
            );
        }
        // Read-only siblings stay ungated.
        for tool in [
            "aios.fs_layout.get",
            "aios.fs_layout.list",
            "aios.fs_layout.validate",
            "aios.fs_layout.fstab",
            "aios.fs_layout.probe",
            "aios.fs_layout.diff",
        ] {
            assert!(
                s.check(None, tool, None).is_ok(),
                "{} must stay reversible",
                tool
            );
        }
    }

    // ---- T-01537 S-18/S-19: scope.paths matching is canonical, not lexical ----

    #[test]
    fn path_keys_fold_platform_aliases() {
        // Spellings the filesystem treats as one directory must not slip past a deny
        // entry. These paths do not exist, so both sides stay lexical and the assertions
        // are deterministic on any machine.
        #[cfg(windows)]
        {
            let deny_only = PathScope {
                allow: vec![],
                deny: vec![r"C:\DenyDir".into()],
            };
            assert!(
                !path_allowed(Some(r"c:\denydir\x.json"), &deny_only),
                "case alias must still match the deny entry"
            );
            assert!(
                !path_allowed(Some(r"C:\DenyDir. \x.json"), &deny_only),
                "trailing dot/space alias must still match the deny entry"
            );
            assert!(!path_allowed(Some(r"C:\DenyDir\sub\..\x.json"), &deny_only));
            // And the allow list agrees, so a scoped grant is not refused for spelling
            // its own directory in a different case (the fail-closed half of the bug).
            let allow_only = PathScope {
                allow: vec![r"C:\AllowedDir".into()],
                deny: vec![],
            };
            assert!(path_allowed(Some(r"c:\alloweddir\store.json"), &allow_only));
        }
        #[cfg(not(windows))]
        {
            // POSIX names are case- and space-sensitive: those are different files, and
            // Windows' aliasing must not leak into POSIX policy decisions.
            assert!(path_allowed(
                Some("/DenyDir/x.json"),
                &PathScope { allow: vec![], deny: vec!["/denydir".into()] }
            ));
            assert!(path_allowed(
                Some("/DenyDir /x.json"),
                &PathScope { allow: vec![], deny: vec!["/DenyDir".into()] }
            ));
        }
    }

    #[test]
    fn path_keys_resolve_an_existing_prefix() {
        // 8.3 short names and symlinks can only be expanded by asking the filesystem, so
        // the key for a not-yet-existing tail must be built from the *resolved* form of
        // its longest existing prefix. That single property is what stops a short-name
        // spelling from escaping a deny entry.
        let dir = std::env::temp_dir();
        let tail = dir.join("pep-key-probe").join("nested").join("store.json");
        let key_dir = canonical_path_key(&dir.to_string_lossy()).expect("temp dir is keyable");
        let key_tail =
            canonical_path_key(&tail.to_string_lossy()).expect("temp dir tail is keyable");
        assert!(
            key_tail.starts_with(&format!("{}/", key_dir.trim_end_matches('/'))),
            "non-existent tail {} must stay under the resolved prefix {}",
            key_tail,
            key_dir
        );

        let deny_dir = PathScope {
            allow: vec![],
            deny: vec![dir.to_string_lossy().to_string()],
        };
        assert!(
            !path_allowed(Some(&tail.to_string_lossy()), &deny_dir),
            "a store below a denied existing directory must be denied"
        );
        let allow_dir = PathScope {
            allow: vec![dir.to_string_lossy().to_string()],
            deny: vec![],
        };
        assert!(path_allowed(Some(&tail.to_string_lossy()), &allow_dir));
    }

    // ---- T-01537 S-22: device/extended-length spellings cannot evade scope.paths ----

    #[test]
    fn device_aliases_key_like_their_plain_form() {
        // The pre-fix keyer left `\\?\C:\DenyDir` mangled (it does not start with a
        // separator, so it never resolved), so the key differed from the resolved deny
        // entry and the deny did not apply. These paths do not exist, so both sides stay
        // lexical and the assertions are deterministic on any machine.
        #[cfg(windows)]
        {
            let deny = PathScope {
                allow: vec![],
                deny: vec![r"C:\DenyDir".into()],
            };
            for spelling in [
                r"\\?\C:\DenyDir\x.json",
                r"\\.\C:\DenyDir\x.json",
                r"//?/C:/DenyDir/x.json",
                r"\\.\c:\denydir\x.json",
                r"\\?\\\?\C:\DenyDir\x.json",
            ] {
                assert!(
                    !path_allowed(Some(spelling), &deny),
                    "{} must not escape the deny entry",
                    spelling
                );
            }
            // The UNC form of a denied UNC directory is the same directory.
            let deny_unc = PathScope {
                allow: vec![],
                deny: vec![r"\\server\share".into()],
            };
            assert!(!path_allowed(
                Some(r"\\?\UNC\server\share\x.json"),
                &deny_unc
            ));
            // And the allow list agrees, so a long-path agent is not refused for spelling
            // its own directory the extended way (the fail-closed half).
            let allow = PathScope {
                allow: vec![r"C:\AllowedDir".into()],
                deny: vec![],
            };
            assert!(path_allowed(Some(r"\\?\C:\AllowedDir\store.json"), &allow));
        }
        // A prefix that is stripped but leaves nothing addressable must fail closed rather
        // than become an unmatchable key, on every platform.
        assert!(canonical_path_key(r"\\.\PhysicalDrive0").is_none());
        assert!(canonical_path_key(r"\\?\GLOBALROOT\Device\HarddiskVolume2\x").is_none());
        assert!(canonical_path_key(r"\\?\").is_none());
        assert!(
            !path_allowed(
                Some(r"\\.\PhysicalDrive0"),
                &PathScope { allow: vec![], deny: vec!["/tmp".into()] }
            ),
            "an unmappable device path must be denied, not merely unmatched"
        );
    }

    // ---- T-01539 §6.21: a `.` entry is the working directory, not the empty key ----

    /// The test's working directory — cargo runs a test binary from its package root — plus
    /// a file that really exists in it, so a `.` entry has something to cover.
    fn cwd_and_real_file() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::current_dir().expect("test has a working directory");
        let file = dir.join("Cargo.toml");
        assert!(
            file.exists(),
            "expected the package root as the working directory, saw {}",
            dir.display()
        );
        (dir, file)
    }

    fn outside_cwd_file() -> std::path::PathBuf {
        std::env::current_dir()
            .expect("test has a working directory")
            .parent()
            .expect("working directory has a parent")
            .join("pep-t01539-outside-probe.json")
    }

    #[test]
    fn dot_spellings_key_to_the_working_directory() {
        let (dir, _) = cwd_and_real_file();
        let cwd_key = canonical_path_key(&dir.to_string_lossy()).expect("cwd is keyable");
        assert!(!cwd_key.is_empty());
        for spelling in [".", "./", ".//", "./.", ".\\"] {
            let key = canonical_path_key(spelling).expect("a `.` spelling must be keyable");
            assert!(
                !key.is_empty(),
                "{:?} keyed to the empty string, which is not a path",
                spelling
            );
            assert_eq!(
                key, cwd_key,
                "{:?} must key like the working directory",
                spelling
            );
        }
        // The empty spelling has no location of its own; it must at least never become the
        // empty key, which as a policy entry covered every absolute path on POSIX.
        assert!(!canonical_path_key("")
            .expect("the empty spelling is keyable")
            .is_empty());
    }

    #[test]
    fn dot_entry_covers_the_working_directory_and_not_the_parent() {
        let (dir, file) = cwd_and_real_file();
        let outside = outside_cwd_file();
        let allow = PathScope {
            allow: vec![".".into()],
            deny: vec![],
        };
        assert!(
            path_allowed(Some(&file.to_string_lossy()), &allow),
            "`.` must cover a file in the working directory (absolute argument)"
        );
        assert!(
            path_allowed(Some("Cargo.toml"), &allow),
            "`.` must cover the same file spelled relatively"
        );
        assert!(
            !path_allowed(Some(&outside.to_string_lossy()), &allow),
            "`.` must not cover the parent directory"
        );
        // The deny direction is the one that has to be exact: a `.` entry that collapses to
        // the empty key denies nothing at all on Windows and everything on POSIX.
        let deny = PathScope {
            allow: vec![],
            deny: vec![".".into()],
        };
        assert!(!path_allowed(Some(&file.to_string_lossy()), &deny));
        assert!(!path_allowed(Some("Cargo.toml"), &deny));
        assert!(!path_allowed(Some(&dir.to_string_lossy()), &deny));
        assert!(
            path_allowed(Some(&outside.to_string_lossy()), &deny),
            "deny `.` must not cover the parent directory"
        );
    }

    #[test]
    fn dot_entry_never_covers_a_root_relative_path() {
        let allow = PathScope {
            allow: vec![".".into()],
            deny: vec![],
        };
        // Before the fix the entry keyed to "", and containment on "" is
        // `key_target.starts_with("/")` — which every root-relative spelling satisfies. So
        // this was never a POSIX-only fail-open: on any platform, the working directory's
        // own entry authorized the whole filesystem.
        for outside in [
            "/pep-t01539-no-such-root/secret.json",
            r"\pep-t01539-no-such-root\secret.json",
        ] {
            let key = canonical_path_key(outside).expect("root-relative spelling is keyable");
            assert!(
                key.starts_with('/'),
                "{:?} resolved to {:?}; this case needs an unresolved root-relative spelling",
                outside,
                key
            );
            assert!(
                !path_allowed(Some(outside), &allow),
                "`.` must not cover {:?}",
                outside
            );
        }
    }

    #[test]
    fn an_empty_key_covers_nothing_on_any_platform() {
        // Containment on an empty entry key degenerates to `key_target.starts_with("/")`,
        // which every absolute POSIX key satisfies — one `.` entry used to authorize the
        // whole filesystem. The matcher refuses an empty key in both directions now,
        // whatever produces one.
        assert!(!key_covers_target("/etc/passwd", ""));
        assert!(!key_covers_target("/", ""));
        assert!(!key_covers_target("c:/windows/system32", ""));
        assert!(!key_covers_target("", ""));
        assert!(!key_covers_target("", "/etc"));
        // The containment test itself stays name-boundary aware.
        assert!(key_covers_target("/tmp", "/tmp"));
        assert!(key_covers_target("/tmp/ok", "/tmp"));
        assert!(key_covers_target("/tmp/ok", "/tmp/"));
        assert!(!key_covers_target("/tmpfoo", "/tmp"));
        assert!(!key_covers_target("/tmp", "/tmp/ok"));
    }

    #[test]
    fn parent_spellings_key_to_the_parent_not_the_working_directory() {
        let (dir, _) = cwd_and_real_file();
        let cwd_key = canonical_path_key(&dir.to_string_lossy()).expect("cwd is keyable");
        let parent = dir.parent().expect("cwd has a parent").to_path_buf();
        let parent_key = canonical_path_key(&parent.to_string_lossy()).expect("parent is keyable");
        assert_ne!(parent_key, cwd_key, "the parent is not the working directory");
        for spelling in ["..", "../", "..//", "..\\"] {
            let key = canonical_path_key(spelling).expect("a parent spelling must be keyable");
            assert_eq!(
                key, parent_key,
                "{:?} must key like the parent directory",
                spelling
            );
        }
        // Cancellation still works: `a/..` is the working directory.
        assert_eq!(canonical_path_key("a/..").expect("keyable"), cwd_key);

        // A `..` entry must cover the parent subtree and nothing above it. Collapsing `..`
        // to nothing made it the working directory, so the deny silently missed the parent —
        // and on POSIX it denied everything instead.
        let deny = PathScope {
            allow: vec![],
            deny: vec!["..".into()],
        };
        let in_parent = parent.join("pep-t01539-nested-probe.json");
        assert!(
            !path_allowed(Some(&in_parent.to_string_lossy()), &deny),
            "deny `..` must cover the parent directory"
        );
        let grandparent = parent.parent().expect("cwd has a grandparent");
        let above = grandparent.join("pep-t01539-nested-probe.json");
        assert!(
            path_allowed(Some(&above.to_string_lossy()), &deny),
            "deny `..` must not spill above the parent"
        );
    }

    #[test]
    fn entry_and_argument_need_not_share_a_spelling_frame() {
        let (dir, file) = cwd_and_real_file();
        let dotted = PathScope {
            allow: vec![".".into()],
            deny: vec![],
        };
        let absolute = PathScope {
            allow: vec![dir.to_string_lossy().to_string()],
            deny: vec![],
        };
        // Both frames of the same argument against both frames of the same entry: the OS
        // resolves the relative spelling against the working directory, so the keys agree.
        let args = ["Cargo.toml".to_string(), file.to_string_lossy().to_string()];
        for arg in &args {
            assert!(path_allowed(Some(arg.as_str()), &dotted), "`.` + {}", arg);
            assert!(
                path_allowed(Some(arg.as_str()), &absolute),
                "absolute entry + {}",
                arg
            );
        }
        // A relative *name* entry still means that name, and only that name.
        let named = PathScope {
            allow: vec!["data".into()],
            deny: vec![],
        };
        assert!(path_allowed(Some("data/store.json"), &named));
        assert!(!path_allowed(Some("other/store.json"), &named));
        assert!(!path_allowed(Some("datax/store.json"), &named));
    }

    #[cfg(windows)]
    #[test]
    fn windows_component_folds_keep_traversal_and_drop_nothing_names() {
        let (dir, _) = cwd_and_real_file();
        let cwd_key = canonical_path_key(&dir.to_string_lossy()).expect("cwd is keyable");
        // `.`/`..` are traversal components, not names: the dot/space fold must not touch
        // them, or `.` keys to the empty string and `..` keys to the working directory.
        assert_eq!(canonical_path_key(".").expect("keyable"), cwd_key);
        assert_ne!(canonical_path_key("..").expect("keyable"), cwd_key);
        // A component that is nothing but dots or spaces names nothing, and must not survive
        // as an empty segment: the doubled separator it injected stopped a padded spelling of
        // a denied location from matching the deny entry.
        assert!(!canonical_path_key("...").expect("keyable").is_empty());
        assert!(!canonical_path_key("   ").expect("keyable").is_empty());
        let padded = canonical_path_key(r"C:\pep-t01539-no-such-dir\...\secret.json")
            .expect("keyable");
        let plain = canonical_path_key(r"C:\pep-t01539-no-such-dir\secret.json").expect("keyable");
        assert_eq!(padded, plain, "a dots-only component must not change the key");
    }

    // ---- T-01539 adversarial residue finding: one physical destination, one budget ----

    #[test]
    fn store_destination_keys_collapse_spelling_aliases() {
        // Case aliases: one physical destination, one key (Windows folds case).
        #[cfg(windows)]
        {
            let a = canonical_store_key(Path::new(r"C:\Layouts\store.json")).expect("keyable");
            let b = canonical_store_key(Path::new(r"c:\layouts\STORE.JSON")).expect("keyable");
            assert_eq!(a, b, "case variants of one destination must key alike");
            // Trailing dot/space components are dropped by Windows itself.
            let c = canonical_store_key(Path::new(r"C:\Layouts\. \store.json")).expect("keyable");
            assert_eq!(a, c, "trailing dot/space components must not change the key");
        }
        // POSIX keeps case: these are genuinely different destinations, and must key
        // differently (no Windows folding leaks into POSIX policy).
        #[cfg(not(windows))]
        {
            let a = canonical_store_key(Path::new("/layouts/store.json")).expect("keyable");
            let b = canonical_store_key(Path::new("/layouts/STORE.JSON")).expect("keyable");
            assert_ne!(a, b, "POSIX case differences are distinct destinations");
        }
        // Nested *spelled* names are different destinations — the mirror image of the
        // evasion, which the old prefix grouping got wrong in the other direction.
        let plain = canonical_store_key(Path::new("/layouts/s.json")).expect("keyable");
        let nested = canonical_store_key(Path::new("/layouts/s.json.tmp")).expect("keyable");
        assert_ne!(plain, nested, "s.json and s.json.tmp are different destinations");
        // A `.`/`..` component must not degenerate: `.` inside a path is dropped, and the
        // result is never the empty key (the empty key covered every root-relative target
        // under containment — the degeneracy this keyer must not recreate). These paths do
        // not exist, so both sides stay lexical and the assertions are deterministic.
        let dotted = canonical_store_key(Path::new("/layouts/./s.json")).expect("keyable");
        assert_eq!(dotted, plain, "`./` in a destination must not change the key");
        // A bare `.` / `..` destination must never key to the empty string. What it keys
        // to instead is host-dependent — on Windows `.` resolves through its existing
        // prefix to the working directory, on POSIX it stays `.` — so the invariant pinned
        // here is the one the matcher needs: keyable and never empty (an empty key was the
        // degeneracy that made a `.` entry cover every root-relative target).
        for spelling in [".", "..", "./", "a/.."] {
            assert!(!canonical_store_key(Path::new(spelling))
                .unwrap_or_else(|| panic!("{spelling:?} must be keyable"))
                .is_empty(),
                "{spelling:?} must never key to the empty string");
        }
    }

    #[test]
    fn staged_destination_names_recover_the_original_destination() {
        let dir = Path::new("/layouts");
        assert_eq!(
            staged_file_destination(".store.json.tmp.123.456.0", dir).as_deref(),
            canonical_store_key(&dir.join("store.json")).as_deref(),
            "a staged file must recover its original destination's key"
        );
        assert_eq!(
            staged_file_destination(".s.json.tmp.tmp.1.1.0", dir).as_deref(),
            canonical_store_key(&dir.join("s.json.tmp")).as_deref(),
            "the numeric tail marks the staged suffix, so a staged file for the nested destination `s.json.tmp` keys apart from `s.json`"
        );
        // Not the staged shape: ignored, never charged.
        assert_eq!(staged_file_destination("store.json", dir), None);
        assert_eq!(staged_file_destination(".tmp.x", dir), None);
        // The `..` component is *kept* by the keyer (it is the parent, not nothing), so a
        // name starting with dots does not match the staged shape at all.
        assert_eq!(
            staged_file_destination(".store.json.tmp.1.2.3", &Path::new("/layouts").join(".")).as_deref(),
            canonical_store_key(Path::new("/layouts/store.json")).as_deref(),
            "a `.` component in the directory must not change the recovered destination"
        );
    }

    #[test]
    fn tool_glob_matches() {
        assert!(tool_glob_match("pentest.nmap", &["pentest.*".to_string()]));
        assert!(!tool_glob_match("pentest.nmap", &["pentest.metasploit".to_string()]));
        assert!(tool_glob_match("pentest.nmap", &["pentest.nmap".to_string()]));
        assert!(!tool_glob_match("pentest.nmap", &[]));
        // Dot boundary (T-03363 follow-up): a family glob never covers a sibling with a longer name.
        assert!(!tool_glob_match("github.delete_repo", &["git.*".to_string()]));
        assert!(!tool_glob_match("aios.fs_layout.delete", &["aios.fs.*".to_string()]));
        assert!(!tool_glob_match("pentesting.x", &["pentest.*".to_string()]));
        assert!(tool_glob_match("git", &["git.*".to_string()]));
        assert!(tool_glob_match("git.push", &["git.*".to_string()]));
        assert!(tool_glob_match("aios.fs.read", &["aios.fs.*".to_string()]));
    }

    #[test]
    fn path_deny_wins() {
        let mut sc = PathScope::default();
        sc.allow = vec!["/tmp".into()];
        sc.deny = vec!["/tmp/secret".into()];
        assert!(path_allowed(Some("/tmp/ok"), &sc));
        assert!(!path_allowed(Some("/tmp/secret/x"), &sc));
    }

    #[test]
    fn path_traversal_blocked() {
        let mut sc = PathScope::default();
        sc.allow = vec!["/tmp".into()];
        sc.deny = vec!["/etc".into()];
        assert!(!path_allowed(Some("/var/log/../../etc/shadow"), &sc));
        assert!(!path_allowed(Some("/etc//shadow"), &sc));
        assert!(!path_allowed(Some(r"\etc\shadow"), &sc));
    }
}
