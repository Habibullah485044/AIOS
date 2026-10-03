//! aiosh — the AIOS shell CLI (Rust rewrite).
//!
//! Subcommands (each emits exactly one audit row):
//!   aiosh status
//!   aiosh run <command...> [--target T]
//!   aiosh agent <prompt> [--grant G] [--max-steps N] [--ollama-url U] [--ollama-model M]
//!   aiosh audit tail [n]
//!   aiosh audit verify [--full]
//!   aiosh audit rotate [--keep N] [--dry-run]
//!   aiosh audit segments
//!   aiosh audit seen <hash> [--exact]
//!   aiosh grant create --to S --tools GLOBS [--networks CIDRS] [--allow P] [--deny P] [--ttl S]
//!   aiosh grant list
//!   aiosh grant revoke <id>
//!   aiosh pentest {nmap|nikto|sqlmap|tshark|aircrack-ng} <args...> [--grant G] [--timeout-s N]
//!   aiosh classify <tool> [--target T] [--json-args S]

use aiosh_core::audit::{AuditRing, AuditRowInput};
use aiosh_core::classifier::classify;
use aiosh_core::pentest;
use aiosh_core::pep::PepStore;
use aiosh_core::retention;
use aiosh_core::types::{AuditRow, CFlags, GrantScope, PathScope};
use serde_json::{json, Value};
use std::process::exit;

const IMPLICIT_REVISION: &str = "v0.0";

fn ai_home() -> String {
    std::env::var("AIOSH_HOME").unwrap_or_else(|_| {
        format!("{}/.aios", std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
    })
}

fn db_path() -> String {
    format!("{}/audit.db", ai_home())
}

struct Ctx {
    ring: AuditRing,
    pep: PepStore,
    con_rev: String,
    con_title: String,
    con_source: String,
    actor_id: String,
}

fn open_context() -> Ctx {
    let path = db_path();
    let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
        path: Some(path.clone()),
        home: None,
    })
    .expect("open audit db");
    ring.prepare_for_write().expect("prepare schemas");
    let pep_path = ring.path().to_string();
    let pep = if pep_path == ":memory:" {
        PepStore::new(rusqlite::Connection::open_in_memory().unwrap()).expect("open pep store")
    } else {
        PepStore::new(rusqlite::Connection::open(&pep_path).expect("open pep db")).expect("open pep store")
    };
    let con_path = std::env::var("AIOSH_CONSTITUTION").unwrap_or_else(|_| {
        "/content/AIOS_MERGED/mostimportanAIfolder/AI_CONSTITUTION.md".into()
    });
    let (con_rev, con_title) = match std::fs::read_to_string(&con_path) {
        Ok(content) => {
            let rev = aiosh_core::canonical::sha256_hex_bytes(content.as_bytes())[..12].to_string();
            let title = content
                .lines()
                .find(|l| l.starts_with("# "))
                .map(|l| l.trim_start_matches("# ").trim().to_string())
                .unwrap_or_else(|| "untitled".into());
            (rev, title)
        }
        Err(_) => (IMPLICIT_REVISION.into(), "(no constitution file found)".into()),
    };
    let actor_id = format!(
        "user:{}@{}",
        std::env::var("USER").unwrap_or_else(|_| "anon".into()),
        std::env::var("HOSTNAME").unwrap_or_else(|_| "host".into())
    );
    Ctx { ring, pep, con_rev, con_title, con_source: con_path, actor_id }
}

/// Emit an audit row with optional classifier provenance.
#[allow(clippy::too_many_arguments)]
fn emit(
    ctx: &mut Ctx,
    tool: &str,
    command: &str,
    args: Value,
    outcome: &str,
    target: Option<&str>,
    outcome_detail: Option<&str>,
    actor: &str,
    grant_token: Option<&str>,
    c_flags: CFlags,
    cls: Option<&aiosh_core::classifier::ClassificationResult>,
) -> AuditRow {
    let input = AuditRowInput {
        ts: aiosh_core::canonical::utcnow_iso(),
        actor: actor.into(),
        actor_id: ctx.actor_id.clone(),
        tool: tool.into(),
        command: command.into(),
        args,
        target: target.map(|s| s.into()),
        outcome: outcome.into(),
        outcome_detail: outcome_detail.map(|s| s.into()),
        constitution_rev: Some(ctx.con_rev.clone()),
        grant_token: grant_token.map(|s| s.into()),
        c_flags,
        policy_revision: cls.map(|c| c.policy_revision.clone()),
        classify_rule_ids: cls.map(|c| c.rule_ids.clone()),
        classify_evidence: cls.map(|c| c.evidence_per_flag()),
        classify_overall_verdict: cls.map(|c| c.overall_verdict.clone()),
        classify_verdict_reason: cls.map(|c| c.verdict_reason.clone()),
    };
    ctx.ring.write(input).expect("audit write")
}

fn classify_and_emit(
    ctx: &mut Ctx,
    tool: &str,
    command: &str,
    args: Value,
    outcome: &str,
    target: Option<&str>,
    outcome_detail: Option<&str>,
    actor: &str,
    grant_token: Option<&str>,
) -> AuditRow {
    let cls = classify(tool, target, &args);
    let c = CFlags {
        c1: cls.c1.flag,
        c2: cls.c2.flag,
        c3: cls.c3.flag,
        c4: cls.c4.flag,
    };
    emit(ctx, tool, command, args, outcome, target, outcome_detail, actor, grant_token, c, Some(&cls))
}

/// Renders untrusted text safely for human-readable terminal output.
///
/// Layout specs may be authored outside the operator's trust boundary (shared profiles,
/// agent-written stores, imported fstab). Raw control characters — notably ESC — would
/// otherwise drive terminal escape sequences (CWE-150), so they are replaced with U+FFFD,
/// the same substitution the argv boundary already performs. JSON output is never
/// sanitized: serde escapes control characters correctly there.
fn sanitize_terminal(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

fn sanitize_terminal_output(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() && c != '\n' && c != '\r' && c != '\t' { '\u{FFFD}' } else { c })
        .collect()
}

fn ok_out(v: Value) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}

fn err_out(v: Value) -> i32 {
    eprintln!("{}", serde_json::to_string_pretty(&v).unwrap());
    1
}

fn print_result(v: Value, ok: bool) -> i32 {
    if ok { ok_out(v); 0 } else { err_out(v) }
}

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn main() {
    // T-00038 hardening: never panic on hostile/accidental non-UTF-8
    // argv — lossy-convert instead (invalid bytes become U+FFFD), so
    // every invocation reaches the standard envelope + audit row.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("status") => cmd_status(),
        Some("run") => cmd_run(&args[1..]),
        Some("agent") => cmd_agent(&args[1..]),
        Some("audit") => cmd_audit(&args[1..]),
        Some("grant") => cmd_grant(&args[1..]),
        Some("pentest") => cmd_pentest(&args[1..]),
        Some("classify") => cmd_classify(&args[1..]),
        Some("release") => cmd_release(&args[1..]),
        Some("backup") => cmd_backup(&args[1..]),
        Some("ci") => cmd_ci(&args[1..]),
        Some("task") => cmd_task(&args[1..]),
        Some("toolchain") => cmd_toolchain(&args[1..]),
        Some("doc") => cmd_doc(&args[1..]),
        Some("evidence") => cmd_evidence(&args[1..]),
        Some("repo") => cmd_repo(&args[1..]),
        Some("secrets") => cmd_secrets(&args[1..]),
        Some("triage") => cmd_triage(&args[1..]),
        Some("handoff") => cmd_handoff(&args[1..]),
        Some("distro") => cmd_distro(&args[1..]),
        Some("image") => cmd_image(&args[1..]),
        Some("package") => cmd_package(&args[1..]),
        Some("service") => cmd_service(&args[1..]),
        Some("session") => cmd_session(&args[1..]),
        Some("layout") | Some("fs-layout") => cmd_fs_layout(&args[1..]),
        Some("mod") | Some("module") => cmd_kernel_module(&args[1..]),
        Some("hw") | Some("hardware") => cmd_hardware(&args[1..]),
        Some("net") | Some("network") => cmd_network(&args[1..]),
        Some("update") | Some("upd") => cmd_update(&args[1..]),
        Some("capability") | Some("cap") => cmd_capability(&args[1..]),
        Some("pep") => cmd_pep(&args[1..]),
        Some("sandbox") | Some("sb") => cmd_sandbox(&args[1..]),
        Some("privilege") | Some("priv") => cmd_privilege(&args[1..]),
        Some("secret") | Some("sec") => cmd_secret(&args[1..]),
        Some("--help") | Some("-h") | None => {
            println!("aiosh — AIOS shell CLI (Rust)\n\nUsage: aiosh <status|run|agent|audit|grant|pentest|classify|task|ci|release|backup|toolchain|doc|evidence|repo|secrets|triage|handoff|distro|image|package|service|session|layout|mod|hw|net|update|capability|pep|sandbox|privilege|secret> ...\n\n  aiosh audit <tail|verify|rotate|segments|seen|query|ancestry|sign-verify|inspect|config>  Audit ring & chain extensions control\n  aiosh task <status|done|block|unblock|skip|rebuild|check>  Task ledger control\n  aiosh ci <show|failures|check|config|metrics> [--file PATH]  CI smoke reports\n  aiosh release generate  Create bootable ISO\n  aiosh backup create  Create system snapshot zip\n  aiosh toolchain check [--config <path>]  Verify host environment against ToolchainManifest\n  aiosh toolchain show [--config <path>]   Display the resolved ToolchainManifest\n  aiosh doc <show|check|search>  Documentation Index Control\n  aiosh evidence <verify|hash|scan>   Evidence & Audit Trail Control\n  aiosh repo <health|check>  Repository Health Diagnostics\n  aiosh secrets <scan|check> [--config <path>]  Secrets & Access Hygiene Scanner\n  aiosh triage <list|show|record|resolve|ingest|check>  Regression Triage Manager\n  aiosh handoff <list|show|initiate|accept|reject|complete|cancel>  Agent Handoff Protocol Manager\n  aiosh distro <list|show|evaluate|recommend|policy|stats|check>  Linux Distro Selection & Justification Manager\n  aiosh image <list|show|plan|filter>  Linux Base Image Build & Packaging Manager\n  aiosh package <list|show|search|plan|apply|validate>  Linux Package Management & Store Control\n  aiosh service <validate|list|show|status|action|start|stop|restart|reload|order>  Init & Service Supervision Control\n  aiosh session <validate|list|show|status|create|action|activate|lock|unlock|terminate|config>  User Session Bootstrap Control\n  aiosh layout <list|show|validate|check|probe|diff|fstab|register|set-active|remove|import-fstab>  Filesystem Layout & Target Partitioning Manager\n  aiosh mod <list|show|blacklist|unblacklist|options|autoload|unautoload|preset|export>  Kernel Module Management\n  aiosh hw <scan|list|show|summary|verify>  Hardware Detection & Inventory Control\n  aiosh net <list|show|routes|dns|state|up|down>  Network Bootstrap & Interface Control\n  aiosh update <status|slots|check|apply|confirm|rollback>  System Update & Dual-Slot Control\n  aiosh capability <list|show|issue|attenuate|revoke|check|prune>  Capability & Zero-Ambient Authority Control\n  aiosh pep <evaluate|rule-add|rule-list|rule-remove|status|report|doc>  PEP Decision Engine & Policy Control\n  aiosh sandbox <profiles|probe|exec>  Sandbox Containment & Execution Control\n  aiosh privilege <eval|status|policy-list|policy-add|policy-remove|report>  Privilege Escalation Prevention Control\n  aiosh secret <store|get|list|rotate|revoke>  Secrets Handling & Runtime Vault Control");
            0
        }
        Some(other) => {
            eprintln!("unknown command: {}", other);
            2
        }
    };
    exit(code);
}

fn cmd_distro(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let cfg = aiosh_core::distro_config::DistroConfig::from_env().unwrap_or_default();
    let store = if let Some(path_str) = parse_flag(rest, "--store") {
        match aiosh_core::distro_service::DistroStore::load_from_path(std::path::Path::new(&path_str)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error loading distro store: {}", e);
                return 1;
            }
        }
    } else {
        match aiosh_core::distro_service::DistroStore::load_from_config(&cfg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error loading distro store from config: {}", e);
                return 1;
            }
        }
    };

    match sub {
        Some("list") => {
            let profiles = store.list_profiles();
            classify_and_emit(
                &mut ctx,
                "distro",
                "list",
                json!({ "count": profiles.len() }),
                "success",
                None,
                Some("Listed distro profiles"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&profiles).unwrap_or_default());
            } else {
                println!("{:<30} {:<10} {:<10} {:<12} NAME", "ID", "FAMILY", "ARCH", "RECOMMENDED");
                println!("{}", "-".repeat(78));
                for p in &profiles {
                    println!("{:<30} {:<10?} {:<10?} {:<12} {}", p.id, p.family, p.arch, p.recommended, p.name);
                }
                println!("\nTotal distro profiles: {}", profiles.len());
            }
            0
        }
        Some("show") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh distro show <id> [--json] [--store <path>]");
                    return 2;
                }
            };
            match store.get_profile(id) {
                Some(p) => {
                    classify_and_emit(
                        &mut ctx,
                        "distro",
                        "show",
                        json!({ "id": p.id }),
                        "success",
                        Some(&p.id),
                        Some("Retrieved distro profile"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
                    } else {
                        println!("Distribution Profile: {}", p.name);
                        println!("  ID:             {}", p.id);
                        println!("  Family:         {:?}", p.family);
                        println!("  Arch:           {:?}", p.arch);
                        println!("  Recommended:    {}", p.recommended);
                        println!("  Init System:    {:?}", p.init_system);
                        println!("  C Library:      {:?}", p.c_lib);
                        println!("  Min Kernel:     {}", p.min_kernel_version);
                        println!("  Packages:       {}", p.default_packages.join(", "));
                        println!("  Justification:  {}", p.justification);
                    }
                    0
                }
                None => {
                    eprintln!("Distro profile '{}' not found", id);
                    1
                }
            }
        }
        Some("evaluate") => {
            let id_opt = rest.first().filter(|s| !s.starts_with("--")).map(|s| s.as_str());
            if let Some(id) = id_opt {
                match store.evaluate_profile(id) {
                    Ok(ev) => {
                        classify_and_emit(
                            &mut ctx,
                            "distro",
                            "evaluate",
                            json!({ "id": ev.profile_id, "score": ev.overall_score }),
                            "success",
                            Some(&ev.profile_id),
                            Some("Evaluated distro profile"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", serde_json::to_string_pretty(&ev).unwrap_or_default());
                        } else {
                            println!("Evaluation for '{}' (Score: {:.2}):", ev.profile_id, ev.overall_score);
                            println!("  Binary Compatibility: {:.2}", ev.binary_compatibility_score);
                            println!("  Minimal Footprint:    {:.2}", ev.footprint_score);
                            println!("  Security Hardening:   {:.2}", ev.security_score);
                            println!("  Production Ready:     {}", ev.is_production_ready);
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("Evaluation error: {}", e);
                        1
                    }
                }
            } else {
                let evals = store.evaluate_all();
                classify_and_emit(
                    &mut ctx,
                    "distro",
                    "evaluate_all",
                    json!({ "count": evals.len() }),
                    "success",
                    None,
                    Some("Evaluated all distro profiles"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&evals).unwrap_or_default());
                } else {
                    println!("{:<30} {:<14} EVALUATION SUMMARY", "PROFILE ID", "OVERALL SCORE");
                    println!("{}", "-".repeat(70));
                    for ev in &evals {
                        println!("{:<30} {:<14.2} compat={:.2} footprint={:.2} security={:.2} ready={}",
                            ev.profile_id, ev.overall_score, ev.binary_compatibility_score, ev.footprint_score, ev.security_score, ev.is_production_ready);
                    }
                }
                0
            }
        }
        Some("recommend") => {
            match store.get_recommended_profile() {
                Some(p) => {
                    classify_and_emit(
                        &mut ctx,
                        "distro",
                        "recommend",
                        json!({ "id": p.id }),
                        "success",
                        Some(&p.id),
                        Some("Retrieved recommended distro profile"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
                    } else {
                        println!("Recommended Profile: {} ({})", p.name, p.id);
                        println!("Architecture: {:?} | Family: {:?}", p.arch, p.family);
                    }
                    0
                }
                None => {
                    eprintln!("No recommended distribution profile found");
                    1
                }
            }
        }
        Some("config") => {
            if is_json {
                println!("{}", serde_json::to_string_pretty(&cfg.to_json_with_sources()).unwrap_or_default());
            } else {
                println!("AIOS Distro Configuration:");
                println!("  Store Path:               {}", cfg.store_path);
                println!("  Pinned Reference ID:      {}", cfg.pinned_reference_id);
                println!("  Min Recommendation Score: {:.2}", cfg.min_recommendation_score);
                println!("  Auto Evaluate:            {}", cfg.auto_evaluate);
                println!("  Weights:                  binary={:.2}, security={:.2}, footprint={:.2}",
                    cfg.weights.binary_compatibility, cfg.weights.security, cfg.weights.footprint);
            }
            0
        }
        Some("policy") => {
            let policy = match aiosh_core::distro_policy::DistroSecurityPolicy::from_env() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error loading security policy: {}", e);
                    return 1;
                }
            };
            let id_opt = rest.first().filter(|s| !s.starts_with("--")).map(|s| s.as_str());
            if let Some(id) = id_opt {
                let profile = match store.get_profile(id) {
                    Some(p) => p,
                    None => {
                        eprintln!("Distro profile '{}' not found", id);
                        return 1;
                    }
                };
                let eval = match store.evaluate_profile(id) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Evaluation error: {}", e);
                        return 1;
                    }
                };
                let verdict = policy.check_profile(&profile, &eval);
                classify_and_emit(
                    &mut ctx,
                    "distro",
                    "policy",
                    json!({ "id": id, "allowed": verdict.allowed, "violations": verdict.violations }),
                    if verdict.allowed { "success" } else { "warning" },
                    Some(id),
                    Some("Checked distro profile security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&verdict).unwrap_or_default());
                } else {
                    println!("Policy Verdict for '{}': {}", verdict.profile_id, if verdict.allowed { "ALLOWED" } else { "REJECTED" });
                    if !verdict.violations.is_empty() {
                        println!("Violations:");
                        for v in &verdict.violations {
                            println!("  - {}", v);
                        }
                    }
                }
                if verdict.allowed { 0 } else { 1 }
            } else {
                let verdicts = store.check_security_policy(&policy);
                let allowed_count = verdicts.iter().filter(|v| v.allowed).count();
                classify_and_emit(
                    &mut ctx,
                    "distro",
                    "policy",
                    json!({ "total": verdicts.len(), "allowed": allowed_count }),
                    "success",
                    None,
                    Some("Checked security policy across all distro profiles"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&verdicts).unwrap_or_default());
                } else {
                    println!("{:<30} {:<10} VIOLATIONS", "PROFILE ID", "STATUS");
                    println!("{}", "-".repeat(60));
                    for v in &verdicts {
                        let status = if v.allowed { "ALLOWED" } else { "REJECTED" };
                        let viol_summary = if v.violations.is_empty() {
                            "-".to_string()
                        } else {
                            v.violations.join("; ")
                        };
                        println!("{:<30} {:<10} {}", v.profile_id, status, viol_summary);
                    }
                    println!("\nCompliant profiles: {}/{}", allowed_count, verdicts.len());
                }
                0
            }
        }
        Some("stats") => {
            let policy_opt = aiosh_core::distro_policy::DistroSecurityPolicy::from_env().ok();
            let report = store.get_observability_report(policy_opt.as_ref());
            classify_and_emit(
                &mut ctx,
                "distro",
                "stats",
                json!({
                    "total": report.total_profiles,
                    "production_ready": report.production_ready_count,
                    "policy_compliant": report.policy_compliant_count,
                }),
                "success",
                None,
                Some("Retrieved distro observability report"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("AIOS Distro Observability Report:");
                println!("  Total Profiles:            {}", report.total_profiles);
                println!("  Recommended Profile:       {}", report.recommended_profile_id.as_deref().unwrap_or("none"));
                println!("  Production Ready:          {}/{}", report.production_ready_count, report.total_profiles);
                println!("  Policy Compliant:          {}/{}", report.policy_compliant_count, report.total_profiles);
                println!("  Average Overall Score:     {:.2}", report.average_overall_score);
                println!("  Average Security Score:    {:.2}", report.average_security_score);
                println!("  Average Footprint Score:   {:.2}", report.average_footprint_score);
                println!("  Average Binary Compat:     {:.2}", report.average_binary_compatibility_score);
                println!("\nFamily Breakdown:");
                for (fam, count) in &report.family_breakdown {
                    println!("  {:<20} {}", fam, count);
                }
                println!("\nArchitecture Breakdown:");
                for (arch, count) in &report.architecture_breakdown {
                    println!("  {:<20} {}", arch, count);
                }
            }
            0
        }
        Some("check") => {
            let report = store.validate_health();
            classify_and_emit(
                &mut ctx,
                "distro",
                "check",
                json!({
                    "healthy": report.healthy,
                    "profile_count": report.profile_count,
                    "errors_count": report.errors.len(),
                }),
                if report.healthy { "success" } else { "failure" },
                None,
                Some("Validated distro store structural health"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("AIOS Distro Store Health Check:");
                println!("  Status:                    {}", if report.healthy { "HEALTHY" } else { "UNHEALTHY" });
                println!("  Profile Count:             {}", report.profile_count);
                println!("  Recommended Profile Valid: {}", if report.recommended_profile_valid { "YES" } else { "NO" });
                if !report.errors.is_empty() {
                    println!("\nErrors Detected:");
                    for err in &report.errors {
                        println!("  - {}", err);
                    }
                }
            }
            if report.healthy { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh distro — Linux Distro Selection & Justification Manager\n\nUsage:\n  aiosh distro list [--json] [--store <path>]\n  aiosh distro show <id> [--json] [--store <path>]\n  aiosh distro evaluate [<id>] [--json] [--store <path>]\n  aiosh distro recommend [--json] [--store <path>]\n  aiosh distro config [--json]\n  aiosh distro policy [<id>] [--json] [--store <path>]\n  aiosh distro stats [--json] [--store <path>]\n  aiosh distro check [--json] [--store <path>]");
            0
        }
        Some(other) => {
            eprintln!("unknown distro subcommand: {}", other);
            2
        }
    }
}

fn cmd_image(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store = if let Some(path_str) = parse_flag(rest, "--store") {
        match aiosh_core::base_image_service::ImageStore::load_from_path(std::path::Path::new(&path_str)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to load image store from '{}': {}", path_str, e);
                return 1;
            }
        }
    } else {
        aiosh_core::base_image_service::ImageStore::new()
    };

    match sub {
        Some("list") => {
            let images = store.list_images();
            classify_and_emit(
                &mut ctx,
                "image",
                "list",
                json!({ "count": images.len() }),
                "success",
                None,
                Some("Enumerated registered base image manifests"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&images).unwrap_or_default());
            } else {
                println!("{:<32} {:<10} {:<10} {:<12} {}", "IMAGE ID", "FORMAT", "ARCH", "FILESYSTEM", "VERSION");
                for img in &images {
                    println!("{:<32} {:<10} {:<10} {:<12} {}", img.id, img.format, img.rootfs.architecture, img.rootfs.filesystem_type, img.version);
                }
            }
            0
        }
        Some("show") => {
            let id = match rest.first() {
                Some(s) if !s.starts_with("--") => s.as_str(),
                _ => {
                    eprintln!("missing required image id: aiosh image show <id>");
                    return 2;
                }
            };
            if !id.chars().all(|c| c.is_ascii_graphic()) || id.is_empty() {
                eprintln!("invalid image id: contains non-printable or control characters");
                return 2;
            }
            let manifest = match store.get_image(id) {
                Some(m) => m,
                None => {
                    eprintln!("image '{}' not found in store", id);
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx,
                "image",
                "show",
                json!({ "id": id, "format": manifest.format.to_string() }),
                "success",
                None,
                Some("Retrieved base image manifest"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(manifest).unwrap_or_default());
            } else {
                println!("AIOS Base Image Manifest: {}", manifest.id);
                println!("  Version:         {}", manifest.version);
                println!("  Format:          {}", manifest.format);
                println!("  Target Distro:   {}", manifest.rootfs.distro_id);
                println!("  Architecture:    {}", manifest.rootfs.architecture);
                println!("  Filesystem:      {}", manifest.rootfs.filesystem_type);
                println!("  Hostname:        {}", manifest.rootfs.hostname);
                println!("  Size Budget:     {} MB", manifest.rootfs.size_budget_bytes / (1024 * 1024));
                println!("  Kernel Version:  {}", manifest.kernel.version);
                println!("  Kernel Cmdline:  {}", manifest.kernel.cmdline);
                println!("  Initramfs Gen:   {}", manifest.kernel.initramfs_generator);
                println!("  Packages Count:  {}", manifest.rootfs.packages.len());
                println!("  Packages Sample: {}", manifest.rootfs.packages.iter().take(8).cloned().collect::<Vec<_>>().join(", "));
            }
            0
        }
        Some("plan") => {
            let id = match rest.first() {
                Some(s) if !s.starts_with("--") => s.as_str(),
                _ => {
                    eprintln!("missing required image id: aiosh image plan <id>");
                    return 2;
                }
            };
            if !id.chars().all(|c| c.is_ascii_graphic()) || id.is_empty() {
                eprintln!("invalid image id: contains non-printable or control characters");
                return 2;
            }
            let plan = match store.generate_build_plan(id) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to generate build plan for '{}': {}", id, e);
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx,
                "image",
                "plan",
                json!({ "id": id, "stages_count": plan.stages.len(), "estimated_duration_secs": plan.estimated_total_duration_secs }),
                "success",
                None,
                Some("Generated base image build plan"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&plan).unwrap_or_default());
            } else {
                println!("AIOS Build Execution Plan for '{}':", plan.image_id);
                println!("  Target Format:      {}", plan.target_format);
                println!("  Estimated Duration: {}s", plan.estimated_total_duration_secs);
                println!("  Estimated Size:     {} MB", plan.estimated_artifact_size_bytes / (1024 * 1024));
                println!("\nDiscrete Stages ({}):", plan.stages.len());
                for (i, stage) in plan.stages.iter().enumerate() {
                    println!("  [{}] {} (approx {}s):", i + 1, stage.name, stage.estimated_duration_secs);
                    println!("      Description: {}", stage.description);
                    println!("      Command:     {}", stage.command_template);
                }
            }
            0
        }
        Some("filter") => {
            let mut matches = store.list_images();
            if let Some(fmt_str) = parse_flag(rest, "--format") {
                let fmt = match fmt_str.to_lowercase().as_str() {
                    "raw" => aiosh_core::base_image::ImageFormat::Raw,
                    "qcow2" => aiosh_core::base_image::ImageFormat::Qcow2,
                    "iso" => aiosh_core::base_image::ImageFormat::Iso,
                    "tarball" | "tar" => aiosh_core::base_image::ImageFormat::Tarball,
                    other => {
                        eprintln!("unknown image format: {}", other);
                        return 2;
                    }
                };
                matches.retain(|m| m.format == fmt);
            }
            if let Some(distro) = parse_flag(rest, "--distro") {
                matches.retain(|m| m.rootfs.distro_id == distro);
            }
            classify_and_emit(
                &mut ctx,
                "image",
                "filter",
                json!({ "matched_count": matches.len() }),
                "success",
                None,
                Some("Filtered registered base image manifests"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&matches).unwrap_or_default());
            } else {
                println!("Matched Base Images ({}):", matches.len());
                for img in &matches {
                    println!("  {:<32} {:<10} {:<10} {}", img.id, img.format, img.rootfs.architecture, img.rootfs.distro_id);
                }
            }
            0
        }
        Some("config") => {
            let config = if let Some(cfg_path_str) = parse_flag(rest, "--config") {
                match aiosh_core::base_image_config::ImageBuildConfig::from_file(std::path::Path::new(&cfg_path_str)) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("failed to load image config from '{}': {}", cfg_path_str, e);
                        return 1;
                    }
                }
            } else {
                match aiosh_core::base_image_config::ImageBuildConfig::from_env() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("failed to load image config from environment: {}", e);
                        return 1;
                    }
                }
            };
            classify_and_emit(
                &mut ctx,
                "image",
                "config",
                json!({ "default_target": config.default_target, "timeout": config.max_build_duration_secs }),
                "success",
                None,
                Some("Inspected base image configuration"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&config).unwrap_or_default());
            } else {
                println!("AIOS Base Image Build Configuration:");
                println!("  Build Directory:    {}", config.build_dir.display());
                println!("  Output Directory:   {}", config.output_dir.display());
                println!("  Default Target:     {}", config.default_target);
                println!("  Max Duration:       {}s", config.max_build_duration_secs);
                println!("  Max Artifact Size:  {} MB", config.max_artifact_size_bytes / (1024 * 1024));
                println!("  Compression Level:  {}", config.compression_level);
            }
            0
        }
        Some("policy") => {
            let policy = match aiosh_core::base_image_policy::BaseImageSecurityPolicy::from_env() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to load image security policy: {}", e);
                    return 1;
                }
            };
            let id_opt = rest.first().filter(|s| !s.starts_with("--")).map(|s| s.as_str());
            if let Some(id) = id_opt {
                if !id.chars().all(|c| c.is_ascii_graphic()) || id.is_empty() {
                    eprintln!("invalid image id: contains non-printable or control characters");
                    return 2;
                }
                let manifest = match store.get_image(id) {
                    Some(m) => m,
                    None => {
                        eprintln!("image '{}' not found in store", id);
                        return 1;
                    }
                };
                let verdict = policy.evaluate(manifest);
                classify_and_emit(
                    &mut ctx,
                    "image",
                    "policy",
                    json!({ "id": id, "allowed": verdict.allowed, "violations_count": verdict.violations.len() }),
                    if verdict.allowed { "success" } else { "failure" },
                    None,
                    Some("Evaluated base image security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&verdict).unwrap_or_default());
                } else {
                    println!("Base Image Policy Verdict for '{}':", id);
                    println!("  Allowed:    {}", verdict.allowed);
                    println!("  Mode:       {:?}", verdict.mode);
                    println!("  Violations: {}", verdict.violations.len());
                    for v in &verdict.violations {
                        println!("    - [{}] {} (fatal: {})", v.rule_id, v.description, v.fatal);
                    }
                }
                if verdict.allowed { 0 } else { 1 }
            } else {
                let verdicts = policy.check_all(&store);
                classify_and_emit(
                    &mut ctx,
                    "image",
                    "policy",
                    json!({ "evaluated_count": verdicts.len() }),
                    "success",
                    None,
                    Some("Evaluated base image security policy across store"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&verdicts).unwrap_or_default());
                } else {
                    println!("Base Image Security Policy (mode: {:?}):", policy.mode);
                    for v in &verdicts {
                        let status_str = if v.allowed { "PASS" } else { "FAIL" };
                        println!("  [{}] {:<32} (violations: {})", status_str, v.manifest_id, v.violations.len());
                    }
                }
                0
            }
        }
        Some("report") => {
            let policy_opt = aiosh_core::base_image_policy::BaseImageSecurityPolicy::from_env().ok();
            let report = aiosh_core::base_image_observability::BaseImageObservabilityReport::generate(&store, policy_opt.as_ref());
            classify_and_emit(
                &mut ctx,
                "image",
                "report",
                json!({ "total_images": report.total_images, "policy_compliant": report.policy_compliant_count }),
                "success",
                None,
                Some("Generated base image observability report"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("AIOS Base Image Build Observability Report:");
                println!("  Total Images:        {}", report.total_images);
                println!("  Policy Compliant:    {}", report.policy_compliant_count);
                println!("  Total Size Budget:   {} MB", report.total_size_budget_bytes / (1024 * 1024));
                println!("  Average Size Budget: {} MB", report.average_size_budget_bytes / (1024 * 1024));
                println!("  Formats:             {:?}", report.format_breakdown);
                println!("  Architectures:       {:?}", report.architecture_breakdown);
                println!("  Distributions:       {:?}", report.distro_breakdown);
                println!("  Kernel Versions:     {:?}", report.kernel_versions);
            }
            0
        }
        Some("check") => {
            let is_fix = has_flag(rest, "--fix");
            let store_path_opt = parse_flag(rest, "--store");
            let (active_store, recovery_action) = if is_fix {
                let p = store_path_opt.as_deref().unwrap_or("/var/lib/aios/images");
                aiosh_core::base_image_recovery::load_or_recover(std::path::Path::new(p))
            } else if let Some(ref path_str) = store_path_opt {
                match aiosh_core::base_image_service::ImageStore::load_from_path(std::path::Path::new(path_str)) {
                    Ok(s) => (s, aiosh_core::base_image_recovery::RecoveryAction::LoadedExisting),
                    Err(e) => {
                        let report = aiosh_core::base_image_recovery::BaseImageValidationReport {
                            healthy: false,
                            total_manifests: 0,
                            valid_manifests: 0,
                            invalid_manifests: 0,
                            errors: vec![format!("failed to load image store: {}", e)],
                            warnings: vec![],
                            generated_at: chrono::Utc::now().to_rfc3339(),
                        };
                        classify_and_emit(
                            &mut ctx,
                            "image",
                            "check",
                            json!({ "healthy": false, "errors": report.errors }),
                            "failure",
                            None,
                            Some("Image store validation failed"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                        } else {
                            eprintln!("Image Store Validation: UNHEALTHY");
                            for err in &report.errors {
                                eprintln!("  [-] {}", err);
                            }
                        }
                        return 1;
                    }
                }
            } else {
                (aiosh_core::base_image_service::ImageStore::new(), aiosh_core::base_image_recovery::RecoveryAction::LoadedExisting)
            };

            let report = aiosh_core::base_image_recovery::validate_store(&active_store);
            let action_name = if is_fix { "image.repair" } else { "image.check" };
            classify_and_emit(
                &mut ctx,
                "image",
                action_name,
                json!({
                    "healthy": report.healthy,
                    "total": report.total_manifests,
                    "valid": report.valid_manifests,
                    "invalid": report.invalid_manifests,
                    "recovery_action": recovery_action
                }),
                if report.healthy { "success" } else { "failure" },
                None,
                Some("Validated base image registry manifests and integrity"),
                "operator",
                None,
            );

            if is_json {
                let out = json!({
                    "report": report,
                    "recovery_action": recovery_action,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                println!("Image Store Validation: {}", if report.healthy { "HEALTHY" } else { "UNHEALTHY" });
                println!("  Total:   {}", report.total_manifests);
                println!("  Valid:   {}", report.valid_manifests);
                println!("  Invalid: {}", report.invalid_manifests);
                if let aiosh_core::base_image_recovery::RecoveryAction::RecoveredFromBackup { backup_path, reason } = &recovery_action {
                    println!("  Recovery: Restored clean store (backup saved at '{}', reason: {})", backup_path, reason);
                }
                for err in &report.errors {
                    eprintln!("  [-] {}", err);
                }
            }

            if report.healthy || is_fix { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh image — Linux Base Image Build & Packaging Manager\n\nUsage:\n  aiosh image list [--json] [--store <path>]\n  aiosh image show <id> [--json] [--store <path>]\n  aiosh image plan <id> [--json] [--store <path>]\n  aiosh image filter [--format <format>] [--distro <id>] [--json] [--store <path>]\n  aiosh image config [--json] [--config <path>]\n  aiosh image policy [<id>] [--json] [--store <path>]\n  aiosh image report [--json] [--store <path>]\n  aiosh image check [--fix] [--json] [--store <path>]");
            0
        }
        Some(other) => {
            eprintln!("unknown image subcommand: {}", other);
            2
        }
    }
}

fn cmd_service(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_opt = parse_flag(rest, "--store");
    if let Some(ref p) = store_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "service",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid store path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    }
    let load_store = || -> Result<aiosh_core::service_service::ServiceStore, String> {
        match store_path_opt {
            Some(ref p) => aiosh_core::service_service::ServiceStore::load_from_path(std::path::Path::new(p)),
            None => Ok(aiosh_core::service_service::ServiceStore::new()),
        }
    };

    match sub {
        Some("validate") => {
            if let Some(name) = parse_flag(rest, "--name") {
                let res = aiosh_core::service::validate_service_name(&name);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("Service name '{}' is valid", name), vec![]),
                    Err(e) => (2, format!("Service name '{}' is invalid: {}", name, e), vec![e]),
                };
                classify_and_emit(
                    &mut ctx,
                    "service",
                    "validate",
                    json!({ "name": name, "valid": code == 0 }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&name),
                    Some(&msg),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "name": name },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Service name '{}' conforms to SS1 naming syntax", name);
                } else {
                    eprintln!("INVALID: {}", msg);
                }
                code
            } else if let Some(spec_str) = parse_flag(rest, "--spec") {
                let content = if std::path::Path::new(&spec_str).exists() {
                    let path = std::path::Path::new(&spec_str);
                    if let Ok(meta) = std::fs::metadata(path) {
                        if meta.len() > 1024 * 1024 {
                            let err_msg = format!("spec file '{}' exceeds 1 MiB size limit (was {} bytes)", spec_str, meta.len());
                            classify_and_emit(
                                &mut ctx,
                                "service",
                                "validate",
                                json!({ "error": err_msg }),
                                "failure",
                                None,
                                Some("Spec file exceeds size limit"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 2;
                        }
                    }
                    match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            let err_msg = format!("failed to read spec file '{}': {}", spec_str, e);
                            classify_and_emit(
                                &mut ctx,
                                "service",
                                "validate",
                                json!({ "error": err_msg }),
                                "failure",
                                None,
                                Some("Failed to read spec file"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 1;
                        }
                    }
                } else {
                    if spec_str.len() > 1024 * 1024 {
                        let err_msg = "inline JSON payload exceeds 1 MiB size limit".to_string();
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Inline JSON exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                    spec_str
                };

                let spec: aiosh_core::service::ServiceSpec = match serde_json::from_str(&content) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("failed to parse service specification JSON: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to parse spec JSON"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "JSON_PARSE_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                };

                let res = aiosh_core::service::validate_service_spec(&spec);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("Service specification '{}' is valid", spec.name), vec![]),
                    Err(errs) => (2, format!("Service specification '{}' violates SS1..SS5 invariants", spec.name), errs),
                };

                classify_and_emit(
                    &mut ctx,
                    "service",
                    "validate",
                    json!({ "name": spec.name, "valid": code == 0, "errors_count": errors.len() }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&spec.name),
                    Some(&msg),
                    "operator",
                    None,
                );

                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "name": spec.name, "spec": spec },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Service specification '{}' conforms to SS1..SS5 invariants", spec.name);
                } else {
                    eprintln!("INVALID: {}", msg);
                    for err in errors {
                        eprintln!("  - {}", err);
                    }
                }
                code
            } else {
                let msg = "Usage: aiosh service validate (--name <name> | --spec <file_or_json>) [--json]";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                2
            }
        }
        Some("list") => {
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "list",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load service store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load service store: {}", e);
                    }
                    return 1;
                }
            };
            let state = match parse_flag(rest, "--state").as_deref() {
                Some("active") => Some(aiosh_core::service::ServiceState::Active),
                Some("inactive") => Some(aiosh_core::service::ServiceState::Inactive),
                Some("activating") => Some(aiosh_core::service::ServiceState::Activating),
                Some("deactivating") => Some(aiosh_core::service::ServiceState::Deactivating),
                Some("failed") => Some(aiosh_core::service::ServiceState::Failed),
                Some("reloading") => Some(aiosh_core::service::ServiceState::Reloading),
                Some(other) => {
                    let msg = format!("unknown state: {}", other);
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid state argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
                None => None,
            };
            let mode = match parse_flag(rest, "--mode").as_deref() {
                Some("enabled") => Some(aiosh_core::service::ServiceStartupMode::Enabled),
                Some("disabled") => Some(aiosh_core::service::ServiceStartupMode::Disabled),
                Some("static") => Some(aiosh_core::service::ServiceStartupMode::Static),
                Some("masked") => Some(aiosh_core::service::ServiceStartupMode::Masked),
                Some(other) => {
                    let msg = format!("unknown mode: {}", other);
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid mode argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
                None => None,
            };
            let pattern = parse_flag(rest, "--pattern");
            if let Some(ref p) = pattern {
                if p.len() > 256 || p.chars().any(|c| c.is_control()) {
                    let msg = "filter pattern cannot exceed 256 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid filter pattern"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let limit = if let Some(s) = parse_flag(rest, "--limit") {
                match s.parse::<usize>() {
                    Ok(n) if n > 0 && n <= 10_000 => Some(n),
                    _ => {
                        let msg = "limit must be a positive integer between 1 and 10,000";
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "list",
                            json!({ "error": msg }),
                            "failure",
                            None,
                            Some("Invalid limit argument"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                }
            } else {
                None
            };

            let query = aiosh_core::service::ServiceQuery {
                name_pattern: pattern,
                state,
                startup_mode: mode,
                limit,
            };
            let services = store.query(&query);
            classify_and_emit(
                &mut ctx,
                "service",
                "list",
                json!({ "count": services.len() }),
                "success",
                None,
                Some("Listed services from store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&services).unwrap_or_default());
            } else {
                println!("AIOS Service Store ({} services):", services.len());
                for svc in services {
                    let st = store.get_status(&svc.name);
                    let state_str = st.map(|s| format!("{:?}", s.state).to_lowercase()).unwrap_or_else(|| "unknown".into());
                    println!("  {:<28} {:<10} {:<10} {}",
                        svc.name,
                        format!("{:?}", svc.service_type).to_lowercase(),
                        state_str,
                        svc.description);
                }
            }
            0
        }
        Some("show") | Some("status") => {
            let name_arg = match rest.first() {
                Some(s) if !s.starts_with("--") => Some(s.to_string()),
                _ => parse_flag(rest, "--name"),
            };
            let name = match name_arg {
                Some(n) => n,
                None => {
                    let msg = "missing service name: aiosh service show <name>";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "show",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing service name argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if name.len() > 128 || name.chars().any(|c| c.is_control()) {
                let msg = format!("service name '{}' is invalid: exceeds 128 characters or contains control characters", name);
                classify_and_emit(
                    &mut ctx,
                    "service",
                    "show",
                    json!({ "name": name, "error": msg }),
                    "failure",
                    Some(&name),
                    Some("Invalid service name"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "show",
                        json!({ "name": name, "error": e }),
                        "failure",
                        Some(&name),
                        Some("Failed to load service store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load service store: {}", e);
                    }
                    return 1;
                }
            };
            match (store.get_service(&name), store.get_status(&name)) {
                (Some(spec), Some(status)) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "show",
                        json!({ "name": name }),
                        "success",
                        Some(&name),
                        Some("Showed service details"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({
                            "code": 0,
                            "data": {
                                "service": spec,
                                "status": status
                            },
                            "error": serde_json::Value::Null
                        }));
                    } else {
                        println!("Service: {}", spec.name);
                        println!("Description: {}", spec.description);
                        println!("Type: {:?}", spec.service_type);
                        println!("State: {:?}", status.state);
                        println!("Startup Mode: {:?}", spec.startup_mode);
                        println!("ExecStart: {}", spec.exec_start);
                        if let Some(ref pid) = status.pid {
                            println!("Main PID: {}", pid);
                        }
                        println!("Healthy: {}", status.health.healthy);
                    }
                    0
                }
                _ => {
                    let msg = format!("service '{}' not found in store", name);
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "show",
                        json!({ "name": name, "error": msg }),
                        "failure",
                        Some(&name),
                        Some("Service not found"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    1
                }
            }
        }
        Some("action") => {
            let positional: Vec<&String> = rest.iter().filter(|s| !s.starts_with("--")).collect();
            if positional.len() < 2 {
                let msg = "Usage: aiosh service action <name> <start|stop|restart|reload|enable|disable|mask|unmask> [--store <path>] [--json]";
                classify_and_emit(
                    &mut ctx,
                    "service",
                    "action",
                    json!({ "error": msg }),
                    "failure",
                    None,
                    Some("Missing arguments for service action"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let name = positional[0];
            let action_str = positional[1].to_lowercase();
            let action = match action_str.as_str() {
                "start" => aiosh_core::service::ServiceAction::Start,
                "stop" => aiosh_core::service::ServiceAction::Stop,
                "restart" => aiosh_core::service::ServiceAction::Restart,
                "reload" => aiosh_core::service::ServiceAction::Reload,
                "enable" => aiosh_core::service::ServiceAction::Enable,
                "disable" => aiosh_core::service::ServiceAction::Disable,
                "mask" => aiosh_core::service::ServiceAction::Mask,
                "unmask" => aiosh_core::service::ServiceAction::Unmask,
                other => {
                    let msg = format!("unknown action '{}': valid actions are start, stop, restart, reload, enable, disable, mask, unmask", other);
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "action",
                        json!({ "name": name, "action": other, "error": msg }),
                        "failure",
                        Some(name),
                        Some("Unknown action"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "action",
                        json!({ "name": name, "action": action_str, "error": e }),
                        "failure",
                        Some(name),
                        Some("Failed to load service store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load service store: {}", e);
                    }
                    return 1;
                }
            };
            match store.execute_action(name, action) {
                Ok(report) => {
                    if let Some(ref p) = store_path_opt {
                        if let Err(e) = store.save_to_path(std::path::Path::new(p)) {
                            let msg = format!("action succeeded but failed to persist store to '{}': {}", p, e);
                            classify_and_emit(
                                &mut ctx,
                                "service",
                                "action",
                                json!({ "name": name, "action": action_str, "error": msg }),
                                "failure",
                                Some(name),
                                Some("Failed to persist store"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "PERSIST_FAILED", "message": msg } }));
                            } else {
                                eprintln!("{}", msg);
                            }
                            return 1;
                        }
                    }
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "action",
                        json!({ "name": name, "action": action_str, "report": report }),
                        "success",
                        Some(name),
                        Some("Executed service action"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({
                            "code": 0,
                            "data": report,
                            "error": serde_json::Value::Null
                        }));
                    } else {
                        println!("Action '{:?}' on service '{}' succeeded (state: {:?} -> {:?})",
                            report.action, report.service_name, report.previous_state, report.new_state);
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "action",
                        json!({ "name": name, "action": action_str, "error": e }),
                        "failure",
                        Some(name),
                        Some("Service action execution failed"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ACTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("action failed: {}", e);
                    }
                    1
                }
            }
        }
        Some(act @ ("start" | "stop" | "restart" | "reload" | "enable" | "disable" | "mask" | "unmask")) => {
            let positional: Vec<&String> = rest.iter().filter(|s| !s.starts_with("--")).collect();
            if positional.is_empty() {
                let msg = format!("Usage: aiosh service {} <name> [--store <path>] [--json]", act);
                classify_and_emit(
                    &mut ctx,
                    "service",
                    act,
                    json!({ "error": msg }),
                    "failure",
                    None,
                    Some("Missing service name argument"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let name = positional[0];
            let mut forwarded_args = vec!["action".to_string(), name.to_string(), act.to_string()];
            let mut skipped_name = false;
            for arg in rest {
                if !skipped_name && arg == name {
                    skipped_name = true;
                    continue;
                }
                forwarded_args.push(arg.clone());
            }
            cmd_service(&forwarded_args)
        }
        Some("order") => {
            let name_arg = match rest.first() {
                Some(s) if !s.starts_with("--") => Some(s.to_string()),
                _ => parse_flag(rest, "--name"),
            };
            let name = match name_arg {
                Some(n) => n,
                None => {
                    let msg = "missing service name: aiosh service order <name>";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "order",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing service name argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "order",
                        json!({ "name": name, "error": e }),
                        "failure",
                        Some(&name),
                        Some("Failed to load service store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load service store: {}", e);
                    }
                    return 1;
                }
            };
            match store.plan_service_order(&name) {
                Ok(order) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "order",
                        json!({ "name": name, "order": order }),
                        "success",
                        Some(&name),
                        Some("Planned service dependency startup sequence"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({
                            "code": 0,
                            "data": {
                                "target": name,
                                "order": order
                            },
                            "error": serde_json::Value::Null
                        }));
                    } else {
                        println!("Activation order for '{}' ({} steps):", name, order.len());
                        for (idx, step) in order.iter().enumerate() {
                            println!("  {}. {}", idx + 1, step);
                        }
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "order",
                        json!({ "name": name, "error": e }),
                        "failure",
                        Some(&name),
                        Some("Failed to plan service order"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ORDER_FAILED", "message": e } }));
                    } else {
                        eprintln!("order planning failed: {}", e);
                    }
                    1
                }
            }
        }
        Some("config") => {
            let config_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = config_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "config path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "config",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid config path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let resolved = match aiosh_core::service_config::ServiceConfig::resolve(config_path_opt.as_deref().map(std::path::Path::new)) {
                Ok(c) => c,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "config",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve service config"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to resolve service config: {}", e);
                    }
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx,
                "service",
                "config",
                json!({ "store_path": resolved.store_path, "auto_persist": resolved.auto_persist }),
                "success",
                None,
                Some("Resolved service configuration"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": resolved, "error": serde_json::Value::Null }));
            } else {
                println!("AIOS Init & Service Supervision Configuration:");
                println!("  Store Path:                 {}", resolved.store_path.display());
                println!("  Default Startup Timeout:    {}s", resolved.default_timeout_start_secs);
                println!("  Default Stop Timeout:       {}s", resolved.default_timeout_stop_secs);
                println!("  Max Store Size:             {} bytes", resolved.max_store_size_bytes);
                println!("  Max Entity Count:           {}", resolved.max_entity_count);
                println!("  Auto Persist:               {}", resolved.auto_persist);
                println!("  Restart Backoff Delay:      {}s", resolved.restart_backoff_secs);
                println!("  Max Restart Burst:          {}", resolved.max_restart_burst);
            }
            0
        }
        Some("policy") => {
            let config_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = config_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "config path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "policy",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid policy config path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let policy = match aiosh_core::service_policy::ServiceSecurityPolicy::resolve(config_path_opt.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "policy",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve service security policy"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to resolve service security policy: {}", e);
                    }
                    return 1;
                }
            };

            let svc_name_opt = parse_flag(rest, "--service").or_else(|| parse_flag(rest, "--name"));
            if let Some(ref name) = svc_name_opt {
                let store = match load_store() {
                    Ok(s) => s,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to load store: {}", e);
                        }
                        return 1;
                    }
                };
                let spec = match store.get_service(name) {
                    Some(s) => s,
                    None => {
                        let msg = format!("service '{}' not found in store", name);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "SERVICE_NOT_FOUND", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                };
                let verdict = policy.evaluate_spec(spec);
                classify_and_emit(
                    &mut ctx,
                    "service",
                    "policy",
                    json!({ "service": name, "allowed": verdict.allowed, "violations": verdict.violations.len() }),
                    if verdict.allowed { "success" } else { "failure" },
                    Some(name),
                    Some("Evaluated service security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": verdict, "error": serde_json::Value::Null }));
                } else {
                    println!("Service Security Policy Verdict for '{}':", name);
                    println!("  Allowed:    {}", verdict.allowed);
                    println!("  Mode:       {:?}", verdict.mode);
                    println!("  Violations: {}", verdict.violations.len());
                    for v in &verdict.violations {
                        println!("    [{}] {}: {}", if v.fatal { "FATAL" } else { "WARN" }, v.rule_id, v.description);
                    }
                }
                if verdict.allowed { 0 } else { 1 }
            } else {
                classify_and_emit(
                    &mut ctx,
                    "service",
                    "policy",
                    json!({ "mode": format!("{:?}", policy.mode) }),
                    "success",
                    None,
                    Some("Inspected service security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": policy, "error": serde_json::Value::Null }));
                } else {
                    println!("AIOS Init & Service Supervision Security Policy:");
                    println!("  Mode:                       {:?}", policy.mode);
                    println!("  Require Service User:       {}", policy.require_service_user);
                    println!("  Disallow Root:              {}", policy.disallow_root);
                    println!("  Max Environment Variables:  {}", policy.max_env_vars);
                    println!("  Max Timeout (s):            {}s", policy.max_timeout_secs);
                    println!("  Prohibited Services:        {}", policy.prohibited_services.join(", "));
                    println!("  Prohibited Exec Paths:      {}", policy.prohibited_exec_paths.join(", "));
                    println!("  Disallowed Env Vars:        {}", policy.disallow_env_vars.join(", "));
                    println!("  Allowed Root Services:      {}", policy.allowed_root_services.join(", "));
                }
                0
            }
        }
        Some("stats") | Some("observability") => {
            let store_path_opt = parse_flag(rest, "--store");
            if let Some(ref p) = store_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "stats",
                        json!({ "error": msg }),
                        "failure",
                        Some("INVALID_ARGUMENT"),
                        Some("Invalid store path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let policy_path_opt = parse_flag(rest, "--policy").or_else(|| parse_flag(rest, "--config"));
            if let Some(ref p) = policy_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "policy path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "stats",
                        json!({ "error": msg }),
                        "failure",
                        Some("INVALID_ARGUMENT"),
                        Some("Invalid policy path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "service",
                        "stats",
                        json!({ "error": e }),
                        "failure",
                        Some("LOAD_STORE_FAILED"),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", e);
                    }
                    return 1;
                }
            };
            let policy = if let Some(ref p) = policy_path_opt {
                match aiosh_core::service_policy::ServiceSecurityPolicy::from_file(std::path::Path::new(p)) {
                    Ok(pol) => Some(pol),
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "stats",
                            json!({ "error": e }),
                            "failure",
                            Some("LOAD_POLICY_FAILED"),
                            Some("Failed to load policy"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_POLICY_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to load policy: {}", e);
                        }
                        return 1;
                    }
                }
            } else {
                aiosh_core::service_policy::ServiceSecurityPolicy::resolve(None).ok()
            };

            let report = aiosh_core::service_observability::ServiceObservabilityReport::generate(&store, policy.as_ref());
            classify_and_emit(
                &mut ctx,
                "service",
                "stats",
                json!({
                    "total_services": report.total_services,
                    "healthy_count": report.healthy_count,
                    "unhealthy_count": report.unhealthy_count,
                    "total_restarts": report.total_restarts,
                    "policy_compliant": report.policy_compliant_count,
                }),
                "success",
                None,
                Some("Generated service observability telemetry report"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("AIOS Init & Service Supervision Observability Report:");
                println!("  Total Services:         {}", report.total_services);
                println!("  Healthy Services:       {}", report.healthy_count);
                println!("  Unhealthy Services:     {}", report.unhealthy_count);
                println!("  Total Process Restarts: {}", report.total_restarts);
                println!("  Policy Compliant:       {}", report.policy_compliant_count);
                println!("  Policy Violations:      {}", report.policy_violations_count);
                if !report.prohibited_services_found.is_empty() {
                    println!("  Prohibited Services:    {}", report.prohibited_services_found.join(", "));
                }
                println!("  State Breakdown:");
                for (k, v) in &report.state_breakdown {
                    println!("    {:<14} {}", k, v);
                }
                println!("  Startup Mode Breakdown:");
                for (k, v) in &report.startup_mode_breakdown {
                    println!("    {:<14} {}", k, v);
                }
                println!("  Service Type Breakdown:");
                for (k, v) in &report.service_type_breakdown {
                    println!("    {:<14} {}", k, v);
                }
                println!("  Restart Policy Breakdown:");
                for (k, v) in &report.restart_policy_breakdown {
                    println!("    {:<14} {}", k, v);
                }
                println!("  Dependency Distribution:");
                for (k, v) in &report.dependency_distribution {
                    println!("    {:<14} {}", k, v);
                }
            }
            0
        }
        Some("check") => {
            let is_fix = has_flag(rest, "--fix");
            let target_path = if let Some(ref p) = store_path_opt {
                std::path::PathBuf::from(p)
            } else {
                std::path::PathBuf::from("/var/lib/aios/services.json")
            };

            let (_store, report, recovered, backup_opt) = if is_fix {
                match aiosh_core::service_recovery::load_or_recover(&target_path) {
                    Ok(res) => res,
                    Err(e) => {
                        let msg = format!("recovery failed: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "check",
                            json!({ "error": msg }),
                            "failure",
                            Some("RECOVERY_FAILED"),
                            Some("Failed to recover service store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RECOVERY_FAILED", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }
                }
            } else if target_path.exists() {
                match aiosh_core::service_service::ServiceStore::load_from_path(&target_path) {
                    Ok(s) => {
                        let rep = aiosh_core::service_recovery::validate_service_store(&s, &target_path);
                        (s, rep, false, None)
                    }
                    Err(e) => {
                        let rep = aiosh_core::service_recovery::ServiceValidationReport {
                            store_path: target_path.to_string_lossy().to_string(),
                            total_services: 0,
                            valid_services: 0,
                            invalid_services: 0,
                            errors: vec![format!("failed to load service store: {}", e)],
                            warnings: vec![],
                            healthy: false,
                            evaluated_at: chrono::Utc::now().to_rfc3339(),
                        };
                        classify_and_emit(
                            &mut ctx,
                            "service",
                            "check",
                            json!({ "healthy": false, "errors": rep.errors }),
                            "failure",
                            Some("LOAD_STORE_FAILED"),
                            Some("Service store check failed"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({
                                "code": 1,
                                "data": serde_json::Value::Null,
                                "error": {
                                    "code": "LOAD_STORE_FAILED",
                                    "message": format!("Service store at {} is corrupted or unreadable. Run with --fix to recover.", target_path.display()),
                                    "report": rep
                                }
                            }));
                        } else {
                            eprintln!("Service Store Validation: UNHEALTHY");
                            for err in &rep.errors {
                                eprintln!("  [-] {}", err);
                            }
                            eprintln!("Hint: Run with --fix to automatically recover.");
                        }
                        return 1;
                    }
                }
            } else {
                let s = aiosh_core::service_service::ServiceStore::new();
                let rep = aiosh_core::service_recovery::validate_service_store(&s, &target_path);
                (s, rep, false, None)
            };

            let action_name = if is_fix && recovered { "service.repair" } else { "service.check" };
            classify_and_emit(
                &mut ctx,
                "service",
                action_name,
                json!({
                    "healthy": report.healthy,
                    "total_services": report.total_services,
                    "valid_services": report.valid_services,
                    "invalid_services": report.invalid_services,
                    "recovered": recovered,
                    "backup_path": backup_opt.as_ref().map(|p| p.to_string_lossy().to_string()),
                }),
                if report.healthy { "success" } else { "failure" },
                None,
                Some("Validated service store integrity and recovery state"),
                "operator",
                None,
            );

            if is_json {
                let out = json!({
                    "report": report,
                    "recovered": recovered,
                    "backup_path": backup_opt.map(|p| p.to_string_lossy().to_string()),
                });
                if report.healthy {
                    println!("{}", json!({ "code": 0, "data": out, "error": serde_json::Value::Null }));
                } else {
                    println!("{}", json!({ "code": 1, "data": out, "error": { "code": "VALIDATION_FAILED", "message": "Service store validation failed" } }));
                }
            } else if report.healthy {
                if recovered {
                    println!("Service store at '{}' was recovered successfully from backup.", target_path.display());
                    if let Some(ref bp) = backup_opt {
                        println!("Quarantine backup preserved at: {}", bp.display());
                    }
                }
                println!("Service Store Validation: HEALTHY ({} services verified)", report.valid_services);
            } else {
                eprintln!("Service Store Validation: UNHEALTHY");
                for err in &report.errors {
                    eprintln!("  [-] {}", err);
                }
                if !is_fix {
                    eprintln!("Hint: Run with --fix to automatically recover.");
                }
            }

            if report.healthy { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh service — Init & Service Supervision Manager\n\nUsage: aiosh service <command> [options]\n\nCommands:\n  validate  Validate service name (SS1) or specification file/json (SS1..SS5)\n  list      List services in store with optional state, mode, and pattern filters\n  show      Display detailed service specification and runtime status (alias: status)\n  action    Execute a lifecycle action (start, stop, restart, reload, enable, disable, mask, unmask)\n  start     Start a service unit (shortcut for action <name> start)\n  stop      Stop a service unit (shortcut for action <name> stop)\n  restart   Restart a service unit (shortcut for action <name> restart)\n  reload    Reload a service unit configuration (shortcut for action <name> reload)\n  enable    Enable a service for automatic startup (shortcut for action <name> enable)\n  disable   Disable a service from automatic startup (shortcut for action <name> disable)\n  mask      Mask a service to prevent activation (shortcut for action <name> mask)\n  unmask    Unmask a service to allow activation (shortcut for action <name> unmask)\n  order     Calculate deterministic dependency startup sequence for a service\n  config    Inspect Init & Service Supervision configuration parameters\n  policy    Inspect or evaluate service security policy (SP1..SP6)\n  stats     Display comprehensive supervision observability report (alias: observability)\n  check     Validate service store integrity (with --fix to auto-recover)");
            0
        }
        Some(other) => {
            let msg = format!("unknown service subcommand: {}", other);
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            2
        }
    }
}

fn cmd_session(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_opt = parse_flag(rest, "--store");
    if let Some(ref p) = store_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "session",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid store path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    }

    let load_service = || -> Result<aiosh_core::session_service::UserSessionService, String> {
        match store_path_opt {
            Some(ref p) => aiosh_core::session_service::UserSessionService::load_from_path(std::path::Path::new(p)).map_err(|e| e.to_string()),
            None => Ok(aiosh_core::session_service::UserSessionService::new()),
        }
    };

    match sub {
        Some("validate") => {
            if let Some(id) = parse_flag(rest, "--id") {
                let res = aiosh_core::session::validate_session_id(&id);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("Session ID '{}' is valid", id), vec![]),
                    Err(e) => (2, format!("Session ID '{}' is invalid: {}", id, e), vec![e]),
                };
                classify_and_emit(
                    &mut ctx,
                    "session",
                    "validate",
                    json!({ "session_id": id, "valid": code == 0 }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&id),
                    Some(&msg),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "session_id": id },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Session ID '{}' conforms to SB1 naming syntax", id);
                } else {
                    eprintln!("INVALID: {}", msg);
                }
                code
            } else if let Some(user) = parse_flag(rest, "--user") {
                let res = aiosh_core::session::validate_username(&user);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("Username '{}' is valid", user), vec![]),
                    Err(e) => (2, format!("Username '{}' is invalid: {}", user, e), vec![e]),
                };
                classify_and_emit(
                    &mut ctx,
                    "session",
                    "validate",
                    json!({ "username": user, "valid": code == 0 }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&user),
                    Some(&msg),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "username": user },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Username '{}' conforms to SB2 user identity syntax", user);
                } else {
                    eprintln!("INVALID: {}", msg);
                }
                code
            } else if let Some(spec_str) = parse_flag(rest, "--spec") {
                let content = if std::path::Path::new(&spec_str).exists() {
                    let path = std::path::Path::new(&spec_str);
                    if let Ok(meta) = std::fs::metadata(path) {
                        if meta.len() > 1024 * 1024 {
                            let err_msg = format!("spec file '{}' exceeds 1 MiB size limit (was {} bytes)", spec_str, meta.len());
                            classify_and_emit(
                                &mut ctx,
                                "session",
                                "validate",
                                json!({ "error": err_msg }),
                                "failure",
                                None,
                                Some("Spec file exceeds size limit"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 2;
                        }
                    }
                    match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            let err_msg = format!("failed to read spec file '{}': {}", spec_str, e);
                            classify_and_emit(
                                &mut ctx,
                                "session",
                                "validate",
                                json!({ "error": err_msg }),
                                "failure",
                                None,
                                Some("Failed to read spec file"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 2;
                        }
                    }
                } else {
                    if spec_str.len() > 1024 * 1024 {
                        let err_msg = "inline JSON payload exceeds 1 MiB size limit".to_string();
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Inline JSON exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                    spec_str
                };

                let spec: aiosh_core::session::UserSessionSpec = match serde_json::from_str(&content) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("failed to parse user session specification JSON: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to parse spec JSON"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "JSON_PARSE_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                };

                let res = aiosh_core::session::validate_user_session_spec(&spec);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("User session specification '{}' is valid", spec.session_id), vec![]),
                    Err(errs) => (2, format!("User session specification '{}' violates SB1..SB5 invariants", spec.session_id), errs),
                };

                classify_and_emit(
                    &mut ctx,
                    "session",
                    "validate",
                    json!({ "session_id": spec.session_id, "valid": code == 0, "errors_count": errors.len() }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&spec.session_id),
                    Some(&msg),
                    "operator",
                    None,
                );

                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "session_id": spec.session_id, "spec": spec },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: User session specification '{}' conforms to SB1..SB5 invariants", spec.session_id);
                } else {
                    eprintln!("INVALID: {}", msg);
                    for err in errors {
                        eprintln!("  - {}", err);
                    }
                }
                code
            } else {
                let msg = "Usage: aiosh session validate (--id <id> | --user <username> | --spec <file_or_json>) [--json]";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                2
            }
        }
        Some("list") => {
            let service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "list",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load session store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let username = parse_flag(rest, "--user");
            let state = parse_flag(rest, "--state").and_then(|st| match st.to_lowercase().as_str() {
                "initializing" => Some(aiosh_core::session::SessionState::Initializing),
                "authenticating" => Some(aiosh_core::session::SessionState::Authenticating),
                "active" => Some(aiosh_core::session::SessionState::Active),
                "locked" => Some(aiosh_core::session::SessionState::Locked),
                "terminating" => Some(aiosh_core::session::SessionState::Terminating),
                "terminated" => Some(aiosh_core::session::SessionState::Terminated),
                _ => None,
            });
            let session_type = parse_flag(rest, "--type").and_then(|t| match t.to_lowercase().as_str() {
                "tty" => Some(aiosh_core::session::SessionType::Tty),
                "x11" => Some(aiosh_core::session::SessionType::X11),
                "wayland" => Some(aiosh_core::session::SessionType::Wayland),
                "ai_agent" | "aiagent" | "agent" => Some(aiosh_core::session::SessionType::AiAgent),
                _ => None,
            });
            let seat = parse_flag(rest, "--seat");
            let limit = if let Some(s) = parse_flag(rest, "--limit") {
                match s.parse::<usize>() {
                    Ok(n) if n > 0 && n <= 10_000 => Some(n),
                    _ => {
                        let msg = "limit must be a positive integer between 1 and 10,000";
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "list",
                            json!({ "error": msg }),
                            "failure",
                            None,
                            Some("Invalid limit argument"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                }
            } else {
                None
            };

            let query = aiosh_core::session::UserSessionQuery {
                username,
                state,
                session_type,
                seat,
                limit,
            };

            let sessions = service.query_sessions(&query);
            classify_and_emit(
                &mut ctx,
                "session",
                "list",
                json!({ "count": sessions.len() }),
                "success",
                None,
                Some("Queried user sessions"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "sessions": sessions, "count": sessions.len() }, "error": serde_json::Value::Null }));
            } else {
                println!("{:<16} {:<12} {:<14} {:<12} {:<8} {:<8}", "SESSION_ID", "USER", "STATE", "SCOPE", "LOCKED", "IDLE(s)");
                for s in &sessions {
                    println!("{:<16} {:<12} {:<14} {:<12} {:<8} {:<8}", s.session_id, s.username, format!("{:?}", s.state), format!("{:?}", s.scope), s.locked, s.idle_seconds);
                }
            }
            0
        }
        Some("show") | Some("get") => {
            let session_id = rest.first().filter(|s| !s.starts_with('-'));
            let session_id = match session_id {
                Some(id) => id.as_str(),
                None => {
                    let msg = "Usage: aiosh session show <session_id> [--json] [--store <path>]";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let status = service.get_session(session_id);
            let spec = service.get_spec(session_id);

            match (status, spec) {
                (Some(st), Some(sp)) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "show",
                        json!({ "session_id": session_id, "state": format!("{:?}", st.state) }),
                        "success",
                        Some(session_id),
                        Some("Retrieved session details"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "status": st, "spec": sp }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Session ID:      {}", st.session_id);
                        println!("Username:        {} (UID: {})", st.username, st.uid);
                        println!("State:           {:?}", st.state);
                        println!("Scope:           {:?}", st.scope);
                        println!("Type:            {:?}", sp.session_type);
                        println!("Class:           {:?}", sp.session_class);
                        println!("Seat:            {}", sp.seat);
                        if let Some(vtnr) = sp.vtnr { println!("VTNR:            {}", vtnr); }
                        if let Some(ref disp) = sp.display { println!("Display:         {}", disp); }
                        println!("Leader PID:      {:?}", st.leader_pid);
                        println!("Locked:          {}", st.locked);
                        println!("Idle Seconds:    {}", st.idle_seconds);
                        println!("Created At:      {}", st.created_at);
                        println!("Last Active At:  {}", st.last_active_at);
                    }
                    0
                }
                _ => {
                    let msg = format!("session '{}' not found", session_id);
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "show",
                        json!({ "session_id": session_id, "error": msg }),
                        "failure",
                        Some(session_id),
                        Some("Session not found"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    1
                }
            }
        }
        Some("action") => {
            let session_id = rest.first().filter(|s| !s.starts_with('-'));
            let action_str = rest.get(1).filter(|s| !s.starts_with('-'));
            let (session_id, action_str) = match (session_id, action_str) {
                (Some(id), Some(act)) => (id.as_str(), act.as_str()),
                _ => {
                    let msg = "Usage: aiosh session action <session_id> <authenticate|activate|lock|unlock|terminate> [--json] [--store <path>]";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let action = match action_str.to_lowercase().as_str() {
                "authenticate" => aiosh_core::session::UserSessionAction::Authenticate,
                "activate" => aiosh_core::session::UserSessionAction::Activate,
                "lock" => aiosh_core::session::UserSessionAction::Lock,
                "unlock" => aiosh_core::session::UserSessionAction::Unlock,
                "terminate" => aiosh_core::session::UserSessionAction::Terminate,
                other => {
                    let msg = format!("unknown session action: '{}'", other);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let report = match service.apply_action(session_id, action) {
                Ok(rep) => rep,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "action",
                        json!({ "session_id": session_id, "action": action_str, "error": e }),
                        "failure",
                        Some(session_id),
                        Some("Session action execution failed"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ACTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Action failed: {}", e);
                    }
                    return 1;
                }
            };

            if let Some(ref p) = store_path_opt {
                if let Err(e) = service.save_to_path(p) {
                    eprintln!("Warning: failed to persist session store to '{}': {}", p, e);
                }
            }

            classify_and_emit(
                &mut ctx,
                "session",
                "action",
                json!({
                    "session_id": session_id,
                    "action": action_str,
                    "previous_state": format!("{:?}", report.previous_state),
                    "new_state": format!("{:?}", report.new_state),
                }),
                "success",
                Some(session_id),
                Some("Session action applied successfully"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Action '{}' applied to session '{}': {:?} -> {:?}", action_str, session_id, report.previous_state, report.new_state);
            }
            0
        }
        Some("create") => {
            let input_arg = rest.first().filter(|s| !s.starts_with('-'));
            let input = match input_arg {
                Some(s) => s.as_str(),
                None => {
                    let msg = "Usage: aiosh session create <spec_file_or_json> [--json] [--store <path>]";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let path = std::path::Path::new(input);
            let content = if path.exists() && path.is_file() {
                if let Ok(meta) = path.metadata() {
                    if meta.len() > 1024 * 1024 {
                        let err_msg = format!("spec file '{}' exceeds 1 MiB size limit", input);
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "create",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Spec file exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        let err_msg = format!("failed to read spec file '{}': {}", input, e);
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "create",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to read spec file"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                }
            } else {
                if input.len() > 1024 * 1024 {
                    let err_msg = "inline JSON payload exceeds 1 MiB size limit".to_string();
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "create",
                        json!({ "error": err_msg }),
                        "failure",
                        None,
                        Some("Inline JSON exceeds size limit"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                    } else {
                        eprintln!("{}", err_msg);
                    }
                    return 2;
                }
                input.to_string()
            };

            let spec: aiosh_core::session::UserSessionSpec = match serde_json::from_str(&content) {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("failed to parse user session specification JSON: {}", e);
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "create",
                        json!({ "error": err_msg }),
                        "failure",
                        None,
                        Some("Failed to parse spec JSON"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "JSON_PARSE_ERROR", "message": err_msg } }));
                    } else {
                        eprintln!("{}", err_msg);
                    }
                    return 2;
                }
            };

            if let Err(errs) = aiosh_core::session::validate_user_session_spec(&spec) {
                let err_msg = format!("User session specification '{}' violates SB1..SB5 invariants: {}", spec.session_id, errs.join("; "));
                classify_and_emit(
                    &mut ctx,
                    "session",
                    "create",
                    json!({ "session_id": spec.session_id, "errors": errs }),
                    "failure",
                    Some(&spec.session_id),
                    Some("Spec violates invariants"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_FAILED", "message": err_msg, "errors": errs } }));
                } else {
                    eprintln!("{}", err_msg);
                }
                return 2;
            }

            let mut service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let session_id = spec.session_id.clone();
            let username = spec.username.clone();
            let seat = spec.seat.clone();

            let report = match service.create_session(spec) {
                Ok(rep) => rep,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "create",
                        json!({ "session_id": session_id, "error": e }),
                        "failure",
                        Some(&session_id),
                        Some("Session creation failed"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CREATE_FAILED", "message": e } }));
                    } else {
                        eprintln!("Error creating session: {}", e);
                    }
                    return 1;
                }
            };

            if let Some(ref p) = store_path_opt {
                if let Err(e) = service.save_to_path(p) {
                    eprintln!("Warning: failed to persist session store to '{}': {}", p, e);
                }
            }

            classify_and_emit(
                &mut ctx,
                "session",
                "create",
                json!({ "session_id": session_id, "username": username, "seat": seat }),
                "success",
                Some(&session_id),
                Some("Session created successfully"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Created session '{}' for user '{}' on seat '{}' (state: {:?})", session_id, username, seat, report.new_state);
            }
            0
        }
        Some("status") => {
            let mut forwarded = vec!["show".to_string()];
            forwarded.extend_from_slice(rest);
            cmd_session(&forwarded)
        }
        Some("activate") | Some("lock") | Some("unlock") | Some("terminate") | Some("auth") | Some("authenticate") => {
            let act_name = match sub {
                Some("auth") => "authenticate",
                Some(other) => other,
                None => "activate",
            };
            let session_id = rest.first().filter(|s| !s.starts_with('-'));
            let session_id = match session_id {
                Some(id) => id.as_str(),
                None => {
                    let msg = format!("Usage: aiosh session {} <session_id> [--json] [--store <path>]", act_name);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENTS", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let mut forwarded = vec!["action".to_string(), session_id.to_string(), act_name.to_string()];
            let mut skipped_id = false;
            for arg in rest {
                if !skipped_id && arg == session_id {
                    skipped_id = true;
                    continue;
                }
                forwarded.push(arg.clone());
            }
            cmd_session(&forwarded)
        }
        Some("config") => {
            let config_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = config_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "config path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "config",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid config path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let resolved = match aiosh_core::session_config::SessionConfig::resolve(config_path_opt.as_deref().map(std::path::Path::new)) {
                Ok(c) => c,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "config",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve session config"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to resolve session config: {}", e);
                    }
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx,
                "session",
                "config",
                json!({ "store_path": resolved.store_path, "auto_persist": resolved.auto_persist }),
                "success",
                None,
                Some("Resolved session configuration"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": resolved, "error": serde_json::Value::Null }));
            } else {
                println!("AIOS User Session Bootstrap Configuration:");
                println!("  Store Path:                 {}", resolved.store_path.display());
                println!("  Max Sessions Per User:      {}", resolved.max_sessions_per_user);
                println!("  Max Total Sessions:         {}", resolved.max_total_sessions);
                println!("  Default Idle Timeout:       {}s", resolved.default_idle_timeout_seconds);
                println!("  Max Store Size:             {} bytes", resolved.max_store_size_bytes);
                println!("  Auto Persist:               {}", resolved.auto_persist);
            }
            0
        }
        Some("policy") => {
            let policy_path_opt = parse_flag(rest, "--policy");
            let spec_path_or_json = parse_flag(rest, "--spec");
            let policy = match policy_path_opt {
                Some(ref p) => match aiosh_core::session_policy::UserSessionSecurityPolicy::from_file(std::path::Path::new(p)) {
                    Ok(pol) => pol,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "policy",
                            json!({ "error": e }),
                            "failure",
                            None,
                            Some("Failed to load session security policy"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_LOAD_FAILED", "message": e } }));
                        } else {
                            eprintln!("Failed to load session security policy: {}", e);
                        }
                        return 1;
                    }
                },
                None => aiosh_core::session_policy::UserSessionSecurityPolicy::default(),
            };

            if let Some(ref spec_input) = spec_path_or_json {
                let content = if std::path::Path::new(spec_input).exists() {
                    match std::fs::read_to_string(spec_input) {
                        Ok(c) => c,
                        Err(e) => {
                            let err_msg = format!("failed to read session specification file '{}': {}", spec_input, e);
                            classify_and_emit(&mut ctx, "session", "policy", json!({ "error": err_msg }), "failure", None, Some("Failed to read spec file"), "operator", None);
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 1;
                        }
                    }
                } else {
                    spec_input.clone()
                };

                let spec: aiosh_core::session::UserSessionSpec = match serde_json::from_str(&content) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("failed to parse user session specification JSON: {}", e);
                        classify_and_emit(&mut ctx, "session", "policy", json!({ "error": err_msg }), "failure", None, Some("Failed to parse spec JSON"), "operator", None);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "PARSE_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 1;
                    }
                };

                let verdict = policy.evaluate_spec(&spec);
                let passed = verdict.allowed;
                classify_and_emit(
                    &mut ctx,
                    "session",
                    "policy",
                    json!({ "session_id": spec.session_id, "allowed": passed, "violations": verdict.violations.len() }),
                    if passed { "success" } else { "failure" },
                    Some(&spec.session_id),
                    Some("Evaluated session specification against security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": if passed { 0 } else { 1 },
                        "data": verdict,
                        "error": if passed { serde_json::Value::Null } else { json!({ "code": "POLICY_VIOLATION", "message": format!("Session '{}' violated security policy", spec.session_id), "violations": verdict.violations }) }
                    }));
                } else if passed {
                    println!("PASSED: Session '{}' conforms to security policy (mode: {:?})", spec.session_id, policy.mode);
                } else {
                    eprintln!("FAILED: Session '{}' violated security policy (mode: {:?}):", spec.session_id, policy.mode);
                    for v in &verdict.violations {
                        eprintln!("  [{}] {}", v.rule_id, v.description);
                    }
                }
                return if passed { 0 } else { 1 };
            }

            // Evaluate entire store if --spec is not provided
            let service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(&mut ctx, "session", "policy", json!({ "error": e }), "failure", None, Some("Failed to load session store"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STORE_LOAD_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let verdicts = policy.evaluate_store(&service.store);
            let any_failed = verdicts.iter().any(|v| !v.allowed);
            let total_violations: usize = verdicts.iter().map(|v| v.violations.len()).sum();
            classify_and_emit(
                &mut ctx,
                "session",
                "policy",
                json!({ "verdicts_count": verdicts.len(), "total_violations": total_violations, "allowed": !any_failed }),
                if !any_failed { "success" } else { "failure" },
                None,
                Some("Evaluated session store against security policy"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": if !any_failed { 0 } else { 1 },
                    "data": { "mode": policy.mode, "verdicts": verdicts, "total_violations": total_violations, "allowed": !any_failed },
                    "error": if !any_failed { serde_json::Value::Null } else { json!({ "code": "POLICY_VIOLATION", "message": "One or more sessions violated security policy" }) }
                }));
            } else if !any_failed {
                println!("PASSED: All sessions in store conform to security policy (mode: {:?}, evaluated: {})", policy.mode, verdicts.len());
            } else {
                eprintln!("FAILED: Session store contains security policy violations (mode: {:?}):", policy.mode);
                for v in &verdicts {
                    for viol in &v.violations {
                        eprintln!("  [{}] ({}) {}", viol.rule_id, viol.session_id, viol.description);
                    }
                }
            }
            if !any_failed { 0 } else { 1 }
        }
        Some("stats") => {
            let policy_path_opt = parse_flag(rest, "--policy");
            if let Some(ref p) = policy_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "policy path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "stats",
                        json!({ "error": msg }),
                        "failure",
                        Some("INVALID_ARGUMENT"),
                        Some("Invalid policy path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }

            let service = match load_service() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "session",
                        "stats",
                        json!({ "error": e }),
                        "failure",
                        Some("LOAD_STORE_FAILED"),
                        Some("Failed to load session store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to load session store: {}", e);
                    }
                    return 1;
                }
            };

            let policy = match policy_path_opt {
                Some(ref p) => match aiosh_core::session_policy::UserSessionSecurityPolicy::from_file(std::path::Path::new(p)) {
                    Ok(pol) => pol,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "stats",
                            json!({ "error": e }),
                            "failure",
                            Some("POLICY_RESOLUTION_FAILED"),
                            Some("Failed to resolve session security policy"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_RESOLUTION_FAILED", "message": e } }));
                        } else {
                            eprintln!("Failed to resolve session security policy: {}", e);
                        }
                        return 1;
                    }
                },
                None => aiosh_core::session_policy::UserSessionSecurityPolicy::default(),
            };

            let report = aiosh_core::session_observability::SessionObservabilityReport::generate(&service.store, Some(&policy));

            classify_and_emit(
                &mut ctx,
                "session",
                "stats",
                json!({
                    "total_sessions": report.total_sessions,
                    "distinct_users": report.distinct_users_count,
                    "locked_count": report.locked_count,
                    "idle_sessions": report.idle_sessions_count,
                    "policy_violations": report.policy_violations_count
                }),
                "success",
                None,
                Some("Generated session observability report"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": report,
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("User Session Observability Report:");
                println!("  Total Sessions:        {}", report.total_sessions);
                println!("  Distinct Users:        {}", report.distinct_users_count);
                println!("  Locked Sessions:       {}", report.locked_count);
                println!("  Idle Sessions:         {}", report.idle_sessions_count);
                println!("  Max Idle Duration:     {}s", report.max_idle_seconds);
                println!("  Total Idle Duration:   {}s", report.total_idle_seconds);
                println!("  Policy Compliant:      {}", report.policy_compliant_count);
                println!("  Policy Violations:     {}", report.policy_violations_count);
            }
            0
        }
        Some("check") | Some("recover") => {
            let is_fix = sub == Some("recover") || has_flag(rest, "--fix");
            let target_path = if let Some(ref p) = store_path_opt {
                std::path::PathBuf::from(p)
            } else {
                std::path::PathBuf::from("/var/run/aios/sessions.json")
            };

            let (_service, report, recovered, backup_opt) = if is_fix {
                match aiosh_core::session_recovery::load_or_recover(&target_path) {
                    Ok(res) => res,
                    Err(e) => {
                        let msg = format!("recovery failed: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "check",
                            json!({ "error": msg }),
                            "failure",
                            Some("RECOVERY_FAILED"),
                            Some("Failed to recover user session store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RECOVERY_FAILED", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }
                }
            } else if target_path.exists() {
                match aiosh_core::session_service::UserSessionService::load_from_path(&target_path) {
                    Ok(s) => {
                        let rep = aiosh_core::session_recovery::validate_session_store(&s.store, &target_path);
                        (s, rep, false, None)
                    }
                    Err(e) => {
                        let rep = aiosh_core::session_recovery::SessionValidationReport {
                            store_path: target_path.to_string_lossy().to_string(),
                            total_sessions: 0,
                            valid_sessions: 0,
                            invalid_sessions: 0,
                            errors: vec![format!("failed to load session store: {}", e)],
                            warnings: vec![],
                            healthy: false,
                            evaluated_at: chrono::Utc::now().to_rfc3339(),
                        };
                        classify_and_emit(
                            &mut ctx,
                            "session",
                            "check",
                            json!({ "healthy": false, "errors": rep.errors }),
                            "failure",
                            Some("LOAD_STORE_FAILED"),
                            Some("Session store check failed"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({
                                "code": 1,
                                "data": serde_json::Value::Null,
                                "error": {
                                    "code": "LOAD_STORE_FAILED",
                                    "message": format!("Session store at {} is corrupted or unreadable. Run with --fix to recover.", target_path.display()),
                                    "report": rep
                                }
                            }));
                        } else {
                            eprintln!("Session Store Validation: UNHEALTHY");
                            for err in &rep.errors {
                                eprintln!("  [-] {}", err);
                            }
                            eprintln!("Hint: Run with --fix to automatically recover.");
                        }
                        return 1;
                    }
                }
            } else {
                let s = aiosh_core::session_service::UserSessionService::new();
                let rep = aiosh_core::session_recovery::validate_session_store(&s.store, &target_path);
                (s, rep, false, None)
            };

            let action_name = if is_fix && recovered { "session.repair" } else { "session.check" };
            classify_and_emit(
                &mut ctx,
                "session",
                action_name,
                json!({
                    "healthy": report.healthy,
                    "total_sessions": report.total_sessions,
                    "valid_sessions": report.valid_sessions,
                    "invalid_sessions": report.invalid_sessions,
                    "recovered": recovered,
                    "backup_path": backup_opt.as_ref().map(|p| p.to_string_lossy().to_string()),
                    "errors_count": report.errors.len(),
                    "warnings_count": report.warnings.len()
                }),
                if report.healthy { "success" } else { "failure" },
                None,
                Some(if recovered { "Recovered user session store" } else { "Checked user session store" }),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": if report.healthy { 0 } else { 1 },
                    "data": {
                        "healthy": report.healthy,
                        "recovered": recovered,
                        "backup_path": backup_opt.map(|p| p.to_string_lossy().to_string()),
                        "total_sessions": report.total_sessions,
                        "valid_sessions": report.valid_sessions,
                        "invalid_sessions": report.invalid_sessions,
                        "errors": report.errors,
                        "warnings": report.warnings,
                        "evaluated_at": report.evaluated_at,
                        "store_path": report.store_path
                    },
                    "error": if report.healthy { serde_json::Value::Null } else {
                        json!({ "code": "VALIDATION_FAILED", "message": "Session store has validation errors" })
                    }
                }));
            } else {
                println!("User Session Store Validation Report:");
                println!("  Store Path:        {}", report.store_path);
                println!("  Status:            {}", if report.healthy { "HEALTHY" } else { "UNHEALTHY" });
                println!("  Total Sessions:    {}", report.total_sessions);
                println!("  Valid Sessions:    {}", report.valid_sessions);
                println!("  Invalid Sessions:  {}", report.invalid_sessions);
                if recovered {
                    println!("  [+] Recovered: Store was repaired using canonical default");
                    if let Some(bak) = backup_opt {
                        println!("  [+] Quarantined Backup: {}", bak.display());
                    }
                }
                if !report.errors.is_empty() {
                    println!("  Errors ({}):", report.errors.len());
                    for err in &report.errors {
                        println!("    [-] {}", err);
                    }
                }
                if !report.warnings.is_empty() {
                    println!("  Warnings ({}):", report.warnings.len());
                    for warn in &report.warnings {
                        println!("    [!] {}", warn);
                    }
                }
            }

            if report.healthy { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh session — User Session Bootstrap Manager\n\nUsage:\n  aiosh session validate (--id <id> | --user <username> | --spec <file_or_json>) [--json]\n  aiosh session list [--user <username>] [--state <state>] [--type <type>] [--seat <seat>] [--limit <n>] [--json] [--store <path>]\n  aiosh session show <session_id> [--json] [--store <path>]\n  aiosh session status <session_id> [--json] [--store <path>]\n  aiosh session create <spec_file_or_json> [--json] [--store <path>]\n  aiosh session action <session_id> <authenticate|activate|lock|unlock|terminate> [--json] [--store <path>]\n  aiosh session activate <session_id> [--json] [--store <path>]\n  aiosh session lock <session_id> [--json] [--store <path>]\n  aiosh session unlock <session_id> [--json] [--store <path>]\n  aiosh session terminate <session_id> [--json] [--store <path>]\n  aiosh session config [--config <path>] [--json]\n  aiosh session policy [--policy <path>] [--spec <file_or_json>] [--store <path>] [--json]\n  aiosh session stats [--policy <path>] [--store <path>] [--json]\n  aiosh session check [--fix] [--store <path>] [--json]\n  aiosh session recover [--store <path>] [--json]");
            0
        }
        Some(other) => {
            let msg = format!("unknown session subcommand: {}", other);
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            2
        }
    }
}

fn load_fs_layout_service(store_path_opt: Option<&str>) -> Result<aiosh_core::fs_layout_service::FilesystemLayoutService, String> {
    match store_path_opt {
        Some(p) => {
            let path = std::path::Path::new(p);
            if path.exists() {
                aiosh_core::fs_layout_service::FilesystemLayoutService::load_from_path(path)
            } else {
                Ok(aiosh_core::fs_layout_service::FilesystemLayoutService::new())
            }
        }
        None => Ok(aiosh_core::fs_layout_service::FilesystemLayoutService::new()),
    }
}

fn cmd_fs_layout_register(
    rest: &[String],
    store_path_opt: Option<&str>,
    is_json: bool,
    ctx: &mut Ctx,
) -> i32 {
    let spec_str = match parse_flag(rest, "--spec") {
        Some(s) => s,
        None => {
            let msg = "register requires '--spec <file_or_json>' argument";
            classify_and_emit(
                ctx,
                "fs_layout",
                "register",
                json!({ "error": msg }),
                "failure",
                None,
                Some("Missing --spec argument for layout register"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    };

    // Inline JSON specs legitimately span multiple lines and often exceed 1024 bytes, so only
    // null bytes are rejected up front; path-style values are still bounded when read below.
    if spec_str.contains('\0') {
        let msg = "spec argument cannot contain null bytes";
        classify_and_emit(
            ctx,
            "fs_layout",
            "register",
            json!({ "error": msg }),
            "failure",
            None,
            Some("Invalid spec argument"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
        } else {
            eprintln!("{}", msg);
        }
        return 2;
    }

    let p = std::path::Path::new(&spec_str);
    let spec = if p.exists() {
        // Bounded, non-blocking read. A metadata-only size check is a check-then-use
        // race, and a FIFO or character device named by --spec would otherwise block
        // the CLI forever (FIFO) or stream until memory is exhausted (/dev/zero).
        let content = match aiosh_core::fs_layout_service::read_bounded_text_file(
            p,
            aiosh_core::fs_layout_service::MAX_LAYOUT_DOC_BYTES,
            "spec file",
        ) {
            Ok(c) => c,
            Err(e) => {
                let msg = e.message().to_string();
                let (code, detail) = match e {
                    aiosh_core::fs_layout_service::LayoutDocReadError::TooLarge(_) => {
                        ("SPEC_SIZE_EXCEEDED", "Spec file exceeds size limit")
                    }
                    aiosh_core::fs_layout_service::LayoutDocReadError::NotRegularFile(_) => {
                        ("SPEC_NOT_REGULAR_FILE", "Spec path is not a regular file")
                    }
                    _ => ("SPEC_READ_FAILED", "Failed to read spec file"),
                };
                classify_and_emit(
                    ctx,
                    "fs_layout",
                    "register",
                    json!({ "error": &msg }),
                    "failure",
                    None,
                    Some(detail),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": code, "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }
        };
        match aiosh_core::fs_layout::FilesystemLayoutSpec::from_json(&content) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("failed to parse layout spec JSON: {}", e);
                classify_and_emit(
                    ctx,
                    "fs_layout",
                    "register",
                    json!({ "error": &msg }),
                    "failure",
                    None,
                    Some("Failed to parse layout spec JSON"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SPEC_PARSE_FAILED", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }
        }
    } else {
        match aiosh_core::fs_layout::FilesystemLayoutSpec::from_json(&spec_str) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("failed to parse layout spec JSON string: {}", e);
                classify_and_emit(
                    ctx,
                    "fs_layout",
                    "register",
                    json!({ "error": &msg }),
                    "failure",
                    None,
                    Some("Failed to parse layout spec JSON string"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SPEC_PARSE_FAILED", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }
        }
    };

    if let Err(e) = spec.validate() {
        let msg = format!("layout spec validation failed: {}", e);
        classify_and_emit(
            ctx,
            "fs_layout",
            "register",
            json!({ "id": spec.id, "error": &msg }),
            "failure",
            Some(&spec.id),
            Some("Layout spec validation failed on register"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_FAILED", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(&msg));
        }
        return 1;
    }

    let mut service = match load_fs_layout_service(store_path_opt) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to load layout store: {}", e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "register",
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Failed to load layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    };

    let layout_id = spec.id.clone();
    if let Err(e) = service.store_mut().register_layout(spec) {
        classify_and_emit(
            ctx,
            "fs_layout",
            "register",
            json!({ "id": layout_id, "error": &e }),
            "failure",
            Some(&layout_id),
            Some("Failed to register layout in store"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REGISTER_FAILED", "message": e } }));
        } else {
            eprintln!("failed to register layout: {}", sanitize_terminal(&e));
        }
        return 1;
    }

    if let Some(store_path) = store_path_opt {
        if let Err(e) = service.save_to_path(std::path::Path::new(store_path)) {
            let msg = format!("failed to persist layout store to '{}': {}", store_path, e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "register",
                json!({ "id": layout_id, "error": &msg }),
                "failure",
                Some(&layout_id),
                Some("Failed to persist layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    }

    classify_and_emit(
        ctx,
        "fs_layout",
        "register",
        json!({ "id": layout_id, "registered": true, "store": store_path_opt }),
        "success",
        Some(&layout_id),
        Some("Registered new filesystem layout"),
        "operator",
        None,
    );

    if is_json {
        println!("{}", json!({ "code": 0, "data": { "id": layout_id, "registered": true }, "error": serde_json::Value::Null }));
    } else {
        println!("SUCCESS: Registered filesystem layout '{}'", layout_id);
    }
    0
}

fn cmd_fs_layout_set_active(
    rest: &[String],
    store_path_opt: Option<&str>,
    is_json: bool,
    ctx: &mut Ctx,
) -> i32 {
    let target_id = rest.iter().find(|s| !s.starts_with("--"));
    let target_id = match target_id {
        Some(id) if !id.is_empty() => id.as_str(),
        _ => {
            let msg = "set-active requires '<id>' argument";
            classify_and_emit(
                ctx,
                "fs_layout",
                "set_active",
                json!({ "error": msg }),
                "failure",
                None,
                Some("Missing <id> argument for layout set-active"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    };

    let mut service = match load_fs_layout_service(store_path_opt) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to load layout store: {}", e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "set_active",
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Failed to load layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    };

    let prev_active = service.store.active_layout_id.clone();
    if let Err(e) = service.store_mut().set_active_layout(target_id) {
        classify_and_emit(
            ctx,
            "fs_layout",
            "set_active",
            json!({ "id": target_id, "error": &e }),
            "failure",
            Some(target_id),
            Some("Failed to set active layout"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SET_ACTIVE_FAILED", "message": e } }));
        } else {
            eprintln!("failed to set active layout: {}", sanitize_terminal(&e));
        }
        return 1;
    }

    if let Some(store_path) = store_path_opt {
        if let Err(e) = service.save_to_path(std::path::Path::new(store_path)) {
            let msg = format!("failed to persist layout store to '{}': {}", store_path, e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "set_active",
                json!({ "id": target_id, "error": &msg }),
                "failure",
                Some(target_id),
                Some("Failed to persist layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    }

    classify_and_emit(
        ctx,
        "fs_layout",
        "set_active",
        json!({ "id": target_id, "previous_active": prev_active, "new_active": target_id, "store": store_path_opt }),
        "success",
        Some(target_id),
        Some("Updated active filesystem layout"),
        "operator",
        None,
    );

    if is_json {
        println!("{}", json!({ "code": 0, "data": { "active": target_id, "previous_active": prev_active }, "error": serde_json::Value::Null }));
    } else {
        println!("SUCCESS: Active filesystem layout set to '{}'", target_id);
    }
    0
}

fn cmd_fs_layout_remove(
    rest: &[String],
    store_path_opt: Option<&str>,
    is_json: bool,
    ctx: &mut Ctx,
) -> i32 {
    let target_id = rest.iter().find(|s| !s.starts_with("--"));
    let target_id = match target_id {
        Some(id) if !id.is_empty() => id.as_str(),
        _ => {
            let msg = "remove requires '<id>' argument";
            classify_and_emit(
                ctx,
                "fs_layout",
                "remove",
                json!({ "error": msg }),
                "failure",
                None,
                Some("Missing <id> argument for layout remove"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    };

    let mut service = match load_fs_layout_service(store_path_opt) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to load layout store: {}", e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "remove",
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Failed to load layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    };

    if let Err(e) = service.store_mut().remove_layout(target_id) {
        classify_and_emit(
            ctx,
            "fs_layout",
            "remove",
            json!({ "id": target_id, "error": &e }),
            "failure",
            Some(target_id),
            Some("Failed to remove layout"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REMOVE_FAILED", "message": e } }));
        } else {
            eprintln!("failed to remove layout: {}", sanitize_terminal(&e));
        }
        return 1;
    }

    if let Some(store_path) = store_path_opt {
        if let Err(e) = service.save_to_path(std::path::Path::new(store_path)) {
            let msg = format!("failed to persist layout store to '{}': {}", store_path, e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "remove",
                json!({ "id": target_id, "error": &msg }),
                "failure",
                Some(target_id),
                Some("Failed to persist layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    }

    classify_and_emit(
        ctx,
        "fs_layout",
        "remove",
        json!({ "id": target_id, "removed": true, "store": store_path_opt }),
        "success",
        Some(target_id),
        Some("Removed filesystem layout profile"),
        "operator",
        None,
    );

    if is_json {
        println!("{}", json!({ "code": 0, "data": { "id": target_id, "removed": true }, "error": serde_json::Value::Null }));
    } else {
        println!("SUCCESS: Removed filesystem layout '{}'", target_id);
    }
    0
}

fn cmd_fs_layout_import_fstab(
    rest: &[String],
    store_path_opt: Option<&str>,
    is_json: bool,
    ctx: &mut Ctx,
) -> i32 {
    let positional: Vec<&str> = rest.iter().filter(|s| !s.starts_with("--")).map(|s| s.as_str()).collect();
    let fstab_arg = parse_flag(rest, "--fstab");
    let base_id = parse_flag(rest, "--base");

    if positional.len() < 2 || fstab_arg.is_none() {
        let msg = "import-fstab requires '<id> <name> --fstab <file_or_content>' arguments";
        classify_and_emit(
            ctx,
            "fs_layout",
            "import_fstab",
            json!({ "error": msg }),
            "failure",
            None,
            Some("Missing arguments for layout import-fstab"),
            "operator",
            None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
        } else {
            eprintln!("{}", msg);
        }
        return 2;
    }

    let id = positional[0];
    let name = positional[1];
    let fstab_input = fstab_arg.unwrap();

    let fstab_content = {
        let p = std::path::Path::new(&fstab_input);
        if p.exists() {
            // Bounded, non-blocking read: see read_bounded_text_file.
            match aiosh_core::fs_layout_service::read_bounded_text_file(
                p,
                aiosh_core::fs_layout_service::MAX_LAYOUT_DOC_BYTES,
                "fstab file",
            ) {
                Ok(c) => c,
                Err(e) => {
                    let msg = e.message().to_string();
                    let (code, detail) = match e {
                        aiosh_core::fs_layout_service::LayoutDocReadError::TooLarge(_) => {
                            ("FSTAB_SIZE_EXCEEDED", "Fstab file exceeds size limit")
                        }
                        aiosh_core::fs_layout_service::LayoutDocReadError::NotRegularFile(_) => {
                            ("FSTAB_NOT_REGULAR_FILE", "Fstab path is not a regular file")
                        }
                        _ => ("FSTAB_READ_FAILED", "Failed to read fstab file"),
                    };
                    classify_and_emit(
                        ctx,
                        "fs_layout",
                        "import_fstab",
                        json!({ "id": id, "error": &msg }),
                        "failure",
                        Some(id),
                        Some(detail),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": code, "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            }
        } else {
            fstab_input
        }
    };

    let mut service = match load_fs_layout_service(store_path_opt) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("failed to load layout store: {}", e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "import_fstab",
                json!({ "id": id, "error": &msg }),
                "failure",
                Some(id),
                Some("Failed to load layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    };

    let imported_spec = match service.import_fstab_as_layout(id, name, &fstab_content, base_id.as_deref()) {
        Ok(spec) => spec,
        Err(e) => {
            let msg = format!("failed to import fstab as layout: {}", e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "import_fstab",
                json!({ "id": id, "error": &msg }),
                "failure",
                Some(id),
                Some("Failed to import fstab as layout"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "IMPORT_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    };

    if let Some(store_path) = store_path_opt {
        if let Err(e) = service.save_to_path(std::path::Path::new(store_path)) {
            let msg = format!("failed to persist layout store to '{}': {}", store_path, e);
            classify_and_emit(
                ctx,
                "fs_layout",
                "import_fstab",
                json!({ "id": id, "error": &msg }),
                "failure",
                Some(id),
                Some("Failed to persist layout store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            return 1;
        }
    }

    classify_and_emit(
        ctx,
        "fs_layout",
        "import_fstab",
        json!({ "id": id, "name": name, "mounts": imported_spec.mounts.len(), "store": store_path_opt }),
        "success",
        Some(id),
        Some("Imported filesystem layout from fstab"),
        "operator",
        None,
    );

    if is_json {
        println!("{}", json!({ "code": 0, "data": imported_spec, "error": serde_json::Value::Null }));
    } else {
        println!("SUCCESS: Imported filesystem layout '{}' with {} mounts", id, imported_spec.mounts.len());
    }
    0
}

fn cmd_fs_layout(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_opt = parse_flag(rest, "--store");
    if let Some(ref p) = store_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "fs_layout",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid store path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    }

    let resolve_layout = |rest: &[String]| -> Result<aiosh_core::fs_layout::FilesystemLayoutSpec, String> {
        let first_id = rest.first().filter(|s| !s.starts_with("--"));
        if let Some(id) = first_id {
            let service = load_fs_layout_service(store_path_opt.as_deref())?;
            if let Some(spec) = service.store().get_layout(id) {
                return Ok(spec.clone());
            } else {
                return Err(format!("layout with id '{}' not found in store", id));
            }
        }
        if has_flag(rest, "--standard") {
            Ok(aiosh_core::fs_layout::FilesystemLayoutSpec::standard_uefi())
        } else if has_flag(rest, "--container") {
            Ok(aiosh_core::fs_layout::FilesystemLayoutSpec::minimal_container())
        } else if let Some(spec_str) = parse_flag(rest, "--spec") {
            // Only null bytes are rejected up front: inline JSON content is multi-line by nature.
            if spec_str.contains('\0') {
                return Err("spec argument cannot contain null bytes".into());
            }
            let p = std::path::Path::new(&spec_str);
            if p.exists() {
                // Bounded, non-blocking read: see read_bounded_text_file.
                let content = aiosh_core::fs_layout_service::read_bounded_text_file(
                    p,
                    aiosh_core::fs_layout_service::MAX_LAYOUT_DOC_BYTES,
                    "spec file",
                )
                .map_err(|e| e.message().to_string())?;
                aiosh_core::fs_layout::FilesystemLayoutSpec::from_json(&content)
            } else {
                aiosh_core::fs_layout::FilesystemLayoutSpec::from_json(&spec_str)
            }
        } else {
            let service = load_fs_layout_service(store_path_opt.as_deref())?;
            service.store().get_active_layout().map(|s| s.clone())
        }
    };

    match sub {
        Some("show") => {
            let layout = match resolve_layout(rest) {
                Ok(l) => l,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "show",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve layout"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RESOLVE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to resolve layout: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "show",
                json!({ "id": layout.id, "partitions": layout.partitions.len(), "mounts": layout.mounts.len() }),
                "success",
                Some(&layout.id),
                Some("Showed filesystem layout"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": layout, "error": serde_json::Value::Null }));
            } else {
                println!("Filesystem Layout: {}", sanitize_terminal(&layout.name));
                println!("  ID:          {}", sanitize_terminal(&layout.id));
                println!("  Description: {}", sanitize_terminal(&layout.description));
                println!("  Min Target:  {} GiB", layout.target_disk_min_bytes / (1024 * 1024 * 1024));
                println!("  Partitions ({}):", layout.partitions.len());
                for p in &layout.partitions {
                    println!("    [{}] {} ({:?}, {} MiB)", p.index, sanitize_terminal(&p.label), p.partition_type, p.size_mib);
                }
                println!("  Mounts ({}):", layout.mounts.len());
                for m in &layout.mounts {
                    println!("    {} -> {} ({:?})", sanitize_terminal(&m.device), sanitize_terminal(&m.path), m.fs_type);
                }
            }
            0
        }
        Some("validate") | Some("check") => {
            let layout_res = resolve_layout(rest);
            let (is_ok, err_msg, layout_id) = match layout_res {
                Ok(l) => match l.validate() {
                    Ok(()) => (true, None, l.id),
                    Err(e) => (false, Some(e), l.id),
                },
                Err(e) => (false, Some(e), "unknown".to_string()),
            };

            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "validate",
                json!({ "id": layout_id, "valid": is_ok, "error": err_msg }),
                if is_ok { "success" } else { "failure" },
                Some(&layout_id),
                Some(if is_ok { "Filesystem layout validated successfully" } else { "Filesystem layout validation failed" }),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": if is_ok { 0 } else { 1 },
                    "data": { "id": layout_id, "valid": is_ok },
                    "error": if is_ok { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": err_msg }) }
                }));
            } else if is_ok {
                println!("VALID: Filesystem layout '{}' satisfies all FL1..FL6 invariants", sanitize_terminal(&layout_id));
            } else {
                eprintln!("INVALID: {}", sanitize_terminal(&err_msg.unwrap_or_default()));
            }

            if is_ok { 0 } else { 1 }
        }
        Some("fstab") => {
            let layout = match resolve_layout(rest) {
                Ok(l) => l,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "fstab",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve layout for fstab generation"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RESOLVE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to resolve layout: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let fstab_content = layout.generate_fstab();
            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "fstab",
                json!({ "id": layout.id, "lines": fstab_content.lines().count() }),
                "success",
                Some(&layout.id),
                Some("Generated /etc/fstab from layout"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "id": layout.id, "fstab": fstab_content }, "error": serde_json::Value::Null }));
            } else {
                print!("{}", sanitize_terminal(&fstab_content));
            }
            0
        }
        Some("list") => {
            let service = match load_fs_layout_service(store_path_opt.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "list",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load layout store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load layout store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };
            let layouts = service.store.list_layouts();
            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "list",
                json!({ "count": layouts.len(), "active": service.store.active_layout_id }),
                "success",
                Some(&service.store.active_layout_id),
                Some("Listed registered filesystem layouts"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "active": service.store.active_layout_id, "layouts": layouts }, "error": serde_json::Value::Null }));
            } else {
                println!("Registered Filesystem Layouts (active: {}):", sanitize_terminal(&service.store.active_layout_id));
                for l in layouts {
                    let active_marker = if l.id == service.store.active_layout_id { "*" } else { " " };
                    println!("  {} {:<28} - {} (min: {} GiB)", active_marker, sanitize_terminal(&l.id), sanitize_terminal(&l.name), l.target_disk_min_bytes / (1024 * 1024 * 1024));
                }
            }
            0
        }
        Some("probe") => {
            let layout = match resolve_layout(rest) {
                Ok(l) => l,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "probe",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve layout for probe"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RESOLVE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to resolve layout: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };
            let target_bytes: u64 = match parse_flag(rest, "--bytes") {
                Some(ref raw) => match raw.parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => {
                        let msg = format!(
                            "invalid --bytes value '{}': expected a non-negative integer",
                            raw
                        );
                        classify_and_emit(
                            &mut ctx,
                            "fs_layout",
                            "probe",
                            json!({ "error": &msg }),
                            "failure",
                            None,
                            Some("Invalid --bytes argument for layout probe"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "ARGUMENT_ERROR", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                },
                None => layout.target_disk_min_bytes,
            };

            let mut service = aiosh_core::fs_layout_service::FilesystemLayoutService::empty();
            let layout_id = layout.id.clone();
            // A layout rejected by FL1..FL6 must fail loudly rather than silently degrade
            // into the "layout not found" path of probe_target below.
            if let Err(e) = service.store_mut().register_layout(layout) {
                let msg = format!("layout '{}' cannot be probed: {}", layout_id, e);
                classify_and_emit(
                    &mut ctx,
                    "fs_layout",
                    "probe",
                    json!({ "id": layout_id, "error": &msg }),
                    "failure",
                    Some(&layout_id),
                    Some("Probe layout rejected by FL1..FL6 validation"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "INVALID_LAYOUT", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            let eval = match service.probe_target(&layout_id, target_bytes) {
                Ok(ev) => ev,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "probe",
                        json!({ "id": layout_id, "error": e }),
                        "failure",
                        Some(&layout_id),
                        Some("Failed to probe target disk capacity"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "PROBE_FAILED", "message": e } }));
                    } else {
                        eprintln!("probe failed: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "probe",
                json!({ "id": eval.layout_id, "is_viable": eval.is_viable, "errors": eval.errors.len(), "warnings": eval.warnings.len() }),
                if eval.is_viable { "success" } else { "failure" },
                Some(&eval.layout_id),
                Some("Probed target disk capacity for filesystem layout"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": if eval.is_viable { 0 } else { 1 }, "data": eval, "error": if eval.is_viable { serde_json::Value::Null } else { json!({ "code": "NOT_VIABLE", "errors": eval.errors }) } }));
            } else {
                println!("Target Disk Probe for '{}' (Capacity: {} GiB):", sanitize_terminal(&eval.layout_id), eval.target_disk_bytes / (1024 * 1024 * 1024));
                println!("  Status:           {}", if eval.is_viable { "VIABLE" } else { "INSUFFICIENT" });
                println!("  Required Minimum: {} GiB", eval.required_disk_bytes / (1024 * 1024 * 1024));
                println!("  Partition Budget: {} GiB", eval.partition_budget_bytes / (1024 * 1024 * 1024));
                if !eval.errors.is_empty() {
                    println!("  Errors:");
                    for err in &eval.errors {
                        println!("    - {}", sanitize_terminal(err));
                    }
                }
                if !eval.warnings.is_empty() {
                    println!("  Warnings:");
                    for w in &eval.warnings {
                        println!("    - {}", sanitize_terminal(w));
                    }
                }
            }
            if eval.is_viable { 0 } else { 1 }
        }
        Some("diff") => {
            let positional: Vec<&str> = rest.iter().filter(|s| !s.starts_with("--")).map(|s| s.as_str()).collect();
            let source_id = if !positional.is_empty() {
                positional[0]
            } else {
                "aios-uefi-standard-v1"
            };
            let target_id = if positional.len() > 1 {
                positional[1]
            } else {
                "aios-container-minimal-v1"
            };

            let service = match load_fs_layout_service(store_path_opt.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "diff",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load layout store for diff"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load layout store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };
            let diff = match service.diff_layouts(source_id, target_id) {
                Ok(d) => d,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "fs_layout",
                        "diff",
                        json!({ "source": source_id, "target": target_id, "error": e }),
                        "failure",
                        Some(source_id),
                        Some("Failed to compute layout diff"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "DIFF_FAILED", "message": e } }));
                    } else {
                        eprintln!("diff failed: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "diff",
                json!({ "source": source_id, "target": target_id, "destructive": diff.destructive }),
                "success",
                Some(source_id),
                Some("Computed diff between filesystem layouts"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": diff, "error": serde_json::Value::Null }));
            } else {
                println!("{}", sanitize_terminal(&diff.summary));
            }
            0
        }
        Some("register") => {
            cmd_fs_layout_register(rest, store_path_opt.as_deref(), is_json, &mut ctx)
        }
        Some("set-active") => {
            cmd_fs_layout_set_active(rest, store_path_opt.as_deref(), is_json, &mut ctx)
        }
        Some("remove") => {
            cmd_fs_layout_remove(rest, store_path_opt.as_deref(), is_json, &mut ctx)
        }
        Some("import-fstab") => {
            cmd_fs_layout_import_fstab(rest, store_path_opt.as_deref(), is_json, &mut ctx)
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh layout — Filesystem Layout & Target Partitioning Manager\n\nUsage:\n  aiosh layout list [--store <path>] [--json]\n  aiosh layout show [ID] [--standard|--container|--spec <file_or_json>] [--store <path>] [--json]\n  aiosh layout validate [--standard|--container|--spec <file_or_json>] [--store <path>] [--json]\n  aiosh layout check [--standard|--container|--spec <file_or_json>] [--store <path>] [--json]\n  aiosh layout probe [--bytes <N>] [--standard|--container|--spec <file_or_json>] [--store <path>] [--json]\n  aiosh layout diff [<source_id> <target_id>] [--store <path>] [--json]\n  aiosh layout fstab [--standard|--container|--spec <file_or_json>] [--store <path>] [--json]\n  aiosh layout register --spec <file_or_json> [--store <path>] [--json]\n  aiosh layout set-active <id> [--store <path>] [--json]\n  aiosh layout remove <id> [--store <path>] [--json]\n  aiosh layout import-fstab <id> <name> --fstab <file_or_content> [--base <id>] [--store <path>] [--json]");
            0
        }
        Some(other) => {
            let msg = format!("unknown layout subcommand: {}", other);
            classify_and_emit(
                &mut ctx,
                "fs_layout",
                "unknown",
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Unknown filesystem layout subcommand"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_package(args: &[String]) -> i32 {

    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_opt = parse_flag(rest, "--store");
    if let Some(ref p) = store_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "package",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid store path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", msg);
            }
            return 2;
        }
    }
    let load_store = || -> Result<aiosh_core::package_service::PackageStore, String> {
        match store_path_opt {
            Some(ref p) => aiosh_core::package_service::PackageStore::load_from_path(std::path::Path::new(p)),
            None => Ok(aiosh_core::package_service::PackageStore::new()),
        }
    };

    match sub {
        Some("list") => {
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "list",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load package store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load package store: {}", e);
                    }
                    return 1;
                }
            };
            let format = match parse_flag(rest, "--format").as_deref() {
                Some("deb") => Some(aiosh_core::package::PackageFormat::Deb),
                Some("apk") => Some(aiosh_core::package::PackageFormat::Apk),
                Some("flatpak") => Some(aiosh_core::package::PackageFormat::Flatpak),
                Some("tarball") => Some(aiosh_core::package::PackageFormat::Tarball),
                Some(other) => {
                    let msg = format!("unknown format: {}", other);
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid format argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
                None => None,
            };
            let state = match parse_flag(rest, "--state").as_deref() {
                Some("available") => Some(aiosh_core::package::PackageState::Available),
                Some("installed") => Some(aiosh_core::package::PackageState::Installed),
                Some("upgradable") => Some(aiosh_core::package::PackageState::Upgradable),
                Some("pending_install") => Some(aiosh_core::package::PackageState::PendingInstall),
                Some("pending_removal") => Some(aiosh_core::package::PackageState::PendingRemoval),
                Some("broken") => Some(aiosh_core::package::PackageState::Broken),
                Some(other) => {
                    let msg = format!("unknown state: {}", other);
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid state argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
                None => None,
            };
            let pattern = parse_flag(rest, "--pattern");
            if let Some(ref p) = pattern {
                if p.len() > 256 || p.chars().any(|c| c.is_control()) {
                    let msg = "filter pattern cannot exceed 256 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "list",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid filter pattern"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let limit = if let Some(s) = parse_flag(rest, "--limit") {
                match s.parse::<usize>() {
                    Ok(n) if n > 0 && n <= 10_000 => Some(n),
                    _ => {
                        let msg = "limit must be a positive integer between 1 and 10,000";
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "list",
                            json!({ "error": msg }),
                            "failure",
                            None,
                            Some("Invalid limit argument"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                }
            } else {
                None
            };

            let query = aiosh_core::package::PackageQuery {
                name_pattern: pattern,
                format,
                state,
                limit,
            };
            let packages = store.query(&query);
            classify_and_emit(
                &mut ctx,
                "package",
                "list",
                json!({ "count": packages.len() }),
                "success",
                None,
                Some("Listed packages from store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&packages).unwrap_or_default());
            } else {
                println!("AIOS Package Store ({} packages):", packages.len());
                for pkg in packages {
                    println!("  {:<16} {:<16} {:<8} {:<10} {:>10} bytes",
                        pkg.name, pkg.version, format!("{:?}", pkg.format).to_lowercase(),
                        format!("{:?}", pkg.state).to_lowercase(), pkg.installed_size_bytes);
                }
            }
            0
        }
        Some("show") => {
            let name_arg = match rest.first() {
                Some(s) if !s.starts_with("--") => Some(s.to_string()),
                _ => parse_flag(rest, "--name"),
            };
            let name = match name_arg {
                Some(n) => n,
                None => {
                    let msg = "missing package name: aiosh package show <name>";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "show",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing package name argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if name.len() > 64 || name.chars().any(|c| c.is_control()) {
                let msg = format!("package name '{}' is invalid: exceeds 64 characters or contains control characters", name);
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "show",
                    json!({ "name": name, "error": msg }),
                    "failure",
                    Some(&name),
                    Some("Invalid package name"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "show",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load package store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load package store: {}", e);
                    }
                    return 1;
                }
            };
            match store.get_package(&name) {
                Some(pkg) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "show",
                        json!({ "name": pkg.name, "version": pkg.version }),
                        "success",
                        Some(&pkg.name),
                        Some("Retrieved package spec"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(pkg).unwrap_or_default());
                    } else {
                        println!("Package: {}", pkg.name);
                        println!("  Version:      {}", pkg.version);
                        println!("  Architecture: {}", pkg.architecture);
                        println!("  Format:       {:?}", pkg.format);
                        println!("  State:        {:?}", pkg.state);
                        println!("  Size:         {} bytes", pkg.installed_size_bytes);
                        println!("  Description:  {}", pkg.description);
                        println!("  Dependencies: {}", pkg.dependencies.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", "));
                    }
                    0
                }
                None => {
                    let msg = format!("package '{}' not found in store", name);
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "show",
                        json!({ "name": name, "error": "not found" }),
                        "failure",
                        Some(&name),
                        Some("Package not found in store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PACKAGE_NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    2
                }
            }
        }
        Some("plan") => {
            let actions_str = match parse_flag(rest, "--actions") {
                Some(s) => s,
                None => {
                    let msg = "missing --actions <json_or_file>: aiosh package plan --actions <json_or_file> [--dry-run]";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing --actions argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let content = if std::path::Path::new(&actions_str).exists() {
                let path = std::path::Path::new(&actions_str);
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.len() > 1024 * 1024 {
                        let err_msg = format!("actions file '{}' exceeds 1 MiB size limit (was {} bytes)", actions_str, meta.len());
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "plan",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Actions file exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        let err_msg = format!("failed to read actions file '{}': {}", actions_str, e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "plan",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to read actions file"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 1;
                    }
                }
            } else {
                if actions_str.len() > 1024 * 1024 {
                    let err_msg = "inline actions JSON payload exceeds 1 MiB size limit".to_string();
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "error": err_msg }),
                        "failure",
                        None,
                        Some("Inline actions JSON exceeds size limit"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                    } else {
                        eprintln!("{}", err_msg);
                    }
                    return 2;
                }
                actions_str
            };
            let actions: Vec<aiosh_core::package::PackageAction> = match serde_json::from_str(&content) {
                Ok(a) => a,
                Err(e) => {
                    let err_msg = format!("failed to parse actions JSON: {}", e);
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "error": err_msg }),
                        "failure",
                        None,
                        Some("Failed to parse actions JSON"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_JSON", "message": err_msg } }));
                    } else {
                        eprintln!("{}", err_msg);
                    }
                    return 2;
                }
            };
            let dry_run = has_flag(rest, "--dry-run");
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load package store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load package store: {}", e);
                    }
                    return 1;
                }
            };
            match store.plan_transaction(actions, dry_run) {
                Ok(tx) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "id": tx.id, "actions_count": tx.actions.len(), "delta_bytes": tx.total_size_delta_bytes }),
                        "success",
                        Some(&tx.id),
                        Some("Planned package transaction"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&tx).unwrap_or_default());
                    } else {
                        println!("Planned Package Transaction: {}", tx.id);
                        println!("  Actions:     {}", tx.actions.len());
                        println!("  Dry Run:     {}", tx.dry_run);
                        println!("  Delta Bytes: {} bytes", tx.total_size_delta_bytes);
                        for (i, act) in tx.actions.iter().enumerate() {
                            println!("  [{}] {:?} on package '{}'", i + 1, act.action, act.package_name);
                        }
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "plan",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to plan package transaction"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PLAN_FAILED", "message": e } }));
                    } else {
                        eprintln!("plan failed: {}", e);
                    }
                    2
                }
            }
        }
        Some("validate") => {
            if let Some(name) = parse_flag(rest, "--name") {
                let res = aiosh_core::package::validate_package_name(&name);
                let (code, msg, errors) = match res {
                    Ok(()) => (0, format!("Package name '{}' is valid", name), vec![]),
                    Err(e) => (2, format!("Package name '{}' is invalid: {}", name, e), vec![e]),
                };
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "validate",
                    json!({ "name": name, "valid": code == 0 }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&name),
                    Some(&msg),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "name": name },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": msg, "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Package name '{}' conforms to PM1 naming syntax", name);
                } else {
                    eprintln!("INVALID: {}", msg);
                }
                code
            } else if let Some(spec_str) = parse_flag(rest, "--spec") {
                let content = if std::path::Path::new(&spec_str).exists() {
                    let path = std::path::Path::new(&spec_str);
                    if let Ok(meta) = std::fs::metadata(path) {
                        if meta.len() > 1024 * 1024 {
                            let err_msg = format!("spec file '{}' exceeds 1 MiB size limit (was {} bytes)", spec_str, meta.len());
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 2;
                        }
                    }
                    match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            let err_msg = format!("failed to read spec file '{}': {}", spec_str, e);
                            classify_and_emit(
                                &mut ctx,
                                "package",
                                "validate",
                                json!({ "error": err_msg }),
                                "failure",
                                None,
                                Some("Failed to read spec file"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                            } else {
                                eprintln!("{}", err_msg);
                            }
                            return 1;
                        }
                    }
                } else {
                    if spec_str.len() > 1024 * 1024 {
                        let err_msg = "inline spec JSON payload exceeds 1 MiB size limit".to_string();
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Inline spec payload exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                    spec_str
                };
                let spec: aiosh_core::package::PackageSpec = match serde_json::from_str(&content) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("failed to parse package spec JSON: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "validate",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to parse package spec JSON"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_JSON", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                };
                let res = aiosh_core::package::validate_package_spec(&spec);
                let (code, errors) = match res {
                    Ok(()) => (0, vec![]),
                    Err(errs) => (2, errs),
                };
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "validate",
                    json!({ "package": spec.name, "valid": code == 0, "errors_count": errors.len() }),
                    if code == 0 { "success" } else { "failure" },
                    Some(&spec.name),
                    Some("Validated package specification"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({
                        "code": code,
                        "data": { "valid": code == 0, "spec": spec },
                        "error": if code == 0 { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": "Package spec violates PM invariants", "errors": errors }) }
                    }));
                } else if code == 0 {
                    println!("VALID: Package specification '{}' ({}) conforms to PM1..PM5 invariants", spec.name, spec.version);
                } else {
                    eprintln!("INVALID: Package specification '{}' has {} errors:", spec.name, errors.len());
                    for err in &errors {
                        eprintln!("  - {}", err);
                    }
                }
                code
            } else {
                eprintln!("usage: aiosh package validate (--name <name> | --spec <json_or_file>) [--json]");
                2
            }
        }
        Some("search") => {
            let pattern = match rest.first() {
                Some(s) if !s.starts_with("--") => Some(s.to_string()),
                _ => parse_flag(rest, "--pattern"),
            };
            let pattern_str = match pattern {
                Some(p) => p,
                None => {
                    let msg = "missing search pattern: aiosh package search <pattern>";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "search",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing pattern argument"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if pattern_str.len() > 256 || pattern_str.chars().any(|c| c.is_control()) {
                let msg = "search pattern cannot exceed 256 characters and cannot contain control characters";
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "search",
                    json!({ "error": msg }),
                    "failure",
                    None,
                    Some("Invalid search pattern"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "search",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load package store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load package store: {}", e);
                    }
                    return 1;
                }
            };
            let limit = if let Some(s) = parse_flag(rest, "--limit") {
                match s.parse::<usize>() {
                    Ok(n) if n > 0 && n <= 10_000 => Some(n),
                    _ => {
                        let msg = "limit must be a positive integer between 1 and 10,000";
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "search",
                            json!({ "error": msg }),
                            "failure",
                            None,
                            Some("Invalid limit argument"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                }
            } else {
                None
            };
            let query = aiosh_core::package::PackageQuery {
                name_pattern: Some(pattern_str.clone()),
                format: None,
                state: None,
                limit,
            };
            let packages = store.query(&query);
            classify_and_emit(
                &mut ctx,
                "package",
                "search",
                json!({ "pattern": pattern_str, "matches": packages.len() }),
                "success",
                None,
                Some("Searched package store"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", serde_json::to_string_pretty(&packages).unwrap_or_default());
            } else {
                println!("AIOS Package Search results for '{}' ({} matches):", pattern_str, packages.len());
                for pkg in packages {
                    println!("  {:<16} {:<16} {:<8} {:<10} {:>10} bytes",
                        pkg.name, pkg.version, format!("{:?}", pkg.format).to_lowercase(),
                        format!("{:?}", pkg.state).to_lowercase(), pkg.installed_size_bytes);
                }
            }
            0
        }
        Some("apply") => {
            let (input_str, is_plan_file) = if let Some(s) = parse_flag(rest, "--plan") {
                (s, true)
            } else if let Some(s) = parse_flag(rest, "--actions") {
                (s, false)
            } else {
                let msg = "missing --actions or --plan: aiosh package apply (--actions <json_or_file> | --plan <json_or_file>) [--dry-run] [--store <path>] [--json]";
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "apply",
                    json!({ "error": msg }),
                    "failure",
                    None,
                    Some("Missing --actions or --plan argument"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            };

            let content = if std::path::Path::new(&input_str).exists() {
                let path = std::path::Path::new(&input_str);
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.len() > 1024 * 1024 {
                        let err_msg = format!("payload file '{}' exceeds 1 MiB size limit (was {} bytes)", input_str, meta.len());
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Payload file exceeds size limit"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        let err_msg = format!("failed to read payload file '{}': {}", input_str, e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to read payload file"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "FILE_READ_ERROR", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 1;
                    }
                }
            } else {
                if input_str.len() > 1024 * 1024 {
                    let err_msg = "inline JSON payload exceeds 1 MiB size limit".to_string();
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "apply",
                        json!({ "error": err_msg }),
                        "failure",
                        None,
                        Some("Inline JSON exceeds size limit"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PAYLOAD_TOO_LARGE", "message": err_msg } }));
                    } else {
                        eprintln!("{}", err_msg);
                    }
                    return 2;
                }
                input_str
            };

            let dry_run = has_flag(rest, "--dry-run");
            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "apply",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to load package store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load package store: {}", e);
                    }
                    return 1;
                }
            };

            let transaction: aiosh_core::package::PackageTransaction = if is_plan_file {
                match serde_json::from_str::<aiosh_core::package::PackageTransaction>(&content) {
                    Ok(mut tx) => {
                        if dry_run {
                            tx.dry_run = true;
                        }
                        tx
                    }
                    Err(e) => {
                        let err_msg = format!("failed to parse plan JSON: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to parse plan JSON"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_JSON", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                }
            } else {
                let actions: Vec<aiosh_core::package::PackageAction> = match serde_json::from_str(&content) {
                    Ok(a) => a,
                    Err(e) => {
                        let err_msg = format!("failed to parse actions JSON: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": err_msg }),
                            "failure",
                            None,
                            Some("Failed to parse actions JSON"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_JSON", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 2;
                    }
                };
                match store.plan_transaction(actions, dry_run) {
                    Ok(tx) => tx,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": e }),
                            "failure",
                            None,
                            Some("Failed to plan package transaction"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PLAN_FAILED", "message": e } }));
                        } else {
                            eprintln!("plan failed: {}", e);
                        }
                        return 2;
                    }
                }
            };

            let report = match store.execute_transaction(&transaction) {
                Ok(rep) => rep,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "apply",
                        json!({ "error": e }),
                        "failure",
                        Some(&transaction.id),
                        Some("Failed to execute package transaction"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "EXECUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("execution failed: {}", e);
                    }
                    return 2;
                }
            };

            if !transaction.dry_run {
                if let Some(ref store_path) = store_path_opt {
                    if let Err(e) = store.save_to_path(std::path::Path::new(store_path)) {
                        let err_msg = format!("failed to persist store to '{}': {}", store_path, e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "apply",
                            json!({ "error": err_msg }),
                            "failure",
                            Some(&transaction.id),
                            Some("Failed to persist package store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "PERSISTENCE_FAILED", "message": err_msg } }));
                        } else {
                            eprintln!("{}", err_msg);
                        }
                        return 1;
                    }
                }
            }

            classify_and_emit(
                &mut ctx,
                "package",
                "apply",
                json!({
                    "transaction_id": report.transaction_id,
                    "installed": report.packages_installed.len(),
                    "removed": report.packages_removed.len(),
                    "upgraded": report.packages_upgraded.len(),
                    "delta_bytes": report.total_size_delta_bytes,
                    "dry_run": transaction.dry_run,
                }),
                "success",
                Some(&report.transaction_id),
                Some("Applied package transaction"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("Applied Package Transaction: {}", report.transaction_id);
                println!("  Dry Run:   {}", transaction.dry_run);
                println!("  Installed: {}", if report.packages_installed.is_empty() { "none".into() } else { report.packages_installed.join(", ") });
                println!("  Removed:   {}", if report.packages_removed.is_empty() { "none".into() } else { report.packages_removed.join(", ") });
                println!("  Upgraded:  {}", if report.packages_upgraded.is_empty() { "none".into() } else { report.packages_upgraded.join(", ") });
                println!("  Delta:     {} bytes", report.total_size_delta_bytes);
            }
            0
        }
        Some("config") => {
            let config_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = config_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "config path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "config",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid config path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let resolved = match aiosh_core::package_config::PackageConfig::resolve(config_path_opt.as_deref().map(std::path::Path::new)) {
                Ok(c) => c,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "config",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve package config"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to resolve package config: {}", e);
                    }
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx,
                "package",
                "config",
                json!({ "store_path": resolved.store_path, "default_format": resolved.default_format }),
                "success",
                None,
                Some("Resolved package configuration"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": resolved, "error": serde_json::Value::Null }));
            } else {
                println!("AIOS Package Management Configuration:");
                println!("  Store Path:           {}", resolved.store_path.display());
                println!("  Default Format:       {:?}", resolved.default_format);
                println!("  Max Store Size:       {} bytes", resolved.max_store_size_bytes);
                println!("  Max Entity Count:     {}", resolved.max_entity_count);
                println!("  Auto Persist:         {}", resolved.auto_persist);
                println!("  Allowed Repositories: {}", resolved.allowed_repositories.join(", "));
            }
            0
        }
        Some("policy") => {
            let policy_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = policy_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "policy path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "policy",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid policy path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let policy = match aiosh_core::package_policy::PackageSecurityPolicy::resolve(policy_path_opt.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "policy",
                        json!({ "error": e }),
                        "failure",
                        None,
                        Some("Failed to resolve package security policy"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("Failed to resolve package security policy: {}", e);
                    }
                    return 1;
                }
            };

            let pkg_name_opt = parse_flag(rest, "--package");
            if let Some(ref name) = pkg_name_opt {
                let store = match load_store() {
                    Ok(s) => s,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to load store: {}", e);
                        }
                        return 1;
                    }
                };
                let spec = match store.get_package(name) {
                    Some(s) => s,
                    None => {
                        let msg = format!("package '{}' not found in store", name);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PACKAGE_NOT_FOUND", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                };
                let verdict = policy.evaluate_spec(spec);
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "policy",
                    json!({ "package": name, "allowed": verdict.allowed, "violations": verdict.violations.len() }),
                    if verdict.allowed { "success" } else { "failure" },
                    Some(name),
                    Some("Evaluated package security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": verdict, "error": serde_json::Value::Null }));
                } else {
                    println!("Package Security Policy Verdict for '{}':", name);
                    println!("  Allowed:    {}", verdict.allowed);
                    println!("  Mode:       {:?}", verdict.mode);
                    println!("  Violations: {}", verdict.violations.len());
                    for v in &verdict.violations {
                        println!("    [{}] {}: {}", if v.fatal { "FATAL" } else { "WARN" }, v.rule_id, v.description);
                    }
                }
                if verdict.allowed { 0 } else { 1 }
            } else {
                classify_and_emit(
                    &mut ctx,
                    "package",
                    "policy",
                    json!({ "mode": format!("{:?}", policy.mode) }),
                    "success",
                    None,
                    Some("Inspected package security policy"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": policy, "error": serde_json::Value::Null }));
                } else {
                    println!("AIOS Package Security Policy:");
                    println!("  Mode:                         {:?}", policy.mode);
                    println!("  Require Checksum:             {}", policy.require_checksum);
                    println!("  Require HTTPS/File Mirror:    {}", policy.require_https_or_file_repo);
                    println!("  Max Package Size:             {} bytes", policy.max_package_size_bytes);
                    println!("  Max Dependencies Per Package: {}", policy.max_dependencies_per_package);
                    println!("  Prohibited Packages:          {}", policy.prohibited_packages.join(", "));
                    println!("  Allowed Architectures:        {}", policy.allowed_architectures.join(", "));
                    println!("  Allowed Repositories:         {}", policy.allowed_repositories.join(", "));
                }
                0
            }
        }
        Some("stats") => {
            let store_path_opt = parse_flag(rest, "--store");
            if let Some(ref p) = store_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "stats",
                        json!({ "error": msg }),
                        "failure",
                        Some("INVALID_ARGUMENT"),
                        Some("Invalid store path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let config_path_opt = parse_flag(rest, "--config");
            if let Some(ref p) = config_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "config path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "stats",
                        json!({ "error": msg }),
                        "failure",
                        Some("INVALID_ARGUMENT"),
                        Some("Invalid config path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            }
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "package",
                        "stats",
                        json!({ "error": e }),
                        "failure",
                        Some("LOAD_STORE_FAILED"),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", e);
                    }
                    return 1;
                }
            };
            let policy = if let Some(ref p) = config_path_opt {
                match aiosh_core::package_policy::PackageSecurityPolicy::from_file(std::path::Path::new(p)) {
                    Ok(pol) => Some(pol),
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "stats",
                            json!({ "error": e }),
                            "failure",
                            Some("LOAD_POLICY_FAILED"),
                            Some("Failed to load policy"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_POLICY_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to load policy: {}", e);
                        }
                        return 1;
                    }
                }
            } else {
                aiosh_core::package_policy::PackageSecurityPolicy::resolve(None).ok()
            };
            let report = aiosh_core::package_observability::PackageObservabilityReport::generate(&store, policy.as_ref());
            classify_and_emit(
                &mut ctx,
                "package",
                "stats",
                json!({ "total_packages": report.total_packages, "installed_size_bytes": report.total_installed_size_bytes }),
                "success",
                None,
                Some("Generated package observability telemetry report"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("AIOS Package Management Observability & Telemetry Report:");
                println!("  Total Packages:               {}", report.total_packages);
                println!("  Total Installed Footprint:    {} bytes", report.total_installed_size_bytes);
                println!("  Average Package Size:         {} bytes", report.average_package_size_bytes);
                println!("  Policy Compliant Packages:    {}/{}", report.policy_compliant_count, report.total_packages);
                println!("  Policy Violations Detected:   {}", report.policy_violations_count);
                if !report.prohibited_packages_found.is_empty() {
                    println!("  Prohibited Packages Found:    {}", report.prohibited_packages_found.join(", "));
                }
                println!("  State Breakdown:");
                for (k, v) in &report.state_breakdown {
                    println!("    {:<16} {}", k, v);
                }
                println!("  Format Breakdown:");
                for (k, v) in &report.format_breakdown {
                    println!("    {:<16} {}", k, v);
                }
                println!("  Architecture Breakdown:");
                for (k, v) in &report.architecture_breakdown {
                    println!("    {:<16} {}", k, v);
                }
                println!("  Dependency Distribution:");
                for (k, v) in &report.dependency_distribution {
                    println!("    {:<16} {}", k, v);
                }
            }
            0
        }
        Some("check") => {
            let is_fix = has_flag(rest, "--fix");
            let target_path = if let Some(ref p) = store_path_opt {
                std::path::PathBuf::from(p)
            } else {
                std::path::PathBuf::from("/var/lib/aios/packages.json")
            };

            let (_store, report, recovered, backup_opt) = if is_fix {
                match aiosh_core::package_recovery::load_or_recover(&target_path) {
                    Ok(res) => res,
                    Err(e) => {
                        let msg = format!("recovery failed: {}", e);
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "check",
                            json!({ "error": msg }),
                            "failure",
                            Some("RECOVERY_FAILED"),
                            Some("Failed to recover package store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RECOVERY_FAILED", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }
                }
            } else if target_path.exists() {
                match aiosh_core::package_service::PackageStore::load_from_path(&target_path) {
                    Ok(s) => {
                        let rep = aiosh_core::package_recovery::validate_package_store(&s, &target_path);
                        (s, rep, false, None)
                    }
                    Err(e) => {
                        let rep = aiosh_core::package_recovery::PackageValidationReport {
                            store_path: target_path.to_string_lossy().to_string(),
                            total_packages: 0,
                            valid_packages: 0,
                            invalid_packages: 0,
                            errors: vec![format!("failed to load package store: {}", e)],
                            healthy: false,
                            evaluated_at: chrono::Utc::now().to_rfc3339(),
                        };
                        classify_and_emit(
                            &mut ctx,
                            "package",
                            "check",
                            json!({ "healthy": false, "errors": rep.errors }),
                            "failure",
                            Some("LOAD_STORE_FAILED"),
                            Some("Package store check failed"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({
                                "code": 1,
                                "data": serde_json::Value::Null,
                                "error": {
                                    "code": "LOAD_STORE_FAILED",
                                    "message": format!("Package store at {} is corrupted or unreadable. Run with --fix to recover.", target_path.display()),
                                    "report": rep
                                }
                            }));
                        } else {
                            eprintln!("Package Store Validation: UNHEALTHY");
                            for err in &rep.errors {
                                eprintln!("  [-] {}", err);
                            }
                            eprintln!("Hint: Run with --fix to automatically recover.");
                        }
                        return 1;
                    }
                }
            } else {
                let s = aiosh_core::package_service::PackageStore::new();
                let rep = aiosh_core::package_recovery::validate_package_store(&s, &target_path);
                (s, rep, false, None)
            };

            let code = if report.healthy { 0 } else { 1 };
            classify_and_emit(
                &mut ctx,
                "package",
                "check",
                json!({
                    "healthy": report.healthy,
                    "recovered": recovered,
                    "total_packages": report.total_packages,
                    "valid_packages": report.valid_packages,
                    "invalid_packages": report.invalid_packages,
                    "backup_path": backup_opt.as_ref().map(|p| p.to_string_lossy().to_string())
                }),
                if report.healthy { "success" } else { "failure" },
                if report.healthy { None } else { Some("UNHEALTHY_STORE") },
                Some("Executed package store integrity check"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": code,
                    "data": {
                        "report": report,
                        "recovered": recovered,
                        "backup_path": backup_opt.map(|p| p.to_string_lossy().to_string())
                    },
                    "error": if report.healthy { serde_json::Value::Null } else { json!({ "code": "UNHEALTHY_STORE", "message": "Package store validation detected errors", "errors": report.errors }) }
                }));
            } else {
                if report.healthy {
                    println!("Package Store Validation: HEALTHY");
                } else {
                    println!("Package Store Validation: UNHEALTHY");
                }
                println!("  Store Path:        {}", report.store_path);
                println!("  Total Packages:    {}", report.total_packages);
                println!("  Valid Packages:    {}", report.valid_packages);
                println!("  Invalid Packages:  {}", report.invalid_packages);
                if recovered {
                    println!("  Recovered:         true");
                    if let Some(ref bp) = backup_opt {
                        println!("  Backup Path:       {}", bp.display());
                    }
                }
                if !report.errors.is_empty() {
                    println!("  Errors:");
                    for err in &report.errors {
                        println!("    [-] {}", err);
                    }
                }
            }
            code
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh package — Linux Package Management Data Model, Core Service & Store Control\n\nUsage:\n  aiosh package list [--format <deb|apk|flatpak|tarball>] [--state <state>] [--pattern <pattern>] [--limit <n>] [--store <path>] [--json]\n  aiosh package show <name> [--store <path>] [--json]\n  aiosh package search <pattern> [--limit <n>] [--store <path>] [--json]\n  aiosh package plan --actions <json_or_file> [--dry-run] [--store <path>] [--json]\n  aiosh package apply (--actions <json_or_file> | --plan <json_or_file>) [--dry-run] [--yes] [--store <path>] [--json]\n  aiosh package validate --name <name> [--json]\n  aiosh package validate --spec <json_or_file> [--json]\n  aiosh package config [--config <path>] [--json]\n  aiosh package policy [--package <name>] [--config <path>] [--json]\n  aiosh package stats [--store <path>] [--config <path>] [--json]\n  aiosh package check [--store <path>] [--fix] [--json]");
            0
        }
        Some(other) => {
            eprintln!("unknown package subcommand: {}", other);
            2
        }
    }
}

fn cmd_handoff(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let config = if let Some(cfg_path_str) = parse_flag(rest, "--config") {
        match aiosh_core::handoff_config::HandoffConfig::from_file(std::path::Path::new(&cfg_path_str)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading handoff config: {}", e);
                return 1;
            }
        }
    } else {
        aiosh_core::handoff_config::HandoffConfig::from_env_or_default()
    };

    let store_path_str = parse_flag(rest, "--store")
        .or_else(|| config.store_path.clone())
        .unwrap_or_else(|| format!("{}/handoff_store.json", ai_home()));
    let store_path = std::path::Path::new(&store_path_str);

    let (mut store, _recovery_warning) = aiosh_core::handoff_service::HandoffStore::load_or_recover_with_config(store_path, &config);

    match sub {
        Some("list") => {
            let active_only = has_flag(rest, "--active");
            let status_filter = parse_flag(rest, "--status");

            let records = if active_only {
                store.list_active()
            } else {
                store.list_all()
            };

            let filtered: Vec<_> = records
                .into_iter()
                .filter(|r| {
                    if let Some(ref st) = status_filter {
                        let st_str = format!("{:?}", r.status).to_lowercase();
                        st_str == st.to_lowercase()
                    } else {
                        true
                    }
                })
                .collect();

            if is_json {
                println!("{}", serde_json::to_string_pretty(&filtered).unwrap_or_default());
            } else {
                println!("{:<14} {:<12} {:<16} {:<16} {:<10} SUMMARY", "ID", "STATUS", "SENDER", "RECEIVER", "PRIORITY");
                println!("{}", "-".repeat(80));
                for r in &filtered {
                    println!(
                        "{:<14} {:<12?} {:<16} {:<16} {:<10?} {}",
                        r.id, r.status, r.sender_agent_id, r.receiver_agent_id, r.priority, r.context_summary
                    );
                }
                println!("\nTotal handoffs listed: {}", filtered.len());
            }
            0
        }
        Some("show") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh handoff show <id> [--json] [--store <path>]");
                    return 2;
                }
            };

            match store.get_by_id(id) {
                Some(r) => {
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
                    } else {
                        println!("Handoff Record: {}", r.id);
                        println!("Signature:      {}", r.signature);
                        println!("Status:         {:?}", r.status);
                        println!("Priority:       {:?}", r.priority);
                        println!("Sender:         {}", r.sender_agent_id);
                        println!("Receiver:       {}", r.receiver_agent_id);
                        if let Some(t) = r.task_id {
                            println!("Task ID:        {}", t);
                        }
                        println!("Created At:     {}", r.created_at);
                        if let Some(ref exp) = r.expires_at {
                            println!("Expires At:     {}", exp);
                        }
                        if let Some(ref notes) = r.resolution_notes {
                            println!("Notes:          {}", notes);
                        }
                        println!("Summary:        {}", r.context_summary);
                        println!("Payload:        {}", r.payload_json);
                    }
                    0
                }
                None => {
                    eprintln!("Error: Handoff record '{}' not found", id);
                    1
                }
            }
        }
        Some("initiate") => {
            let sender = match parse_flag(rest, "--sender") {
                Some(s) => s,
                None => {
                    eprintln!("Error: --sender is required for aiosh handoff initiate");
                    return 2;
                }
            };
            let receiver = match parse_flag(rest, "--receiver") {
                Some(r) => r,
                None => {
                    eprintln!("Error: --receiver is required for aiosh handoff initiate");
                    return 2;
                }
            };
            let summary = match parse_flag(rest, "--summary") {
                Some(s) => s,
                None => {
                    eprintln!("Error: --summary is required for aiosh handoff initiate");
                    return 2;
                }
            };
            let task_id = parse_flag(rest, "--task").and_then(|t| t.parse::<u32>().ok());
            let payload = parse_flag(rest, "--payload").unwrap_or_else(|| "{}".into());
            let priority = match parse_flag(rest, "--priority").as_deref() {
                Some("low") => aiosh_core::handoff::HandoffPriority::Low,
                Some("high") => aiosh_core::handoff::HandoffPriority::High,
                Some("urgent") => aiosh_core::handoff::HandoffPriority::Urgent,
                _ => aiosh_core::handoff::HandoffPriority::Normal,
            };

            let rec = store.initiate_handoff(&sender, &receiver, task_id, &summary, &payload, priority);

            if let Err(e) = store.save_to_path(store_path) {
                eprintln!("Error saving store: {}", e);
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "handoff",
                "initiate",
                json!({ "id": rec.id, "sender": sender, "receiver": receiver }),
                "success",
                Some(&rec.id),
                Some("Handoff initiated"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
            } else {
                println!("Initiated handoff: {} (status: {:?})", rec.id, rec.status);
            }
            0
        }
        Some("accept") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh handoff accept <id> [--notes <notes>] [--store <path>]");
                    return 2;
                }
            };
            let notes = parse_flag(rest, "--notes");

            match store.accept_handoff(id, notes.as_deref()) {
                Ok(rec) => {
                    if let Err(e) = store.save_to_path(store_path) {
                        eprintln!("Error saving store: {}", e);
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx,
                        "handoff",
                        "accept",
                        json!({ "id": rec.id, "receiver": rec.receiver_agent_id }),
                        "success",
                        Some(&rec.id),
                        Some("Handoff accepted"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
                    } else {
                        println!("Accepted handoff: {} (status: {:?})", rec.id, rec.status);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error accepting handoff: {}", e);
                    1
                }
            }
        }
        Some("reject") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh handoff reject <id> [--notes <notes>] [--store <path>]");
                    return 2;
                }
            };
            let notes = parse_flag(rest, "--notes");

            match store.reject_handoff(id, notes.as_deref()) {
                Ok(rec) => {
                    if let Err(e) = store.save_to_path(store_path) {
                        eprintln!("Error saving store: {}", e);
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx,
                        "handoff",
                        "reject",
                        json!({ "id": rec.id, "receiver": rec.receiver_agent_id }),
                        "success",
                        Some(&rec.id),
                        Some("Handoff rejected"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
                    } else {
                        println!("Rejected handoff: {} (status: {:?})", rec.id, rec.status);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error rejecting handoff: {}", e);
                    1
                }
            }
        }
        Some("complete") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh handoff complete <id> [--notes <notes>] [--store <path>]");
                    return 2;
                }
            };
            let notes = parse_flag(rest, "--notes");

            match store.complete_handoff(id, notes.as_deref()) {
                Ok(rec) => {
                    if let Err(e) = store.save_to_path(store_path) {
                        eprintln!("Error saving store: {}", e);
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx,
                        "handoff",
                        "complete",
                        json!({ "id": rec.id, "receiver": rec.receiver_agent_id }),
                        "success",
                        Some(&rec.id),
                        Some("Handoff completed"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
                    } else {
                        println!("Completed handoff: {} (status: {:?})", rec.id, rec.status);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error completing handoff: {}", e);
                    1
                }
            }
        }
        Some("cancel") => {
            let id = match rest.first() {
                Some(id_str) if !id_str.starts_with("--") => id_str.as_str(),
                _ => {
                    eprintln!("Usage: aiosh handoff cancel <id> [--notes <notes>] [--store <path>]");
                    return 2;
                }
            };
            let notes = parse_flag(rest, "--notes");

            match store.cancel_handoff(id, notes.as_deref()) {
                Ok(rec) => {
                    if let Err(e) = store.save_to_path(store_path) {
                        eprintln!("Error saving store: {}", e);
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx,
                        "handoff",
                        "cancel",
                        json!({ "id": rec.id, "sender": rec.sender_agent_id }),
                        "success",
                        Some(&rec.id),
                        Some("Handoff cancelled"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
                    } else {
                        println!("Cancelled handoff: {} (status: {:?})", rec.id, rec.status);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error cancelling handoff: {}", e);
                    1
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh handoff — Agent Handoff Protocol Manager\n\nUsage:\n  aiosh handoff list [--active] [--status <status>] [--json] [--store <path>]\n  aiosh handoff show <id> [--json] [--store <path>]\n  aiosh handoff initiate --sender <S> --receiver <R> [--task <T>] --summary <CTX> [--payload <JSON>] [--priority <P>] [--store <path>]\n  aiosh handoff accept <id> [--notes <notes>] [--store <path>]\n  aiosh handoff reject <id> [--notes <notes>] [--store <path>]\n  aiosh handoff complete <id> [--notes <notes>] [--store <path>]\n  aiosh handoff cancel <id> [--notes <notes>] [--store <path>]");
            0
        }
        Some(other) => {
            eprintln!("unknown handoff subcommand: {}", other);
            2
        }
    }
}

fn cmd_triage(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let config = if let Some(cfg_path_str) = parse_flag(rest, "--config") {
        match aiosh_core::triage_config::TriageConfig::from_file(std::path::Path::new(&cfg_path_str)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading triage config: {}", e);
                return 1;
            }
        }
    } else {
        aiosh_core::triage_config::TriageConfig::from_env_or_default()
    };

    let store_path_str = parse_flag(rest, "--store")
        .or_else(|| config.store_path.clone())
        .unwrap_or_else(|| format!("{}/triage_store.json", ai_home()));
    let store_path = std::path::Path::new(&store_path_str);

    let mut store = match aiosh_core::triage_service::TriageStore::load_from_path_with_config(store_path, &config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error loading triage store: {}", e);
            return 1;
        }
    };

    match sub {
        Some("list") => {
            let status_filter = parse_flag(rest, "--status");
            let severity_filter = parse_flag(rest, "--severity");

            let report = store.to_report();
            let filtered: Vec<_> = report.records.into_iter().filter(|r| {
                if let Some(ref st) = status_filter {
                    let st_str = match r.status {
                        aiosh_core::triage::TriageStatus::Untriaged => "untriaged",
                        aiosh_core::triage::TriageStatus::Triaged => "triaged",
                        aiosh_core::triage::TriageStatus::FixPending => "fix_pending",
                        aiosh_core::triage::TriageStatus::Resolved => "resolved",
                        aiosh_core::triage::TriageStatus::WontFix => "wont_fix",
                    };
                    if st_str != st.to_lowercase() {
                        return false;
                    }
                }
                if let Some(ref sv) = severity_filter {
                    let sv_str = match r.severity {
                        aiosh_core::triage::TriageSeverity::Blocker => "blocker",
                        aiosh_core::triage::TriageSeverity::Critical => "critical",
                        aiosh_core::triage::TriageSeverity::Major => "major",
                        aiosh_core::triage::TriageSeverity::Minor => "minor",
                    };
                    if sv_str != sv.to_lowercase() {
                        return false;
                    }
                }
                true
            }).collect();

            if is_json {
                println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
            } else {
                println!("=== AIOS Regression Triage Records ({}) ===", filtered.len());
                for r in &filtered {
                    println!("[{}] {:?} {:?} - {} ({}) occ:{}", r.id, r.severity, r.status, r.test_target, r.suite_name, r.occurrences);
                    println!("    error: {}", r.error_message.lines().next().unwrap_or(""));
                    if let Some(ref n) = r.resolution_notes {
                        println!("    notes: {}", n);
                    }
                }
            }
            0
        }
        Some("show") => {
            let id = match rest.first() {
                Some(i) => i,
                None => {
                    eprintln!("Usage: aiosh triage show <id> [--store <path>] [--json]");
                    return 2;
                }
            };
            if let Some(rec) = store.get_by_id(id) {
                if is_json {
                    println!("{}", serde_json::to_string_pretty(rec).unwrap());
                } else {
                    println!("Triage ID:       {}", rec.id);
                    println!("Signature:       {}", rec.signature);
                    println!("Status:          {:?}", rec.status);
                    println!("Severity:        {:?}", rec.severity);
                    println!("Test Target:     {}", rec.test_target);
                    println!("Suite Name:      {}", rec.suite_name);
                    println!("Occurrences:     {}", rec.occurrences);
                    println!("First Observed:  {}", rec.first_observed_at);
                    println!("Last Observed:   {}", rec.last_observed_at);
                    println!("Repro Command:   {}", rec.repro_command);
                    println!("Error Message:\n{}", rec.error_message);
                    if let Some(ref n) = rec.resolution_notes {
                        println!("Resolution Notes: {}", n);
                    }
                }
                0
            } else {
                eprintln!("Record {} not found", id);
                1
            }
        }
        Some("record") => {
            let target = match parse_flag(rest, "--target") {
                Some(t) => t,
                None => {
                    eprintln!("Missing required option --target");
                    return 2;
                }
            };
            let suite = parse_flag(rest, "--suite").unwrap_or_else(|| "manual".into());
            let error_msg = match parse_flag(rest, "--error") {
                Some(e) => e,
                None => {
                    eprintln!("Missing required option --error");
                    return 2;
                }
            };
            let repro = parse_flag(rest, "--repro").unwrap_or_else(|| "".into());
            let sev = match parse_flag(rest, "--severity").as_deref() {
                Some("blocker") => aiosh_core::triage::TriageSeverity::Blocker,
                Some("major") => aiosh_core::triage::TriageSeverity::Major,
                Some("minor") => aiosh_core::triage::TriageSeverity::Minor,
                _ => aiosh_core::triage::TriageSeverity::Critical,
            };

            let rec = store.record_failure(&target, &suite, &error_msg, &repro, sev);
            if let Err(e) = store.save_to_path(store_path) {
                eprintln!("Failed to save triage store: {}", e);
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "triage",
                "record",
                json!({ "id": rec.id, "target": target, "suite": suite }),
                "success",
                Some(&rec.id),
                Some("Regression recorded"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", serde_json::to_string_pretty(&rec).unwrap());
            } else {
                println!("Recorded triage item {} (occurrences: {})", rec.id, rec.occurrences);
            }
            0
        }
        Some("resolve") => {
            let id = match rest.first() {
                Some(i) => i,
                None => {
                    eprintln!("Usage: aiosh triage resolve <id> --notes <text> [--store <path>]");
                    return 2;
                }
            };
            let notes = match parse_flag(rest, "--notes") {
                Some(n) => n,
                None => {
                    eprintln!("Missing required option --notes");
                    return 2;
                }
            };

            let rec = match store.resolve(id, &notes) {
                Ok(r) => r.clone(),
                Err(e) => {
                    eprintln!("Resolve error: {}", e);
                    return 1;
                }
            };

            if let Err(e) = store.save_to_path(store_path) {
                eprintln!("Failed to save triage store: {}", e);
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "triage",
                "resolve",
                json!({ "id": id, "notes": notes }),
                "success",
                Some(id),
                Some("Regression resolved"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", serde_json::to_string_pretty(&rec).unwrap());
            } else {
                println!("Resolved triage item {}", rec.id);
            }
            0
        }
        Some("ingest") => {
            let file_path_str = match rest.first() {
                Some(f) => f,
                None => {
                    eprintln!("Usage: aiosh triage ingest <summary_json_file> [--store <path>]");
                    return 2;
                }
            };
            let summary_path = std::path::Path::new(file_path_str);
            let summary = match aiosh_core::ci::load_summary_with_retry(summary_path, 2) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to load CI summary: {}", e);
                    return 1;
                }
            };

            let count = store.ingest_ci_summary_with_config(&summary, &config);
            if let Err(e) = store.save_to_path(store_path) {
                eprintln!("Failed to save triage store: {}", e);
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "triage",
                "ingest",
                json!({ "source": file_path_str, "processed": count }),
                "success",
                Some(file_path_str),
                Some(&format!("Ingested {} regression candidates", count)),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "processed": count, "store": store_path_str }));
            } else {
                println!("Ingested {} regression candidates into {}", count, store_path_str);
            }
            0
        }
        Some("check") => {
            let report = store.to_report();
            let mut blocker_count = 0;
            let mut critical_count = 0;

            for r in &report.records {
                if r.status != aiosh_core::triage::TriageStatus::Resolved && r.status != aiosh_core::triage::TriageStatus::WontFix {
                    match r.severity {
                        aiosh_core::triage::TriageSeverity::Blocker => blocker_count += 1,
                        aiosh_core::triage::TriageSeverity::Critical => critical_count += 1,
                        _ => {}
                    }
                }
            }

            let ok = blocker_count == 0 && critical_count == 0;
            if is_json {
                println!("{}", json!({
                    "clean": ok,
                    "total_records": report.total_records,
                    "open_records": report.open_records,
                    "blocker_open": blocker_count,
                    "critical_open": critical_count
                }));
            } else {
                println!("=== AIOS Triage Check ===");
                println!("Total records:   {}", report.total_records);
                println!("Open records:    {}", report.open_records);
                println!("Blocker open:    {}", blocker_count);
                println!("Critical open:   {}", critical_count);
                if ok {
                    println!("\nPASS: No open blocker or critical regressions.");
                } else {
                    println!("\nFAIL: Found {} blocker and {} critical open regressions.", blocker_count, critical_count);
                }
            }
            if ok { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("Usage: aiosh triage <list|show|record|resolve|ingest|check> [options]\n\nSubcommands:\n  list [--status <st>] [--severity <sev>] [--json] [--store <path>]\n  show <id> [--json] [--store <path>]\n  record --target <target> --suite <suite> --error <msg> [--repro <cmd>] [--severity <sev>] [--store <path>]\n  resolve <id> --notes <notes> [--store <path>]\n  ingest <summary_file> [--store <path>]\n  check [--store <path>] [--json]");
            0
        }
        Some(other) => {
            eprintln!("unknown triage subcommand: {}", other);
            2
        }
    }
}

fn cmd_secrets(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let repo_flag = parse_flag(rest, "--repo");
    let file_flag = parse_flag(rest, "--file");
    let config_flag = parse_flag(rest, "--config");

    let config = match config_flag {
        Some(ref cp) => match aiosh_core::secrets_config::SecretsConfig::from_path(std::path::Path::new(cp)) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Failed to read secrets config: {}", e);
                if is_json {
                    return err_out(json!({"ok": false, "subcommand": "secrets", "error": msg}));
                } else {
                    eprintln!("[-] {}", msg);
                    return 1;
                }
            }
        },
        None => aiosh_core::secrets_config::SecretsConfig::from_env().unwrap_or_default(),
    };

    let max_bytes: u64 = parse_flag(rest, "--max-bytes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(config.max_file_bytes);

    let repo_root = repo_flag
        .as_deref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| std::path::Path::new("."));

    match sub {
        Some("scan") | Some("check") => {
            let is_check = sub == Some("check");
            let report = if let Some(ref file_path_str) = file_flag {
                let target_file = std::path::Path::new(file_path_str);
                let findings = match aiosh_core::secrets_service::scan_file_for_secrets(target_file, repo_root, max_bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        let msg = format!("Failed to scan file for secrets: {}", e);
                        emit(
                            &mut ctx,
                            "secrets.scan",
                            &format!("aiosh secrets scan --file {}", file_path_str),
                            json!({"file": file_path_str}),
                            "error",
                            Some(file_path_str),
                            Some(&msg),
                            "user",
                            None,
                            CFlags::default(),
                            None,
                        );
                        if is_json {
                            return err_out(json!({"ok": false, "subcommand": "secrets scan", "error": msg}));
                        } else {
                            eprintln!("[-] {}", msg);
                            return 1;
                        }
                    }
                };
                aiosh_core::secrets::SecretScanReport::new(
                    target_file.to_string_lossy().to_string(),
                    findings,
                    1,
                )
            } else {
                let ignored_slice: Vec<&str> = config.ignored_dirs.iter().map(|s| s.as_str()).collect();
                match aiosh_core::secrets_service::scan_workspace_for_secrets(
                    repo_root,
                    max_bytes,
                    &ignored_slice,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("Failed to scan workspace for secrets: {}", e);
                        emit(
                            &mut ctx,
                            "secrets.scan",
                            "aiosh secrets scan",
                            json!({"repo": repo_root.to_string_lossy()}),
                            "error",
                            None,
                            Some(&msg),
                            "user",
                            None,
                            CFlags::default(),
                            None,
                        );
                        if is_json {
                            return err_out(json!({"ok": false, "subcommand": "secrets scan", "error": msg}));
                        } else {
                            eprintln!("[-] {}", msg);
                            return 1;
                        }
                    }
                }
            };

            let outcome = if report.is_clean { "ok" } else { "failure" };
            emit(
                &mut ctx,
                if is_check { "secrets.check" } else { "secrets.scan" },
                &format!("aiosh secrets {}", if is_check { "check" } else { "scan" }),
                json!({
                    "repo": repo_root.to_string_lossy(),
                    "is_clean": report.is_clean,
                    "total_findings": report.total_findings,
                    "scanned_files_count": report.scanned_files_count,
                }),
                outcome,
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                if report.is_clean {
                    ok_out(json!({"ok": true, "subcommand": format!("secrets {}", if is_check { "check" } else { "scan" }), "data": report}));
                    0
                } else {
                    err_out(json!({"ok": false, "subcommand": format!("secrets {}", if is_check { "check" } else { "scan" }), "data": report}));
                    1
                }
            } else if is_check {
                if report.is_clean {
                    println!("[+] Secrets check passed (0 findings in {} files).", report.scanned_files_count);
                    0
                } else {
                    eprintln!("[-] Secrets check failed: {} findings detected across {} files in {}.", report.total_findings, report.scanned_files_count, report.repo_path);
                    1
                }
            } else {
                println!("=== Secrets & Access Hygiene Scan: {} ===", report.repo_path);
                println!("Timestamp: {}", report.timestamp_utc);
                println!(
                    "Status: {} ({} files scanned, {} findings: {} critical, {} high, {} medium, {} low)",
                    if report.is_clean { "CLEAN" } else { "FINDINGS DETECTED" },
                    report.scanned_files_count,
                    report.total_findings,
                    report.critical_findings,
                    report.high_findings,
                    report.medium_findings,
                    report.low_findings
                );
                println!();

                if !report.is_clean {
                    println!("Findings:");
                    for f in &report.findings {
                        println!(
                            "  - [!] {} ({:?}) {}:{} - {}",
                            f.rule_id, f.severity, f.path, f.line_number, f.description
                        );
                        let fp_short = if f.fingerprint.len() >= 8 { &f.fingerprint[..8] } else { &f.fingerprint };
                        println!("      Snippet: {} [fp: {}]", f.redacted_snippet, fp_short);
                    }
                }

                if report.is_clean { 0 } else { 1 }
            }
        }
        Some(other) => {
            eprintln!("unknown secrets subcommand: {} (usage: aiosh secrets <scan|check> [--repo <path>] [--file <path>] [--json])", other);
            2
        }
        None => {
            eprintln!("missing secrets subcommand (usage: aiosh secrets <scan|check> [--repo <path>] [--file <path>] [--json])");
            2
        }
    }
}

fn cmd_repo(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let repo_flag = parse_flag(rest, "--repo");
    let config_flag = parse_flag(rest, "--config");
    let repo_root = repo_flag
        .as_deref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| std::path::Path::new("."));

    let _config = match config_flag {
        Some(ref p) => match aiosh_core::repo_health_config::RepoHealthConfig::from_path(std::path::Path::new(p)) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Failed to load repo health config: {}", e);
                if is_json {
                    return err_out(json!({"ok": false, "subcommand": "repo health", "error": msg}));
                } else {
                    eprintln!("[-] {}", msg);
                    return 1;
                }
            }
        },
        None => aiosh_core::repo_health_config::RepoHealthConfig::from_env().unwrap_or_default(),
    };

    match sub {
        Some("health") | Some("check") => {
            let report = match aiosh_core::repo_health_service::check_repo_health(repo_root) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("Failed to assess repository health: {}", e);
                    emit(
                        &mut ctx,
                        "repo.health",
                        "aiosh repo health",
                        json!({"repo": repo_root.to_string_lossy()}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        return err_out(json!({"ok": false, "subcommand": "repo health", "error": msg}));
                    } else {
                        eprintln!("[-] {}", msg);
                        return 1;
                    }
                }
            };

            let is_fail = report.overall_status == aiosh_core::repo_health::HealthStatus::Fail;
            let outcome = if is_fail { "error" } else { "ok" };

            emit(
                &mut ctx,
                "repo.health",
                "aiosh repo health",
                json!({
                    "repo": repo_root.to_string_lossy(),
                    "overall_status": report.overall_status,
                    "total_checks": report.total_checks,
                    "failed_checks": report.failed_checks,
                }),
                outcome,
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                if is_fail {
                    err_out(json!({"ok": false, "subcommand": "repo health", "data": report}));
                    return 1;
                } else {
                    ok_out(json!({"ok": true, "subcommand": "repo health", "data": report}));
                    return 0;
                }
            } else {
                println!("=== Repository Health Assessment: {} ===", report.repo_path);
                println!("Timestamp: {}", report.timestamp_utc);
                println!(
                    "Overall Status: {:?} ({} checks: {} pass, {} warn, {} fail, {} skip)",
                    report.overall_status,
                    report.total_checks,
                    report.passed_checks,
                    report.warn_checks,
                    report.failed_checks,
                    report.skipped_checks
                );
                println!();

                for c in &report.checks {
                    let symbol = match c.status {
                        aiosh_core::repo_health::HealthStatus::Pass => "[+]",
                        aiosh_core::repo_health::HealthStatus::Warn => "[!]",
                        aiosh_core::repo_health::HealthStatus::Fail => "[-]",
                        aiosh_core::repo_health::HealthStatus::Skip => "[*]",
                    };
                    println!("{} {} ({}, {:?}) - {}ms", symbol, c.name, c.check_id, c.category, c.duration_ms);
                    println!("    {}", c.message);
                    if let Some(ref details) = c.details {
                        for d in details {
                            println!("      * {}", d);
                        }
                    }
                }

                if is_fail { 1 } else { 0 }
            }
        }
        Some(other) => {
            eprintln!("unknown repo subcommand: {} (usage: aiosh repo <health|check> [--repo <path>] [--json])", other);
            2
        }
        None => {
            eprintln!("missing repo subcommand (usage: aiosh repo <health|check> [--repo <path>] [--json])");
            2
        }
    }
}

fn cmd_doc(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let repo_flag = parse_flag(rest, "--repo");
    let config_flag = parse_flag(rest, "--config");
    let repo_root = repo_flag
        .as_deref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| std::path::Path::new("."));

    let _config = match config_flag {
        Some(ref p) => match aiosh_core::doc_index_config::DocIndexConfig::from_path(std::path::Path::new(p)) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Failed to load doc index config: {}", e);
                if is_json {
                    return err_out(json!({"ok": false, "subcommand": "doc", "error": msg}));
                } else {
                    eprintln!("[-] {}", msg);
                    return 1;
                }
            }
        },
        None => aiosh_core::doc_index_config::DocIndexConfig::from_env().unwrap_or_default(),
    };

    let default_docs = &["docs/README.md", "docs/SPEC-TASK-LEDGER.md", "docs/tasks/GOALS.md"];

    match sub {
        Some("show") => {
            let manifest = match aiosh_core::doc_index_service::build_doc_index_from_paths(repo_root, default_docs) {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to build doc index: {}", e);
                    emit(
                        &mut ctx,
                        "doc.show",
                        "aiosh doc show",
                        json!({"repo": repo_root.to_string_lossy()}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        return err_out(json!({"ok": false, "subcommand": "doc show", "error": msg}));
                    } else {
                        eprintln!("[-] {}", msg);
                        return 1;
                    }
                }
            };

            emit(
                &mut ctx,
                "doc.show",
                "aiosh doc show",
                json!({"repo": repo_root.to_string_lossy(), "count": manifest.entries.len()}),
                "ok",
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                ok_out(json!({"ok": true, "subcommand": "doc show", "data": manifest}));
            } else {
                println!("{}", aiosh_core::doc_index_service::format_doc_index_summary(&manifest));
            }
            0
        }
        Some("check") => {
            let (_manifest, report, telemetry) = match aiosh_core::doc_index_service::reconcile_doc_index(repo_root, default_docs) {
                Ok(t) => t,
                Err(e) => {
                    let msg = format!("Failed to read doc files: {}", e);
                    emit(
                        &mut ctx,
                        "doc.check",
                        "aiosh doc check",
                        json!({"repo": repo_root.to_string_lossy()}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        return err_out(json!({"ok": false, "subcommand": "doc check", "error": msg}));
                    } else {
                        eprintln!("[-] {}", msg);
                        return 1;
                    }
                }
            };

            let outcome = if report.is_valid { "ok" } else { "failure" };
            emit(
                &mut ctx,
                "doc.check",
                "aiosh doc check",
                json!({"repo": repo_root.to_string_lossy(), "report": report, "telemetry": telemetry}),
                outcome,
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                if report.is_valid {
                    ok_out(json!({"ok": true, "subcommand": "doc check", "data": report}));
                    0
                } else {
                    err_out(json!({"ok": false, "subcommand": "doc check", "data": report}));
                    1
                }
            } else {
                if report.is_valid {
                    println!("[+] Documentation link verification passed ({} links checked)", report.total_links_checked);
                    0
                } else {
                    eprintln!("[-] Broken links detected ({} links checked, {} broken):", report.total_links_checked, report.broken_links.len());
                    for b in &report.broken_links {
                        eprintln!("    - {} -> {} ({})", b.source_path, b.target_link, b.reason);
                    }
                    1
                }
            }
        }
        Some("search") => {
            let positional = strip_flags(rest, &["--json", "--repo"]);
            let query = match positional.first() {
                Some(q) => q.to_lowercase(),
                None => {
                    eprintln!("usage: aiosh doc search <query> [--json] [--repo <path>]");
                    return 2;
                }
            };

            let manifest = match aiosh_core::doc_index_service::build_doc_index_from_paths(repo_root, default_docs) {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to read doc files: {}", e);
                    if is_json {
                        return err_out(json!({"ok": false, "subcommand": "doc search", "error": msg}));
                    } else {
                        eprintln!("[-] {}", msg);
                        return 1;
                    }
                }
            };

            let matches: Vec<_> = manifest.entries.into_iter().filter(|e| {
                e.title.to_lowercase().contains(&query) ||
                e.path.to_lowercase().contains(&query) ||
                e.section.to_lowercase().contains(&query)
            }).collect();

            emit(
                &mut ctx,
                "doc.search",
                "aiosh doc search",
                json!({"query": query, "matches_count": matches.len()}),
                "ok",
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                ok_out(json!({"ok": true, "subcommand": "doc search", "data": matches}));
            } else {
                println!("Documentation search results for '{}':", query);
                for entry in &matches {
                    println!("  [{}] {} ({})", entry.section, entry.title, entry.path);
                }
            }
            0
        }
        _ => {
            eprintln!("usage: aiosh doc <show|check|search> [--json] [--repo <path>]");
            2
        }
    }
}

fn cmd_evidence(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let is_json = has_flag(rest, "--json");
    let repo_flag = parse_flag(rest, "--repo");
    let manifest_flag = parse_flag(rest, "--manifest");
    let repo_root = repo_flag
        .as_deref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| std::path::Path::new("."));

    match sub {
        Some("verify") => {
            let manifest = match manifest_flag {
                Some(ref p) => {
                    let content = match std::fs::read_to_string(p) {
                        Ok(c) => c,
                        Err(e) => {
                            let msg = format!("Failed to read manifest file {}: {}", p, e);
                            if is_json {
                                return err_out(json!({"ok": false, "subcommand": "evidence verify", "error": msg}));
                            } else {
                                eprintln!("[-] {}", msg);
                                return 1;
                            }
                        }
                    };
                    match aiosh_core::evidence::TaskEvidenceManifest::from_json(&content) {
                        Ok(m) => m,
                        Err(e) => {
                            let msg = format!("Failed to parse evidence manifest: {}", e);
                            if is_json {
                                return err_out(json!({"ok": false, "subcommand": "evidence verify", "error": msg}));
                            } else {
                                eprintln!("[-] {}", msg);
                                return 1;
                            }
                        }
                    }
                }
                None => aiosh_core::evidence::TaskEvidenceManifest::default(),
            };

            let report = match aiosh_core::evidence_service::verify_evidence_manifest(repo_root, &manifest) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("Failed to verify evidence manifest: {}", e);
                    emit(
                        &mut ctx,
                        "evidence.verify",
                        "aiosh evidence verify",
                        json!({"repo": repo_root.to_string_lossy()}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        return err_out(json!({"ok": false, "subcommand": "evidence verify", "error": msg}));
                    } else {
                        eprintln!("[-] {}", msg);
                        return 1;
                    }
                }
            };

            let outcome = if report.is_valid { "ok" } else { "failure" };
            emit(
                &mut ctx,
                "evidence.verify",
                "aiosh evidence verify",
                json!({"repo": repo_root.to_string_lossy(), "report": report}),
                outcome,
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                if report.is_valid {
                    ok_out(json!({"ok": true, "subcommand": "evidence verify", "data": report}));
                } else {
                    err_out(json!({"ok": false, "subcommand": "evidence verify", "error": "Evidence verification failed", "report": report}));
                }
            } else {
                if report.is_valid {
                    println!("[+] All {} evidence records verified successfully (SHA-256 match).", report.total_records);
                } else {
                    eprintln!("[-] Evidence verification failed: {}/{} valid.", report.valid_records, report.total_records);
                    for m in &report.missing_files {
                        eprintln!("    - Missing: {}", m);
                    }
                    for h in &report.hash_mismatches {
                        eprintln!("    - Mismatch: {}", h);
                    }
                    return 1;
                }
            }
            0
        }
        Some("hash") => {
            let positional = strip_flags(rest, &["--json"]);
            let path_str = match positional.first() {
                Some(p) => p,
                None => {
                    eprintln!("usage: aiosh evidence hash <path> [--json]");
                    return 2;
                }
            };
            let target_path = std::path::Path::new(path_str);
            match aiosh_core::evidence_service::compute_file_sha256(target_path) {
                Ok(hash) => {
                    emit(
                        &mut ctx,
                        "evidence.hash",
                        "aiosh evidence hash",
                        json!({"path": path_str, "sha256": hash}),
                        "ok",
                        None,
                        None,
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        ok_out(json!({"ok": true, "subcommand": "evidence hash", "path": path_str, "sha256": hash}));
                    } else {
                        println!("[+] {} -> {}", path_str, hash);
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("Failed to compute SHA-256 for {}: {}", path_str, e);
                    emit(
                        &mut ctx,
                        "evidence.hash",
                        "aiosh evidence hash",
                        json!({"path": path_str}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    if is_json {
                        err_out(json!({"ok": false, "subcommand": "evidence hash", "error": msg}))
                    } else {
                        eprintln!("[-] {}", msg);
                        1
                    }
                }
            }
        }
        Some("scan") => {
            let task_filter = parse_flag(rest, "--task").and_then(|s| s.parse::<u32>().ok());
            let evidence_dir = repo_root.join("docs/tasks/evidence");
            if !evidence_dir.exists() {
                let msg = format!("Evidence directory not found: {}", evidence_dir.display());
                if is_json {
                    return err_out(json!({"ok": false, "subcommand": "evidence scan", "error": msg}));
                } else {
                    eprintln!("[-] {}", msg);
                    return 1;
                }
            }

            let mut records = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().map_or(false, |ext| ext == "md") {
                        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                        if file_name.starts_with('T') && file_name.contains('-') {
                            let parts: Vec<&str> = file_name.split('-').collect();
                            if parts.len() >= 2 {
                                if let Ok(tid) = parts[1].parse::<u32>() {
                                    if task_filter.map_or(true, |target| target == tid) {
                                        let rel_path = format!("docs/tasks/evidence/{}", file_name);
                                        if let Ok(hash) = aiosh_core::evidence_service::compute_file_sha256(&path) {
                                            records.push(json!({
                                                "task_id": tid,
                                                "file_path": rel_path,
                                                "sha256": hash
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            emit(
                &mut ctx,
                "evidence.scan",
                "aiosh evidence scan",
                json!({"repo": repo_root.to_string_lossy(), "count": records.len()}),
                "ok",
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );

            if is_json {
                ok_out(json!({"ok": true, "subcommand": "evidence scan", "data": records}));
            } else {
                println!("Scanned {} evidence files in {}", records.len(), evidence_dir.display());
                for r in &records {
                    println!("  [T-{:05}] {} ({})", r["task_id"].as_u64().unwrap_or(0), r["file_path"].as_str().unwrap_or(""), &r["sha256"].as_str().unwrap_or("")[..8]);
                }
            }
            0
        }
        _ => {
            eprintln!("usage: aiosh evidence <verify|hash|scan> [--json] [--repo <path>] [--manifest <path>] [--task <id>]");
            2
        }
    }
}

fn cmd_release(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    match sub {
        Some("generate") => {
            let os = match parse_flag(args, "--os") {
                Some(v) => v,
                None => {
                    eprintln!("usage: aiosh release generate --os <target_os> --version <version> [--components <c1,c2...>]");
                    return 2;
                }
            };
            let version = match parse_flag(args, "--version") {
                Some(v) => v,
                None => {
                    eprintln!("usage: aiosh release generate --os <target_os> --version <version> [--components <c1,c2...>]");
                    return 2;
                }
            };
            let comp_str = parse_flag(args, "--components").unwrap_or_else(|| "core".into());
            let components: Vec<String> = comp_str.split(',').map(|s| s.trim().to_string()).collect();
            
            let manifest = aiosh_core::release::PackageManifest {
                target_os: os,
                version,
                components,
            };
            
            let mut rel_ctx = aiosh_core::release::ReleaseCtx {
                ring: &mut ctx.ring,
                actor_id: &ctx.actor_id,
                constitution_rev: &ctx.con_rev,
            };
            
            match aiosh_core::release::generate_release(&mut rel_ctx, &manifest) {
                Ok((path, hash)) => {
                    ok_out(json!({"ok": true, "subcommand": "release generate", "data": {"artifact_path": path, "hash": hash}}));
                    0
                }
                Err(e) => {
                    err_out(json!({"ok": false, "subcommand": "release generate", "error": e}));
                    1
                }
            }
        }
        _ => {
            eprintln!("usage: aiosh release generate --os <target_os> --version <version> [--components <c1,c2...>]");
            2
        }
    }
}

fn cmd_toolchain(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());

    // Parse optional --config <path> from remaining args
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let mut config_path: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--config" {
            if i + 1 >= rest.len() {
                eprintln!("usage: aiosh toolchain <check|show> [--config <path>]");
                return 2;
            }
            config_path = Some(rest[i + 1].clone());
            i += 2;
        } else {
            eprintln!("unknown flag: {}", rest[i]);
            eprintln!("usage: aiosh toolchain <check|show> [--config <path>]");
            return 2;
        }
    }

    // Resolve manifest using --config flag, env var, or default path
    let load_manifest = || -> Result<aiosh_core::toolchain_config::ToolchainManifest, String> {
        match &config_path {
            Some(p) => aiosh_core::toolchain_config::ToolchainManifest::from_path(p),
            None => aiosh_core::toolchain_config::ToolchainManifest::from_env(),
        }
    };

    match sub {
        Some("check") => {
            let manifest = match load_manifest() {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to load toolchain config: {}", e);
                    err_out(json!({"ok": false, "subcommand": "toolchain check", "error": msg.clone()}));
                    emit(
                        &mut ctx,
                        "toolchain.check",
                        "aiosh toolchain check",
                        json!({}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    return 1;
                }
            };

            match aiosh_core::toolchain_service::enforce_toolchain(&manifest) {
                Ok(_) => {
                    let data = manifest.to_json_with_sources();
                    ok_out(json!({"ok": true, "subcommand": "toolchain check", "data": data}));
                    emit(
                        &mut ctx,
                        "toolchain.check",
                        "aiosh toolchain check",
                        json!({"manifest": data}),
                        "success",
                        None,
                        None,
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    0
                }
                Err(e) => {
                    err_out(json!({"ok": false, "subcommand": "toolchain check", "error": e}));
                    emit(
                        &mut ctx,
                        "toolchain.check",
                        "aiosh toolchain check",
                        json!({}),
                        "error",
                        None,
                        Some(&e),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    1
                }
            }
        }
        Some("show") => {
            let manifest = match load_manifest() {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to load toolchain config: {}", e);
                    err_out(json!({"ok": false, "subcommand": "toolchain show", "error": msg.clone()}));
                    emit(
                        &mut ctx,
                        "toolchain.show",
                        "aiosh toolchain show",
                        json!({}),
                        "error",
                        None,
                        Some(&msg),
                        "user",
                        None,
                        CFlags::default(),
                        None,
                    );
                    return 1;
                }
            };

            let data = manifest.to_json_with_sources();
            ok_out(json!({"ok": true, "subcommand": "toolchain show", "data": data}));
            emit(
                &mut ctx,
                "toolchain.show",
                "aiosh toolchain show",
                json!({"manifest": data}),
                "success",
                None,
                None,
                "user",
                None,
                CFlags::default(),
                None,
            );
            0
        }
        _ => {
            eprintln!("usage: aiosh toolchain <check|show> [--config <path>]");
            2
        }
    }
}

fn cmd_backup(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    match sub {
        Some("create") => {
            let target_path = match parse_flag(args, "--target-path") {
                Some(t) => t,
                None => {
                    eprintln!("usage: aiosh backup create --target-path <path> [--include-audit <true|false>] [--include-memory <true|false>]");
                    return 2;
                }
            };
            let include_audit = match parse_flag(args, "--include-audit").as_deref() {
                Some("false") => false,
                _ => true,
            };
            let include_memory = match parse_flag(args, "--include-memory").as_deref() {
                Some("true") => true,
                _ => false,
            };
            
            let snapshot = aiosh_core::release::BackupSnapshot {
                target_path,
                include_audit,
                include_memory,
            };
            
            let mut rel_ctx = aiosh_core::release::ReleaseCtx {
                ring: &mut ctx.ring,
                actor_id: &ctx.actor_id,
                constitution_rev: &ctx.con_rev,
            };
            
            match aiosh_core::release::create_backup(&mut rel_ctx, &snapshot) {
                Ok(path) => {
                    ok_out(json!({"ok": true, "subcommand": "backup create", "data": {"backup_path": path}}));
                    0
                }
                Err(e) => {
                    err_out(json!({"ok": false, "subcommand": "backup create", "error": e}));
                    1
                }
            }
        }
        _ => {
            eprintln!("usage: aiosh backup create --target-path <path> [--include-audit <true|false>] [--include-memory <true|false>]");
            2
        }
    }
}

/// `aiosh task` — Task Ledger Control (T-00016; unified validation
/// T-00034 via `task_service::TaskCall`, spec T-00032). Every outcome —
/// including usage refusals — writes an honest audit row (ADR-0035 §F-2).
fn cmd_ci(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let action = args.first().map(|s| s.as_str());
    let file_arg = parse_flag(args, "--file").unwrap_or_else(|| {
        std::env::var("AIOSH_CI_RESULTS").unwrap_or_else(|_| "/tmp/aiosh-ci-results.json".to_string())
    });

    let path = std::path::Path::new(&file_arg);
    let summary = match aiosh_core::ci::load_summary_with_retry(path, 3) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ci-service: {}", e);
            emit(
                &mut ctx,
                "aiosh",
                "ci check",
                json!({"file": file_arg}),
                "error",
                None,
                Some(&e),
                "human",
                None,
                CFlags::default(),
                None,
            );
            return 2;
        }
    };

    match action {
        Some("show") => {
            print!("{}", aiosh_core::ci::human_report(&summary));
            0
        }
                Some("metrics") => {
            match aiosh_core::ci_config::CiConfig::from_env() {
                Ok(cfg) => {
                    let snapshot = serde_json::json!({
                        "ok": true,
                        "action": "metrics",
                        "ci": &summary,
                        "config": cfg.to_json_with_sources()
                    });
                    println!("{}", serde_json::to_string_pretty(&snapshot).unwrap());
                    0
                }
                Err(e) => {
                    eprintln!("{}", e);
                    2
                }
            }
        }
        Some("config") => {
            match aiosh_core::ci_config::CiConfig::from_env() {
                Ok(cfg) => {
                    println!("{}", serde_json::to_string_pretty(&cfg.to_json_with_sources()).unwrap());
                    0
                }
                Err(e) => {
                    eprintln!("{}", e);
                    2
                }
            }
        }
        Some("failures") => {
            let failures: Vec<_> = summary.results.iter().filter(|r| r.status != "pass").collect();
            if failures.is_empty() {
                println!("no failed suites");
            } else {
                for r in failures {
                    let rc = r.exit_code.map_or("-".to_string(), |c| c.to_string());
                    println!("[FAIL] {} {} ({} ms) exit={} log={}", r.index, r.suite, r.duration_ms, rc, r.log_path);
                }
            }
            0
        }
        Some("check") => {
            let passed = summary.all_pass;
            let msg = if passed {
                format!("ci-check: PASS ({}/{} suites)", summary.passed, summary.total)
            } else {
                format!("ci-check: FAIL ({}/{} suites, {} failed)", summary.passed, summary.total, summary.failed)
            };
            println!("{}", msg);
            
            emit(
                &mut ctx,
                "aiosh",
                "ci check",
                json!({"file": file_arg}),
                if passed { "success" } else { "failure" },
                None,
                Some(&msg),
                "human",
                None,
                CFlags::default(),
                None,
            );

            if passed { 0 } else { 1 }
        }
        _ => {
            eprintln!("usage: aiosh ci <show|failures|check|config|metrics> [--file PATH]

  config                       print resolved configuration and source
    metrics                      print consolidated JSON observability snapshot");
            2
        }
    }
}

fn cmd_task(args: &[String]) -> i32 {
    if args.first().map(|s| s.as_str()) == Some("help") {
        println!("{}", task_usage_text(None));
        return 0;
    }
    let sub = args.first().cloned().unwrap_or_default();
    let label = if sub.is_empty() { "task".to_string() } else { format!("task {sub}") };
    let mut ctx = open_context();
    let run = || -> Result<Value, String> {
        if sub == "config" {
            let cfg = aiosh_core::ledger_config::LedgerConfig::from_env()?;
            return Ok(cfg.to_json_with_sources());
        }
        if sub == "metrics" {
            // T-00085: metrics is a no-operand action; a stray token is a
            // loud usage refusal (audited via the standard envelope below),
            // never silently ignored.
            if let Some(extra) = args.get(1) {
                return Err(format!(
                    "unexpected argument '{extra}' — 'metrics' takes no operands"
                ));
            }
            let cfg = aiosh_core::ledger_config::LedgerConfig::from_env()?;
            let tasks = aiosh_core::ledger::load_state(&aiosh_core::ledger::paths()?.state,
                                                       &aiosh_core::ledger::paths()?.events)?;
            let vr = ctx.ring.verify().map_err(|e| e.to_string())?;
            let head = ctx.ring.tail(1).unwrap_or_default();
            let prefix = head.first().map(|r| r.hash.chars().take(16).collect::<String>())
                               .unwrap_or_default();
            return aiosh_core::task_service::TaskCall::build_metrics_pub(
                tasks, vr.checked, vr.ok, &prefix, &cfg);
        }
        let parsed = parse_task_args(args)?;
        let call = parsed.call();
        call.validate()?;
        let p = aiosh_core::ledger::paths()?;
        if call.action == aiosh_core::task_service::TaskAction::Metrics {
            // T-00084: consolidated observability snapshot. The CLI
            // owns the ring handle, so it supplies audit facts here
            // (read-only surface; same envelope as other subs).
            let verify = ctx.ring.verify().map_err(|e| e.to_string())?;
            // T-00088 hardening: O(1) COUNT(*) instead of loading every
            // live row into memory via tail(i64::MAX).
            let rows = ctx.ring.count().unwrap_or(0) as usize;
            let head = ctx.ring.tail(1).unwrap_or_default();
            let head_prefix = head.first().map(|r| r.hash.chars().take(12).collect::<String>()).unwrap_or_default();
            let cfg = aiosh_core::ledger_config::LedgerConfig::from_env()?;
            let tasks = aiosh_core::ledger::load_state(&p.state, &p.events)?;
            return aiosh_core::task_service::TaskCall::build_metrics(tasks, rows, verify.ok, &head_prefix, &cfg);
        }
        call.execute_with(&p)
    };
    let (code, outcome, detail) = match run() {
        Ok(v) => {
            ok_out(json!({"ok": true, "subcommand": label, "data": v}));
            (0, "ok", None)
        }
        Err(e) => {
            err_out(json!({"ok": false, "subcommand": label, "error": e}));
            (1, "refused", Some(e))
        }
    };
    emit(
        &mut ctx,
        "task.ledger",
        &format!("aiosh {}", label),
        json!({"subcommand": sub, "args": &args[1.min(args.len())..]}),
        outcome,
        None,
        detail.as_deref(),
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    code
}

// ----------------------------------------------------------------------
// T-00034 IMPLEMENTATION — CLI surface unification (spec T-00032).
//
// Replaces the permissive `flag_after` parsing (research T-00031
// Q2/Q3/Q4/Q6). cmd_task now routes through these helpers.
//
// Contract highlights (spec §2):
//   - argv -> TaskArgsOwned mirroring `task_service::parse_args`
//     semantics for non-JSON input: decimal u64 >= 1 ids, non-empty
//     note/reason, 4096-byte text cap, <=16 evidence items, values
//     must not start with "--" unless after a `--` delimiter,
//     unknown subcommand/missing values are usage errors.
//   - `--` ends option parsing; later tokens are values even when
//     dash-prefixed.
//   - options-after-operands stays (documented POSIX-G9 deviation).

// ----------------------------------------------------------------------
// T-00034 IMPLEMENTATION — CLI surface unification (spec T-00032).
//
// argv -> TaskArgsOwned mirroring `task_service::parse_args` semantics
// for non-JSON input. Grammar (spec §2):
//   - decimal u64 >= 1 operand where required; exactly one.
//   - options AFTER operands allowed (documented POSIX-G9 deviation).
//   - option values must be separate arguments, must not start with
//     "--" unless after a `--` delimiter (G7/G14), and must exist (no
//     silent-empty).
//   - `--` ends option parsing; later tokens are values even when
//     dash-prefixed (G10).
//   - unknown dash-tokens are errors naming the token.
// Semantic rules (non-empty, caps, conditional ids) stay in
// `TaskCall::validate` — the SAME code the MCP surface runs.

fn missing_value(opt: &str) -> String {
    format!("missing value for '{opt}'\n{}", task_usage_text(None))
}

/// Consume the value token for `opt` starting at `*i` (pointing at the
/// option). A bare `--` in value position becomes the delimiter and the
/// FOLLOWING token is taken as the value (spec §2 / POSIX G10+G14).
fn take_value(
    args: &[String],
    i: &mut usize,
    opt: &str,
    past_dd: &mut bool,
) -> Result<String, String> {
    *i += 1;
    loop {
        let v = args.get(*i).ok_or_else(|| missing_value(opt))?;
        if v == "--" && !*past_dd {
            *past_dd = true;
            *i += 1;
            continue;
        }
        if v.starts_with("--") && !*past_dd {
            return Err(format!(
                "value for '{opt}' must not start with \"--\" (use \"--\" to pass literals)"
            ));
        }
        return Ok(v.clone());
    }
}

fn parse_task_args(args: &[String]) -> Result<aiosh_core::task_service::TaskArgsOwned, String> {
    use aiosh_core::task_service::{TaskAction, TaskArgsOwned, MAX_EVIDENCE_ITEMS};
    let overview = task_usage_text(None);
    let sub = args
        .first()
        .ok_or_else(|| overview.clone())?;
    let action =
        TaskAction::parse(sub).ok_or_else(|| format!("unknown subcommand '{sub}'\n{overview}"))?;
    let needs_id = !matches!(
        action,
        TaskAction::Status | TaskAction::Check | TaskAction::Validate | TaskAction::Rebuild
    );
    let mut task_id: Option<u64> = None;
    let mut note: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut evidence: Vec<String> = Vec::new();
    let mut past_dd = false;
    let mut i = 1;
    while i < args.len() {
        let tok = &args[i];
        if !past_dd && tok == "--" {
            past_dd = true;
            i += 1;
            continue;
        }
        if !past_dd && tok.starts_with('-') && tok.len() > 1 {
            let (slot, opt): (&mut Option<String>, &str) = match tok.as_str() {
                "--note" => (&mut note, "--note"),
                "--reason" => (&mut reason, "--reason"),
                "--evidence" => {
                    let v = take_value(args, &mut i, "--evidence", &mut past_dd)?;
                    if evidence.len() >= MAX_EVIDENCE_ITEMS {
                        return Err(format!("'evidence' exceeds {MAX_EVIDENCE_ITEMS} items"));
                    }
                    evidence.push(v);
                    i += 1; // take_value left i on the value token
                    continue;
                }
                other => {
                    return Err(format!(
                        "unknown option '{other}'\n{}",
                        task_usage_text(Some(sub))
                    ))
                }
            };
            *slot = Some(take_value(args, &mut i, opt, &mut past_dd)?);
            i += 1;
            continue;
        }
        // Bare token: the single required operand, or an error.
        if needs_id && task_id.is_none() {
            let id: u64 = tok
                .parse()
                .map_err(|_| format!("invalid task_id '{tok}' (decimal integer >= 1)\n{}", task_usage_text(Some(sub))))?;
            if id == 0 {
                return Err(format!(
                    "invalid task_id '0' (must be >= 1)\n{}",
                    task_usage_text(Some(sub))
                ));
            }
            task_id = Some(id);
        } else {
            return Err(format!(
                "unexpected argument '{tok}'\n{}",
                task_usage_text(Some(sub))
            ));
        }
        i += 1;
    }
    Ok(TaskArgsOwned {
        action,
        task_id,
        note,
        reason,
        evidence,
        grant_id: None,
    })
}

fn task_usage_text(sub: Option<&str>) -> String {
    let overview = "\
usage: aiosh task <status|check|validate|config|done|block|unblock|skip|rebuild|help> [args]

  status                       print TASK_STATE.json
  check                        validate ledger invariants
  validate                     read-only integrity report (state vs events)
  done     <id> --note <text> [--evidence <path>]...
  block    <id> --reason <text>
  unblock  <id> --reason <text>
  skip     <id> --reason <text>
  rebuild                      recompute pointer from COMPLETIONS.jsonl
  config                       print effective AIOSH_LEDGER_* settings
  help                         this help

notes:
  * done/block/unblock/skip act ONLY on the current next_task (no-skip law)
  * text values: non-empty, <= 4096 bytes; evidence: <= 16 paths
  * a value may not start with \"--\" unless preceded by a lone \"--\"
  * options may appear after the operand (intentional GNU-style deviation)";
    match sub {
        None => overview.to_string(),
        Some("done") => "\
usage: aiosh task done <task_id> --note <text> [--evidence <path>]...
  complete the current next_task; --note is required and non-empty."
            .into(),
        Some("block") => "\
usage: aiosh task block <task_id> --reason <text>
  refuse to proceed; pointer does not advance.".into(),
        Some("unblock") => "\
usage: aiosh task unblock <task_id> --reason <text>
  clear the blocked marker; pointer returns to <task_id>.".into(),
        Some("skip") => "\
usage: aiosh task skip <task_id> --reason <text>
  human override: record pointer_reset and advance past <task_id>.".into(),
        Some("status") => "usage: aiosh task status\n  print the live TASK_STATE.json pointer.".into(),
        Some("check") => "usage: aiosh task check\n  validate ledger invariants (ids contiguous, linear deps).".into(),
        Some("validate") => "usage: aiosh task validate\n  read-only integrity report: live state vs event-log replay (report-only; `task rebuild` remains the only repair path).".into(),
        Some("rebuild") => "usage: aiosh task rebuild\n  recompute TASK_STATE.json from the append-only event log.".into(),
        Some(other) => format!("no such subcommand '{other}'\n{overview}"),
    }
}

fn cmd_status() -> i32 {
    let mut ctx = open_context();
    let verify = ctx.ring.verify().expect("verify");
    let head = ctx.ring.tail(1).unwrap_or_default();
    emit(
        &mut ctx,
        "system.status",
        "aiosh status",
        json!({}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    let data = json!({
        "aiosh_version": "0.1.0",
        "ai_home": ai_home(),
        "audit_db": db_path(),
        "constitution_rev": ctx.con_rev,
        "constitution_title": ctx.con_title,
        "constitution_source": ctx.con_source,
        "audit_ring": {
            "verify_ok": verify.ok,
            "rows": verify.checked,
            "head_hash": head.first().map(|r| r.hash.clone()).unwrap_or_else(|| "null".into()),
        },
        "rust": format!("{}", rustc_version()),
    });
    ok_out(json!({"ok": true, "subcommand": "status", "outcome": "ok",
                  "audit_id": -1, "data": data}));
    0
}

fn rustc_version() -> String {
    let v = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into());
    format!("aiosh-rust/{}", v)
}

fn cmd_run(args: &[String]) -> i32 {
    let mut ctx = open_context();
    // Single-pass option parsing: `--target VALUE` / `--target=VALUE` is
    // consumed together with its value; EVERY other token — including
    // dash-prefixed ones — belongs to the spawned command's argv.
    let mut target: Option<String> = None;
    let mut command_args: Vec<String> = Vec::new();
    {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == "--target" {
                target = it.next().cloned();
                continue;
            }
            if let Some(v) = a.strip_prefix("--target=") {
                target = Some(v.to_string());
                continue;
            }
            command_args.push(a.clone());
        }
    }
    if command_args.is_empty() {
        return err_out(json!({"ok": false, "subcommand": "run", "outcome": "error",
                              "audit_id": -1, "error": "usage: aiosh run <command...>"}));
    }
    let command = command_args.join(" ");
    let bin = command_args[0].clone();
    let rest = command_args[1..].to_vec();

    // Sandbox policy (conservative defaults).
    let policy = json!({
        "paths_ro": ["/usr", "/lib", "/lib64", "/etc/ld.so.cache",
                    "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/dev", "/proc/self"],
        "paths_rw": ["/tmp"],
        "paths_execute": ["/usr/bin", "/usr/local/bin", "/bin"],
        "no_new_privs": true,
        "seccomp_denylist": ["ptrace", "mount", "umount2", "reboot", "kexec_load",
                             "kexec_file_load", "init_module", "finit_module",
                             "delete_module", "setuid", "setgid", "setreuid", "setregid",
                             "setresuid", "setresgid", "chroot", "pivot_root"],
        "inherit_defaults": true,
    });
    let argv: Vec<String> = std::iter::once(bin.clone())
        .chain(rest.clone())
        .collect();
    let result = aiosh_core::sandbox::sandbox_exec(&argv, &parse_policy(&policy));
    let mut full_argv = vec![bin.clone()];
    full_argv.extend(rest.clone());
    let outcome = if result == 0 { "ok" } else { "error" };
    let outcome_detail: Option<String> = if result == 0 {
        None
    } else {
        Some(format!("exit code {}", result))
    };
    classify_and_emit(
        &mut ctx,
        "process.run",
        &format!("aiosh run {}", command),
        json!({"bin": bin, "args": rest, "target": target, "policy": policy}),
        outcome,
        target.as_deref().or(Some(bin.as_str())),
        outcome_detail.as_deref(),
        "user",
        None,
    );
    ok_out(json!({"ok": result == 0, "subcommand": "run",
                  "outcome": if result == 0 { "ok" } else { "error" },
                  "audit_id": -1,
                  "data": {"bin": bin, "args": rest, "exit_code": result}}));
    if result == 0 { 0 } else { 1 }
}

fn parse_policy(v: &Value) -> aiosh_core::sandbox::SandboxPolicy {
    aiosh_core::sandbox::SandboxPolicy::from_json(&v.to_string()).unwrap_or_default()
}

fn cmd_agent(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let grant = parse_flag(args, "--grant");
    let max_steps: usize = parse_flag(args, "--max-steps")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .clamp(1, 32);
    let ollama_url = parse_flag(args, "--ollama-url").unwrap_or_else(|| "http://localhost:11434".into());
    let ollama_model =
        parse_flag(args, "--ollama-model").unwrap_or_else(|| "qwen2.5:7b-instruct".into());

    // First positional token(s) = the prompt. Known value-taking flags
    // are skipped together with their values so option values never
    // leak into the prompt text.
    const VALUE_FLAGS: [&str; 4] =
        ["--grant", "--max-steps", "--ollama-url", "--ollama-model"];
    let mut prompt_args: Vec<String> = Vec::new();
    {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if VALUE_FLAGS.contains(&a.as_str()) {
                let _ = it.next(); // consume the flag's value
                continue;
            }
            if a.starts_with("--") {
                continue;
            }
            prompt_args.push(a.clone());
        }
    }
    let prompt = prompt_args.join(" ");
    if prompt.is_empty() {
        return err_out(json!({"ok": false, "subcommand": "agent", "outcome": "error",
                              "audit_id": -1, "error": "usage: aiosh agent <prompt>"}));
    }

    if let Some(g) = &grant {
        if ctx.pep.get(g).expect("grant get").is_none() {
            let out = classify_and_emit(
                &mut ctx,
                "agent.invoke",
                "aiosh agent",
                json!({"prompt": prompt.chars().take(256).collect::<String>(), "grant": g}),
                "refused",
                None,
                Some(&format!("unknown grant {}", g)),
                "user",
                Some(g),
            );
            return err_out(json!({"ok": false, "subcommand": "agent", "outcome": "refused",
                                  "audit_id": out.id, "error": format!("unknown grant: {}", g),
                                  "data": {}}));
        }
    }

    classify_and_emit(
        &mut ctx,
        "agent.invoke",
        "aiosh agent",
        json!({"prompt": prompt.chars().take(256).collect::<String>(),
               "grant": grant, "max_steps": max_steps}),
        "ok",
        None,
        None,
        "user",
        grant.as_deref(),
    );

    let loop_opts = aiosh_core::agent::AgentLoopOptions {
        prompt: &prompt,
        grant_id: grant.as_deref(),
        ring: &mut ctx.ring,
        constitution_rev: &ctx.con_rev,
        ollama_url: &ollama_url,
        ollama_model: &ollama_model,
        max_steps,
        pep: &ctx.pep,
        dispatcher: None,
    };
    let result = aiosh_core::agent::run_agent_loop(loop_opts);
    ok_out(json!({"ok": true, "subcommand": "agent", "outcome": "ok",
                  "audit_id": -1, "data": result.to_json()}));
    0
}

fn cmd_audit(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str());
    match sub {
        Some("tail") => cmd_audit_tail(&args[1..]),
        Some("verify") => cmd_audit_verify(&args[1..]),
        Some("rotate") => cmd_audit_rotate(&args[1..]),
        Some("segments") => cmd_audit_segments(),
        Some("seen") => cmd_audit_seen(&args[1..]),
        Some("query") => cmd_audit_query(&args[1..]),
        Some("ancestry") => cmd_audit_ancestry(&args[1..]),
        Some("sign-verify") => cmd_audit_sign_verify(&args[1..]),
        Some("inspect") => cmd_audit_inspect(&args[1..]),
        Some("config") => cmd_audit_config(&args[1..]),
        Some("policy") => cmd_audit_policy(&args[1..]),
        Some("stats") | Some("telemetry") => cmd_audit_stats(&args[1..]),
        Some("doc") => cmd_audit_doc(&args[1..]),
        Some("validate") => cmd_audit_validate(&args[1..]),
        Some("repair") => cmd_audit_repair(&args[1..]),
        _ => {
            eprintln!("usage: aiosh audit <tail|verify|rotate|segments|seen|query|ancestry|sign-verify|inspect|config|policy|stats|doc|validate|repair>");
            2
        }
    }
}

fn cmd_audit_config(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let cfg = aiosh_core::audit_chain_config::AuditChainConfig::from_env();
    if is_json {
        println!("{}", serde_json::to_string_pretty(&cfg).unwrap_or_default());
    } else {
        println!("=== Audit Chain Configuration ===");
        println!("Version:                    {}", cfg.version);
        println!("DB Path:                    {}", cfg.db_path.display());
        println!("Max Query Limit:            {}", cfg.max_query_limit);
        println!("Default Lineage Depth:      {}", cfg.default_lineage_depth);
        println!("Max Causal Links:           {}", cfg.max_causal_links);
        println!("Max Extensions Bytes:       {}", cfg.max_extensions_bytes);
        println!("Verify Signatures on Read:  {}", cfg.verify_signatures_on_read);
        println!("Strict Provenance:          {}", cfg.strict_provenance);
    }
    0
}

fn cmd_audit_policy(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let mut path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--path" {
            path = iter.next().cloned();
        }
    }

    let policy = match path {
        Some(p) => match aiosh_core::audit_chain_policy::AuditChainSecurityPolicy::load_from_file(&p) {
            Ok(pol) => pol,
            Err(err) => {
                eprintln!("Error loading audit policy: {}", err);
                return 1;
            }
        },
        None => aiosh_core::audit_chain_policy::AuditChainSecurityPolicy::default(),
    };

    if is_json {
        println!("{}", serde_json::to_string_pretty(&policy).unwrap_or_default());
    } else {
        println!("=== Audit Chain Security Policy ===");
        println!("Version:                    {}", policy.version);
        println!("Mode:                       {:?}", policy.mode);
        println!("Description:                {}", policy.description);
        println!("Disallow Anonymous:         {}", policy.disallow_anonymous);
        println!("Max Causal Links:           {}", policy.max_allowed_causal_links);
        println!("Max Future Skew (s):        {}", policy.allow_future_timestamps_max_secs);
        println!("Prohibited Actors:          {:?}", policy.prohibited_actors);
        println!("Prohibited Tools:           {:?}", policy.prohibited_tools);
        println!("Signature Required:         {:?}", policy.signature_required_prefixes);
    }
    0
}

fn cmd_audit_stats(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let ctx = open_context();
    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let report = match aiosh_core::audit_chain_observability::AuditChainObservabilityReport::generate(&service) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error generating audit observability report: {}", e);
            return 1;
        }
    };

    if is_json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else {
        println!("=== Audit Chain Observability & Telemetry ===");
        println!("Generated At (UTC):          {}", report.generated_at_utc);
        println!("Total Rows:                  {}", report.total_rows);
        println!("Extended Rows:               {}", report.total_extended_rows);
        println!("Total Causal Links:          {}", report.total_causal_links);
        println!("Signed Events:               {}", report.total_signed_events);
        println!("Unique Actors:               {}", report.unique_actors_count);
        println!("Unique Tools:                {}", report.unique_tools_count);
        println!("Unique Sessions:             {}", report.unique_sessions_count);
        println!("Unique Traces:               {}", report.unique_traces_count);
        println!("Active Policy Mode:          {}", report.active_policy_mode);
        println!("DB File Bytes:               {}", report.db_file_bytes);
        println!("Chain Integrity OK:          {}", report.chain_integrity_ok);
        println!("System Healthy:              {}", report.is_healthy);
        println!("Outcomes Distribution:       {:?}", report.outcomes_by_type);
    }
    0
}

fn cmd_audit_doc(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let index = aiosh_core::audit_chain_doc::AuditChainDocIndex::new();

    let non_flags: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(|s| s.as_str())
        .collect();

    if non_flags.is_empty() {
        if is_json {
            println!("{}", serde_json::to_string_pretty(index.list_topics()).unwrap_or_default());
        } else {
            println!("=== Audit Chain Documentation Topics ===");
            for t in index.list_topics() {
                println!("{:<24} [{}] {}", t.id, t.category.as_str(), t.title);
                println!("  Summary: {}", t.summary);
            }
        }
        return 0;
    }

    let target = non_flags[0];
    if let Some(topic) = index.get_topic(target) {
        if is_json {
            println!("{}", serde_json::to_string_pretty(topic).unwrap_or_default());
        } else {
            match index.render_markdown(target) {
                Ok(md) => print!("{}", md),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return 1;
                }
            }
        }
        return 0;
    }

    match index.search(target) {
        Ok(results) => {
            if is_json {
                println!("{}", serde_json::to_string_pretty(&results).unwrap_or_default());
            } else {
                println!("=== Search Results for '{}' ===", target);
                if results.is_empty() {
                    println!("No matching topics found.");
                } else {
                    for r in results {
                        println!("- {} (id: {}, score: {})", r.title, r.topic_id, r.score);
                        println!("  {}", r.snippet);
                    }
                }
            }
            0
        }
        Err(e) => {
            eprintln!("Error searching audit doc: {}", e);
            1
        }
    }
}

fn cmd_audit_validate(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let ctx = open_context();
    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);

    match aiosh_core::audit_chain_recovery::AuditChainRecoveryManager::validate(&service) {
        Ok(report) => {
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("=== Audit Chain Invariant Validation ===");
                println!("Total Events:      {}", report.total_events);
                println!("Healthy Events:    {}", report.healthy_events);
                println!("Is Valid:          {}", report.is_valid);
                println!("Can Auto-Repair:   {}", report.can_auto_repair);
                if !report.issues.is_empty() {
                    println!("\nDetected Issues ({}):", report.issues.len());
                    for issue in report.issues {
                        println!("- [{:?}] {:?}: {}", issue.severity, issue.code, issue.message);
                        if let Some(row_id) = issue.row_id {
                            println!("    Row ID: {}", row_id);
                        }
                    }
                }
            }
            if report.is_valid { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("Error validating audit chain: {}", e);
            1
        }
    }
}

fn cmd_audit_repair(args: &[String]) -> i32 {
    let is_json = args.iter().any(|a| a == "--json");
    let mut backup_dir = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--backup-dir" {
            backup_dir = iter.next().cloned();
        }
    }

    let ctx = open_context();
    let mut service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let dir_path = backup_dir.as_ref().map(|s| std::path::Path::new(s));

    match aiosh_core::audit_chain_recovery::AuditChainRecoveryManager::recover(&mut service, dir_path) {
        Ok(res) => {
            if is_json {
                println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
            } else {
                println!("=== Audit Chain Forward Recovery Result ===");
                println!("Success:           {}", res.ok);
                if let Some(ref bp) = res.backup_path {
                    println!("Backup Snapshot:   {}", bp);
                }
                println!("Repaired Actions:  {}", res.repaired_count);
                for act in &res.actions {
                    println!("- [{}] {}", act.action_type, act.description);
                }
                println!("Post-validation:   is_valid={}", res.post_validation.is_valid);
            }
            if res.ok { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("Error executing audit chain recovery: {}", e);
            1
        }
    }
}

fn cmd_audit_tail(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let n: i64 = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .clamp(1, 1024);
    let rows = ctx.ring.tail(n).expect("tail");
    let rows_json: Vec<Value> = rows.iter().map(|r| row_to_json(r)).collect();
    emit(
        &mut ctx,
        "audit.tail",
        &format!("aiosh audit tail {}", n),
        json!({"n": n}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    ok_out(json!({"ok": true, "subcommand": "audit tail", "outcome": "ok",
                  "audit_id": -1, "data": {"count": rows_json.len(), "rows": rows_json}}));
    0
}

fn row_to_json(r: &AuditRow) -> Value {
    // Same shape as the legacy to_dict: base fields + conditional classifier.
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(r.id));
    m.insert("ts".into(), json!(r.ts));
    m.insert("actor".into(), json!(r.actor));
    m.insert("actor_id".into(), json!(r.actor_id));
    m.insert("tool".into(), json!(r.tool));
    m.insert("command".into(), json!(r.command));
    m.insert("args".into(), r.args.clone());
    m.insert("target".into(), json!(r.target));
    m.insert("outcome".into(), json!(r.outcome));
    m.insert("outcome_detail".into(), json!(r.outcome_detail));
    m.insert("constitution_rev".into(), json!(r.constitution_rev));
    m.insert("grant_token".into(), json!(r.grant_token));
    m.insert("c_flags".into(), r.c_flags.to_json());
    if let Some(p) = &r.policy_revision {
        m.insert("policy_revision".into(), json!(p));
    }
    if let Some(ids) = &r.classify_rule_ids {
        m.insert("classify_rule_ids".into(), json!(ids));
    }
    if let Some(ev) = &r.classify_evidence {
        m.insert("classify_evidence".into(), ev.clone());
    }
    if let Some(v) = &r.classify_overall_verdict {
        m.insert("classify_overall_verdict".into(), json!(v));
    }
    if let Some(v) = &r.classify_verdict_reason {
        m.insert("classify_verdict_reason".into(), json!(v));
    }
    m.insert("prev_hash".into(), json!(r.prev_hash));
    m.insert("hash".into(), json!(r.hash));
    Value::Object(m)
}

fn cmd_audit_verify(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let full = has_flag(args, "--full");
    let conn = ctx.ring.conn();
    let v = if full {
        let res = retention::verify_full(&conn, None).expect("verify_full");
        json!({
            "ok": res.ok,
            "checked": res.checked,
            "broken_at": res.broken_at,
            "anchor": res.anchor,
            "segments": res.segments,
            "archive_checked": res.archive_checked,
            "live_checked": res.live_checked,
            "broken_segment": res.broken_segment,
            "error": res.error,
            "mode": "full",
        })
    } else {
        let res = ctx.ring.verify().expect("verify");
        json!({
            "ok": res.ok,
            "checked": res.checked,
            "broken_at": res.broken_at,
            "anchor": res.anchor,
            "segments": res.segments,
            "mode": "live",
        })
    };
    let vok = v["ok"].as_bool().unwrap_or(false);
    emit(
        &mut ctx,
        "audit.verify",
        &format!("aiosh audit verify{}", if full { " --full" } else { "" }),
        json!({"full": full}),
        if vok { "ok" } else { "refused" },
        None,
        if vok {
            None
        } else {
            v.get("error").and_then(|e| e.as_str())
        },
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    print_result(
        json!({"ok": vok, "subcommand": "audit verify",
               "outcome": if vok { "ok" } else { "refused" },
               "audit_id": -1, "data": v}),
        vok,
    )
}

fn cmd_audit_rotate(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let keep: i64 = parse_flag(args, "--keep").and_then(|s| s.parse().ok()).unwrap_or(0);
    let dry_run = has_flag(args, "--dry-run");
    let db_path = ctx.ring.path().to_string();
    let conn = match if db_path == ":memory:" {
        rusqlite::Connection::open_in_memory()
    } else {
        rusqlite::Connection::open(&db_path)
    } {
        Ok(c) => c,
        Err(e) => {
            eprintln!("audit rotate failed to open database: {e}");
            return 1;
        }
    };
    let res = match retention::rotate(
        &conn,
        &mut ctx.ring,
        retention::RotateOptions {
            keep_rows: keep,
            dry_run,
            actor: "user".into(),
            actor_id: ctx.actor_id.clone(),
            constitution_rev: Some(ctx.con_rev.clone()),
            ..Default::default()
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("audit rotate operation failed: {e}");
            return 1;
        }
    };
    let out = json!({
        "ok": res.ok, "subcommand": "audit rotate",
        "outcome": if res.ok { "ok" } else { "refused" },
        "audit_id": res.audit_id.unwrap_or(-1),
        "data": res.to_json(),
        "error": res.error,
    });
    print_result(out, res.ok)
}

fn cmd_audit_segments() -> i32 {
    let mut ctx = open_context();
    let conn = ctx.ring.conn();
    let segs = retention::list_segments(&conn).expect("segments");
    let segs_json: Vec<Value> = segs
        .iter()
        .map(|s| {
            json!({
                "segment_id": s.segment_id,
                "closed_at": s.closed_at,
                "first_row_id": s.first_row_id,
                "last_row_id": s.last_row_id,
                "row_count": s.row_count,
                "genesis_prev_hash": s.genesis_prev_hash,
                "head_hash": s.head_hash,
                "archive_path": s.archive_path,
                "archive_sha256": s.archive_sha256,
                "bloom_m_bits": s.bloom_m_bits,
                "bloom_k": s.bloom_k,
                "bloom_hex": s.bloom_hex,
            })
        })
        .collect();
    emit(
        &mut ctx,
        "audit.segments",
        "aiosh audit segments",
        json!({}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    ok_out(json!({"ok": true, "subcommand": "audit segments", "outcome": "ok",
                  "audit_id": -1, "data": {"count": segs_json.len(), "segments": segs_json}}));
    0
}

fn cmd_audit_seen(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let hash = args
        .first()
        .cloned()
        .unwrap_or_default();
    let exact = has_flag(args, "--exact");
    let conn = ctx.ring.conn();
    let res = retention::seen(&conn, &hash, exact, None).expect("seen");
    emit(
        &mut ctx,
        "audit.seen",
        &format!("aiosh audit seen {}", hash),
        json!({"hash": hash, "exact": exact}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    ok_out(json!({"ok": true, "subcommand": "audit seen", "outcome": "ok",
                  "audit_id": -1, "data": res.to_json()}));
    0
}

fn cmd_audit_query(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let session_id = parse_flag(args, "--session");
    let trace_id = parse_flag(args, "--trace");
    let actor = parse_flag(args, "--actor");
    let tool = parse_flag(args, "--tool");
    let parent_hash = parse_flag(args, "--parent");
    let limit = parse_flag(args, "--limit").and_then(|s| s.parse::<usize>().ok());

    let filter = aiosh_core::audit_chain_service::AuditQueryFilter {
        session_id: session_id.clone(),
        trace_id: trace_id.clone(),
        actor: actor.clone(),
        tool: tool.clone(),
        parent_hash: parent_hash.clone(),
        limit,
    };

    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let rows = match service.query_events(&filter) {
        Ok(r) => r,
        Err(e) => {
            return err_out(json!({
                "ok": false,
                "subcommand": "audit query",
                "outcome": "error",
                "audit_id": -1,
                "error": e
            }));
        }
    };
    let rows_json: Vec<Value> = rows.iter().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect();
    let count = rows_json.len();
    ctx.ring = service.into_ring();

    emit(
        &mut ctx,
        "audit.query",
        "aiosh audit query",
        json!({"session": session_id, "trace": trace_id, "actor": actor, "tool": tool, "parent": parent_hash, "limit": limit}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );

    ok_out(json!({
        "ok": true,
        "subcommand": "audit query",
        "outcome": "ok",
        "audit_id": -1,
        "data": {
            "count": count,
            "rows": rows_json
        }
    }));
    0
}

fn cmd_audit_ancestry(args: &[String]) -> i32 {
    let hash = args.first().cloned().unwrap_or_default();
    if hash.is_empty() {
        eprintln!("usage: aiosh audit ancestry <hash> [--depth <n>]");
        return 2;
    }
    let depth: usize = parse_flag(args, "--depth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    let mut ctx = open_context();
    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let report = match service.trace_ancestry(&hash, depth) {
        Ok(rep) => rep,
        Err(e) => {
            return err_out(json!({
                "ok": false,
                "subcommand": "audit ancestry",
                "outcome": "error",
                "audit_id": -1,
                "error": e
            }));
        }
    };
    ctx.ring = service.into_ring();

    emit(
        &mut ctx,
        "audit.ancestry",
        &format!("aiosh audit ancestry {} --depth {}", hash, depth),
        json!({"hash": hash, "depth": depth}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );

    ok_out(json!({
        "ok": true,
        "subcommand": "audit ancestry",
        "outcome": "ok",
        "audit_id": -1,
        "data": serde_json::to_value(&report).unwrap_or(Value::Null)
    }));
    0
}

fn cmd_audit_sign_verify(args: &[String]) -> i32 {
    let hash = args.first().cloned().unwrap_or_default();
    if hash.is_empty() {
        eprintln!("usage: aiosh audit sign-verify <hash>");
        return 2;
    }

    let mut ctx = open_context();
    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let report = match service.verify_event_signature(&hash) {
        Ok(rep) => rep,
        Err(e) => {
            return err_out(json!({
                "ok": false,
                "subcommand": "audit sign-verify",
                "outcome": "error",
                "audit_id": -1,
                "error": e
            }));
        }
    };
    ctx.ring = service.into_ring();

    emit(
        &mut ctx,
        "audit.sign-verify",
        &format!("aiosh audit sign-verify {}", hash),
        json!({"hash": hash}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );

    ok_out(json!({
        "ok": true,
        "subcommand": "audit sign-verify",
        "outcome": "ok",
        "audit_id": -1,
        "data": serde_json::to_value(&report).unwrap_or(Value::Null)
    }));
    0
}

fn cmd_audit_inspect(args: &[String]) -> i32 {
    let hash = args.first().cloned().unwrap_or_default();
    if hash.is_empty() {
        eprintln!("usage: aiosh audit inspect <hash>");
        return 2;
    }

    let mut ctx = open_context();
    let service = aiosh_core::audit_chain_service::AuditChainService::new(ctx.ring);
    let row = match service.get_row_by_hash(&hash) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return err_out(json!({
                "ok": false,
                "subcommand": "audit inspect",
                "outcome": "not_found",
                "audit_id": -1,
                "error": format!("Audit event with hash {} not found", hash)
            }));
        }
        Err(e) => {
            return err_out(json!({
                "ok": false,
                "subcommand": "audit inspect",
                "outcome": "error",
                "audit_id": -1,
                "error": e
            }));
        }
    };
    ctx.ring = service.into_ring();

    emit(
        &mut ctx,
        "audit.inspect",
        &format!("aiosh audit inspect {}", hash),
        json!({"hash": hash}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );

    ok_out(json!({
        "ok": true,
        "subcommand": "audit inspect",
        "outcome": "ok",
        "audit_id": -1,
        "data": serde_json::to_value(&row).unwrap_or(Value::Null)
    }));
    0
}

fn cmd_grant(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str());
    match sub {
        Some("create") => cmd_grant_create(&args[1..]),
        Some("list") => cmd_grant_list(),
        Some("revoke") => cmd_grant_revoke(&args[1..]),
        _ => {
            eprintln!("usage: aiosh grant <create|list|revoke>");
            2
        }
    }
}

fn cmd_grant_create(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let to = parse_flag(args, "--to").unwrap_or_default();
    let tools_str = parse_flag(args, "--tools").unwrap_or_default();
    let networks = parse_flag(args, "--networks");
    let allow = parse_flag(args, "--allow");
    let deny = parse_flag(args, "--deny");
    let ttl: i64 = parse_flag(args, "--ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
    let max_irreversible = parse_flag(args, "--max-irreversible").and_then(|s| s.parse().ok());

    if to.is_empty() || tools_str.is_empty() {
        return err_out(json!({"ok": false, "subcommand": "grant create", "outcome": "error",
                              "audit_id": -1,
                              "error": "--to and --tools are required"}));
    }
    let scope = GrantScope {
        tools: tools_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        networks: networks
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
            .unwrap_or_default(),
        paths: PathScope {
            allow: allow
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
            deny: deny
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
        },
        max_irreversible,
    };
    let grant = ctx
        .pep
        .create(&scope, ttl, &to, &ctx.con_rev)
        .expect("grant create");
    emit(
        &mut ctx,
        "pep.grant.create",
        "aiosh grant create",
        json!({"scope": scope_to_json(&scope), "ttl": ttl, "issued_to": to}),
        "ok",
        Some(&grant.grant_id),
        None,
        "user",
        Some(&grant.grant_id),
        CFlags { c4: true, ..Default::default() },
        None,
    );
    ok_out(json!({"ok": true, "subcommand": "grant create", "outcome": "ok",
                  "audit_id": -1,
                  "data": {
                      "grant_id": grant.grant_id,
                      "issued_at": grant.issued_at,
                      "expires_at": grant.expires_at,
                      "issued_to": grant.issued_to,
                      "constitution_rev": grant.constitution_rev,
                      "scope": scope_to_json(&grant.scope),
                  }}));
    0
}

fn scope_to_json(scope: &GrantScope) -> Value {
    json!({
        "tools": scope.tools,
        "networks": scope.networks,
        "paths": {"allow": scope.paths.allow, "deny": scope.paths.deny},
        "max_irreversible": scope.max_irreversible,
    })
}

fn cmd_grant_list() -> i32 {
    let mut ctx = open_context();
    let grants = ctx.pep.list(true).expect("grant list");
    let grants_json: Vec<Value> = grants
        .iter()
        .map(|g| {
            json!({
                "grant_id": g.grant_id,
                "issued_at": g.issued_at,
                "expires_at": g.expires_at,
                "issued_to": g.issued_to,
                "constitution_rev": g.constitution_rev,
                "scope": scope_to_json(&g.scope),
            })
        })
        .collect();
    emit(
        &mut ctx,
        "pep.grant.list",
        "aiosh grant list",
        json!({}),
        "ok",
        None,
        None,
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    ok_out(json!({"ok": true, "subcommand": "grant list", "outcome": "ok",
                  "audit_id": -1, "data": {"count": grants_json.len(), "grants": grants_json}}));
    0
}

fn cmd_grant_revoke(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let grant_id = args.first().cloned().unwrap_or_default();
    let ok = ctx.pep.revoke(&grant_id).expect("revoke");
    emit(
        &mut ctx,
        "pep.grant.revoke",
        &format!("aiosh grant revoke {}", grant_id),
        json!({"grant_id": grant_id}),
        if ok { "ok" } else { "refused" },
        Some(&grant_id),
        if ok { None } else { Some("grant already revoked") },
        "user",
        None,
        CFlags { c4: true, ..Default::default() },
        None,
    );
    print_result(
        json!({"ok": ok, "subcommand": "grant revoke",
               "outcome": if ok { "ok" } else { "refused" },
               "audit_id": -1,
               "data": {"grant_id": grant_id, "revoked": ok}}),
        ok,
    )
}

fn cmd_pentest(args: &[String]) -> i32 {
    let tool = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = &args[1..];
    let grant = parse_flag(rest, "--grant");
    let timeout: u64 = parse_flag(rest, "--timeout-s").and_then(|s| s.parse().ok()).unwrap_or(60);
    // Positional args (drop --grant/--timeout-s and their values).
    let positional = strip_flags(rest, &["--grant", "--timeout-s"]);

    let mut ctx = open_context();
    let result = match tool {
        "nmap" => {
            let target = positional.first().cloned().unwrap_or_default();
            if target.is_empty() {
                return err_out(json!({"ok": false, "error": "nmap requires <target>"}));
            }
            pentest::pentest_nmap(&mut pentest_ctx(&mut ctx), &target, grant.as_deref(), timeout)
        }
        "nikto" => {
            let target = positional.first().cloned().unwrap_or_default();
            if target.is_empty() {
                return err_out(json!({"ok": false, "error": "nikto requires <target>"}));
            }
            pentest::pentest_nikto(&mut pentest_ctx(&mut ctx), &target, grant.as_deref(), timeout)
        }
        "sqlmap" => {
            let url = positional.first().cloned().unwrap_or_default();
            if url.is_empty() {
                return err_out(json!({"ok": false, "error": "sqlmap requires <url>"}));
            }
            let level: i64 = parse_flag(rest, "--level").and_then(|s| s.parse().ok()).unwrap_or(1);
            let risk: i64 = parse_flag(rest, "--risk").and_then(|s| s.parse().ok()).unwrap_or(1);
            pentest::pentest_sqlmap(&mut pentest_ctx(&mut ctx), &url, grant.as_deref(), level, risk, timeout)
        }
        "tshark" => {
            let pcap = positional.first().cloned().unwrap_or_default();
            if pcap.is_empty() {
                return err_out(json!({"ok": false, "error": "tshark requires <pcap_path>"}));
            }
            let filter = parse_flag(rest, "--display-filter");
            pentest::pentest_tshark(&mut pentest_ctx(&mut ctx), &pcap, filter.as_deref(), grant.as_deref(), timeout)
        }
        "aircrack-ng" => {
            let capture = positional.first().cloned().unwrap_or_default();
            let wordlist = positional.get(1).cloned().unwrap_or_default();
            if capture.is_empty() || wordlist.is_empty() {
                return err_out(json!({"ok": false, "error": "aircrack-ng requires <capture> <wordlist>"}));
            }
            pentest::pentest_aircrack_ng(&mut pentest_ctx(&mut ctx), &capture, &wordlist, grant.as_deref(), timeout)
        }
        _ => {
            return err_out(json!({"ok": false, "error": format!(
                "unknown pentest tool: {} (nmap|nikto|sqlmap|tshark|aircrack-ng)", tool)}));
        }
    };
    let r_ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    print_result(
        json!({"ok": r_ok, "subcommand": format!("pentest {}", tool),
               "outcome": if r_ok { "ok" } else { "refused" },
               "audit_id": result.get("audit_id").cloned().unwrap_or(json!(-1)),
               "data": result}),
        r_ok,
    )
}

fn pentest_ctx(ctx: &mut Ctx) -> pentest::RunToolCtx<'_> {
    pentest::RunToolCtx {
        ring: &mut ctx.ring,
        pep: &ctx.pep,
        constitution_rev: &ctx.con_rev,
        actor_id: &ctx.actor_id,
    }
}

fn strip_flags(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut out = vec![];
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if flags.contains(&a.as_str()) {
            let _ = it.next();
            continue;
        }
        out.push(a.clone());
    }
    out
}

fn cmd_classify(args: &[String]) -> i32 {
    let tool = args.first().cloned().unwrap_or_default();
    if tool.is_empty() {
        eprintln!("usage: aiosh classify <tool> [--target T] [--json-args S]");
        return 2;
    }
    let target = parse_flag(args, "--target");
    let json_args = parse_flag(args, "--json-args").unwrap_or_else(|| "{}".into());
    let parsed: Value = match serde_json::from_str(&json_args) {
        Ok(v) => v,
        Err(e) => {
            return err_out(json!({"ok": false, "subcommand": "classify", "outcome": "error",
                                  "audit_id": 0,
                                  "data": {"error": format!("invalid --json-args: {}", e)}}));
        }
    };
    let result = classify(&tool, target.as_deref(), &parsed);
    println!(
        "{}",
        serde_json::to_string_pretty(&result.to_dict()).unwrap()
    );
    0
}

fn cmd_kernel_module(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_opt = parse_flag(rest, "--store");
    if let Some(ref p) = store_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "kernel_module",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid store path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let proc_path_opt = parse_flag(rest, "--proc-modules");
    if let Some(ref p) = proc_path_opt {
        if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
            let msg = "proc-modules path cannot exceed 1024 characters and cannot contain control characters";
            classify_and_emit(
                &mut ctx,
                "kernel_module",
                sub.unwrap_or("unknown"),
                json!({ "error": msg }),
                "failure",
                None,
                Some("Invalid proc-modules path"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let resolved_store_path = store_path_opt
        .clone()
        .unwrap_or_else(|| std::env::var("AIOSH_KERNEL_MODULE_STORE").unwrap_or_else(|_| format!("{}/kernel_modules.json", ai_home())));

    let load_store = || -> Result<aiosh_core::kernel_module_service::KernelModuleStore, String> {
        let p = std::path::Path::new(&resolved_store_path);
        if p.exists() {
            aiosh_core::kernel_module_service::KernelModuleStore::load_from_path(p)
        } else {
            Ok(aiosh_core::kernel_module_service::KernelModuleStore::new("default", "AIOS Kernel Module Store"))
        }
    };

    let save_store = |store: &aiosh_core::kernel_module_service::KernelModuleStore| -> Result<(), String> {
        let p = std::path::Path::new(&resolved_store_path);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store.save_to_path(p)
    };

    match sub {
        Some("list") => {
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "list",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };
            let mut service = aiosh_core::kernel_module_service::KernelModuleService::new(store);
            if let Some(proc_p) = proc_path_opt {
                service = service.with_proc_modules_path(std::path::PathBuf::from(proc_p));
            }
            let loaded = match service.list_loaded_modules() {
                Ok(m) => m,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "list",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to list loaded modules"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LIST_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to list modules: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "list",
                json!({ "loaded_count": loaded.len(), "rules_count": service.store.config.rules.len() }),
                "success",
                None,
                Some("Listed kernel modules"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": {
                        "loaded_modules": loaded,
                        "rules": service.store.config.rules,
                        "autoload_modules": service.store.config.autoload_modules,
                    },
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Loaded Modules ({}):", loaded.len());
                for m in &loaded {
                    println!("  {} ({} bytes, refcount: {}, state: {:?})", sanitize_terminal(&m.name), m.size_bytes, m.ref_count, m.state);
                }
                println!("\nConfigured Rules ({}):", service.store.config.rules.len());
                for r in &service.store.config.rules {
                    println!("  {:?}", r);
                }
                println!("\nAutoload Modules ({}):", service.store.config.autoload_modules.len());
                for m in &service.store.config.autoload_modules {
                    println!("  {}", sanitize_terminal(m));
                }
            }
            0
        }
        Some("show") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'show'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "show",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "show",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let mut service = aiosh_core::kernel_module_service::KernelModuleService::new(store);
            if let Some(proc_p) = proc_path_opt {
                service = service.with_proc_modules_path(std::path::PathBuf::from(proc_p));
            }

            let loaded_mod = match service.get_module(name) {
                Ok(m) => m,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "show",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to inspect module"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SHOW_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to inspect module: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let matching_rules: Vec<_> = service.store.config.rules.iter().filter(|r| match r {
                aiosh_core::kernel_module::ModprobeRule::Blacklist { module } => module == name,
                aiosh_core::kernel_module::ModprobeRule::Options { module, .. } => module == name,
                aiosh_core::kernel_module::ModprobeRule::Alias { alias, module } => alias == name || module == name,
                aiosh_core::kernel_module::ModprobeRule::Install { module, .. } => module == name,
                aiosh_core::kernel_module::ModprobeRule::Remove { module, .. } => module == name,
                aiosh_core::kernel_module::ModprobeRule::Softdep { module, .. } => module == name,
            }).cloned().collect();

            let is_autoload = service.store.config.autoload_modules.iter().any(|m| m == name);

            if loaded_mod.is_none() && matching_rules.is_empty() && !is_autoload {
                let msg = format!("module '{}' not found in loaded modules or configured store", name);
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "show",
                    json!({ "error": &msg }),
                    "failure",
                    Some(name),
                    Some("Module not found"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "MODULE_NOT_FOUND", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "show",
                json!({ "module": name, "loaded": loaded_mod.is_some(), "rules_count": matching_rules.len(), "autoload": is_autoload }),
                "success",
                Some(name),
                Some("Showed module details"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": {
                        "module": loaded_mod,
                        "rules": matching_rules,
                        "autoload": is_autoload,
                    },
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Module: {}", sanitize_terminal(name));
                if let Some(m) = loaded_mod {
                    println!("  Loaded: yes ({} bytes, refcount: {}, state: {:?})", m.size_bytes, m.ref_count, m.state);
                    if !m.used_by.is_empty() {
                        println!("  Used by: {}", sanitize_terminal(&m.used_by.join(", ")));
                    }
                } else {
                    println!("  Loaded: no");
                }
                println!("  Autoload: {}", if is_autoload { "yes" } else { "no" });
                println!("  Configured Rules ({}):", matching_rules.len());
                for r in &matching_rules {
                    println!("    {:?}", r);
                }
            }
            0
        }
        Some("blacklist") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'blacklist'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "blacklist",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "blacklist",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            if let Err(e) = store.add_blacklist(name) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "blacklist",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Blacklist addition failed"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "BLACKLIST_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to blacklist module: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            if let Err(e) = save_store(&store) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "blacklist",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Failed to save store"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to save store: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "blacklist",
                json!({ "module": name, "action": "blacklisted" }),
                "success",
                Some(name),
                Some("Blacklisted kernel module"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "module": name, "blacklisted": true }, "error": serde_json::Value::Null }));
            } else {
                println!("Module '{}' blacklisted successfully.", sanitize_terminal(name));
            }
            0
        }
        Some("unblacklist") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'unblacklist'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unblacklist",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unblacklist",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let removed = store.remove_blacklist(name);
            if removed {
                if let Err(e) = save_store(&store) {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unblacklist",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to save store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to save store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "unblacklist",
                json!({ "module": name, "removed": removed }),
                "success",
                Some(name),
                Some("Unblacklisted kernel module"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "module": name, "removed": removed }, "error": serde_json::Value::Null }));
            } else {
                if removed {
                    println!("Module '{}' removed from blacklist.", sanitize_terminal(name));
                } else {
                    println!("Module '{}' was not blacklisted.", sanitize_terminal(name));
                }
            }
            0
        }
        Some("options") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'options'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "options",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut opts = Vec::new();
            let mut it = rest.iter().skip(1);
            while let Some(arg) = it.next() {
                if arg == "--store" || arg == "--proc-modules" || arg == "--modprobe" || arg == "--autoload" {
                    let _ = it.next();
                } else if arg.starts_with("--") {
                    continue;
                } else {
                    opts.push(arg.clone());
                }
            }
            if opts.is_empty() {
                let msg = "missing option parameter(s) for 'options'";
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "options",
                    json!({ "error": msg }),
                    "failure",
                    Some(name),
                    Some("Missing options"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_OPTIONS", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "options",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            if let Err(e) = store.add_options(name, opts.clone()) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "options",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Options update failed"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "OPTIONS_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to set module options: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            if let Err(e) = save_store(&store) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "options",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Failed to save store"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to save store: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "options",
                json!({ "module": name, "options": opts }),
                "success",
                Some(name),
                Some("Configured module options"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "module": name, "options": opts }, "error": serde_json::Value::Null }));
            } else {
                println!("Options for module '{}' set to: {:?}", sanitize_terminal(name), opts);
            }
            0
        }
        Some("autoload") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'autoload'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "autoload",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "autoload",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            if let Err(e) = store.add_autoload(name) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "autoload",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Autoload addition failed"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "AUTOLOAD_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to add autoload module: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            if let Err(e) = save_store(&store) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "autoload",
                    json!({ "error": &e }),
                    "failure",
                    Some(name),
                    Some("Failed to save store"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to save store: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "autoload",
                json!({ "module": name, "action": "autoloaded" }),
                "success",
                Some(name),
                Some("Added kernel module to autoload"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "module": name, "autoload": true }, "error": serde_json::Value::Null }));
            } else {
                println!("Module '{}' added to autoload list.", sanitize_terminal(name));
            }
            0
        }
        Some("unautoload") => {
            let target_name = rest.first().filter(|s| !s.starts_with("--"));
            let name = match target_name {
                Some(n) => n.as_str(),
                None => {
                    let msg = "missing module name for 'unautoload'";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unautoload",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing module name"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MODULE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unautoload",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let removed = store.remove_autoload(name);
            if removed {
                if let Err(e) = save_store(&store) {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "unautoload",
                        json!({ "error": &e }),
                        "failure",
                        Some(name),
                        Some("Failed to save store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to save store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "unautoload",
                json!({ "module": name, "removed": removed }),
                "success",
                Some(name),
                Some("Removed module from autoload"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "module": name, "removed": removed }, "error": serde_json::Value::Null }));
            } else {
                if removed {
                    println!("Module '{}' removed from autoload list.", sanitize_terminal(name));
                } else {
                    println!("Module '{}' was not in autoload list.", sanitize_terminal(name));
                }
            }
            0
        }
        Some("preset") => {
            let action = rest.first().filter(|s| !s.starts_with("--")).map(|s| s.as_str());
            match action {
                Some("list") => {
                    let store = load_store().unwrap_or_else(|_| aiosh_core::kernel_module_service::KernelModuleStore::new("default", "AIOS Kernel Module Store"));
                    let service = aiosh_core::kernel_module_service::KernelModuleService::new(store);
                    let presets = service.list_presets();

                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "preset-list",
                        json!({ "count": presets.len() }),
                        "success",
                        None,
                        Some("Listed kernel module presets"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", json!({ "code": 0, "data": presets, "error": serde_json::Value::Null }));
                    } else {
                        println!("Available Kernel Module Presets ({}):", presets.len());
                        for p in &presets {
                            println!("  {} — {} ({} rules)", sanitize_terminal(&p.name), sanitize_terminal(&p.description), p.config.rules.len());
                        }
                    }
                    0
                }
                Some("apply") => {
                    let target_preset = rest.get(1).filter(|s| !s.starts_with("--")).map(|s| s.as_str());
                    let preset_name = match target_preset {
                        Some(p) => p,
                        None => {
                            let msg = "missing preset name for 'preset apply'";
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "preset-apply",
                                json!({ "error": msg }),
                                "failure",
                                None,
                                Some("Missing preset name"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_PRESET_NAME", "message": msg } }));
                            } else {
                                eprintln!("{}", msg);
                            }
                            return 2;
                        }
                    };

                    let store = match load_store() {
                        Ok(s) => s,
                        Err(e) => {
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "preset-apply",
                                json!({ "error": &e }),
                                "failure",
                                Some(preset_name),
                                Some("Failed to load store"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                            } else {
                                eprintln!("failed to load store: {}", sanitize_terminal(&e));
                            }
                            return 1;
                        }
                    };

                    let mut service = aiosh_core::kernel_module_service::KernelModuleService::new(store);
                    if let Err(e) = service.apply_preset(preset_name) {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "preset-apply",
                            json!({ "error": &e }),
                            "failure",
                            Some(preset_name),
                            Some("Failed to apply preset"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "PRESET_APPLY_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to apply preset: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }

                    if let Err(e) = save_store(&service.store) {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "preset-apply",
                            json!({ "error": &e }),
                            "failure",
                            Some(preset_name),
                            Some("Failed to save store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to save store: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "preset-apply",
                        json!({ "preset": preset_name, "applied": true }),
                        "success",
                        Some(preset_name),
                        Some("Applied kernel module preset"),
                        "operator",
                        None,
                    );

                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "preset": preset_name, "applied": true }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Preset '{}' applied successfully.", sanitize_terminal(preset_name));
                    }
                    0
                }
                None => {
                    let msg = "missing preset action (expected 'list' or 'apply')";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "preset",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Missing preset action"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_PRESET_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    2
                }
                Some(other) => {
                    let msg = format!("unknown preset action '{}' (expected 'list' or 'apply')", other);
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "preset",
                        json!({ "error": &msg }),
                        "failure",
                        None,
                        Some("Unknown preset action"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_PRESET_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("export") => {
            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "export",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let modprobe_conf = store.export_modprobe_conf();
            let modules_load_conf = store.export_modules_load_conf();

            let modprobe_out = parse_flag(rest, "--modprobe");
            if let Some(ref path_str) = modprobe_out {
                if let Err(e) = std::fs::write(path_str, &modprobe_conf) {
                    let msg = format!("failed to write modprobe file {}: {}", path_str, e);
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "export",
                        json!({ "error": &msg }),
                        "failure",
                        None,
                        Some("Export write error"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "EXPORT_WRITE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            }

            let autoload_out = parse_flag(rest, "--autoload");
            if let Some(ref path_str) = autoload_out {
                if let Err(e) = std::fs::write(path_str, &modules_load_conf) {
                    let msg = format!("failed to write autoload file {}: {}", path_str, e);
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "export",
                        json!({ "error": &msg }),
                        "failure",
                        None,
                        Some("Export write error"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "EXPORT_WRITE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "export",
                json!({ "modprobe_lines": modprobe_conf.lines().count(), "autoload_lines": modules_load_conf.lines().count() }),
                "success",
                None,
                Some("Exported kernel module configuration"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": {
                        "modprobe_conf": modprobe_conf,
                        "modules_load_conf": modules_load_conf,
                    },
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("# === /etc/modprobe.d/aios.conf ===\n{}", modprobe_conf);
                println!("# === /etc/modules-load.d/aios.conf ===\n{}", modules_load_conf);
            }
            0
        }
        Some("import") => {
            let modprobe_in = parse_flag(rest, "--modprobe");
            let autoload_in = parse_flag(rest, "--autoload");

            if modprobe_in.is_none() && autoload_in.is_none() {
                let msg = "missing source file for 'import' (specify --modprobe <path> or --autoload <path>)";
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "import",
                    json!({ "error": msg }),
                    "failure",
                    None,
                    Some("Missing import source"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_IMPORT_SOURCE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let mut store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "import",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let mut modprobe_count = 0;
            if let Some(ref path_str) = modprobe_in {
                match aiosh_core::kernel_module_config::import_modprobe_file_to_store(&mut store, std::path::Path::new(path_str)) {
                    Ok(c) => modprobe_count = c,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "import",
                            json!({ "error": &e }),
                            "failure",
                            None,
                            Some("Modprobe import error"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "IMPORT_MODPROBE_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to import modprobe: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }
                }
            }

            let mut autoload_count = 0;
            if let Some(ref path_str) = autoload_in {
                match aiosh_core::kernel_module_config::import_modules_load_file_to_store(&mut store, std::path::Path::new(path_str)) {
                    Ok(c) => autoload_count = c,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "import",
                            json!({ "error": &e }),
                            "failure",
                            None,
                            Some("Autoload import error"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "IMPORT_AUTOLOAD_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to import autoload: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }
                }
            }

            if let Err(e) = save_store(&store) {
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "import",
                    json!({ "error": &e }),
                    "failure",
                    None,
                    Some("Failed to save store"),
                    "operator",
                    None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_STORE_FAILED", "message": e } }));
                } else {
                    eprintln!("failed to save store: {}", sanitize_terminal(&e));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "import",
                json!({ "modprobe_imported": modprobe_count, "autoload_imported": autoload_count }),
                "success",
                None,
                Some("Imported kernel module configuration"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": {
                        "modprobe_imported": modprobe_count,
                        "autoload_imported": autoload_count,
                    },
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Imported {} modprobe rule(s) and {} autoload module(s).", modprobe_count, autoload_count);
            }
            0
        }
        Some("policy") => {
            let policy_path_opt = parse_flag(rest, "--policy").or_else(|| parse_flag(rest, "--config"));
            if let Some(ref p) = policy_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "policy path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "policy",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid policy path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            }

            let policy = match aiosh_core::kernel_module_policy::KernelModuleSecurityPolicy::resolve(policy_path_opt.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "policy",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to resolve kernel module security policy"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to resolve policy: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let evaluate_store_flag = rest.iter().any(|s| s == "--evaluate-store");
            let target_module = parse_flag(rest, "--module").or_else(|| {
                rest.first().filter(|s| !s.starts_with("--")).cloned()
            });

            if evaluate_store_flag {
                let store = match load_store() {
                    Ok(s) => s,
                    Err(e) => {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "policy",
                            json!({ "error": &e }),
                            "failure",
                            None,
                            Some("Failed to load store"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                        } else {
                            eprintln!("failed to load store: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }
                };

                let verdicts = policy.evaluate_store(&store);
                let all_allowed = verdicts.iter().all(|v| v.allowed);
                let violation_count: usize = verdicts.iter().map(|v| v.violations.len()).sum();

                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "policy",
                    json!({ "evaluated": "store", "allowed": all_allowed, "verdicts": verdicts.len(), "violations": violation_count }),
                    if all_allowed { "success" } else { "failure" },
                    None,
                    Some("Evaluated kernel module store against policy"),
                    "operator",
                    None,
                );

                if is_json {
                    println!("{}", json!({
                        "code": if all_allowed { 0 } else { 1 },
                        "data": {
                            "allowed": all_allowed,
                            "mode": policy.mode,
                            "verdicts": verdicts,
                        },
                        "error": serde_json::Value::Null
                    }));
                } else {
                    println!("Kernel Module Store Policy Evaluation:");
                    println!("  Mode:       {:?}", policy.mode);
                    println!("  Allowed:    {}", all_allowed);
                    println!("  Verdicts:   {}", verdicts.len());
                    println!("  Violations: {}", violation_count);
                    for v in &verdicts {
                        if !v.violations.is_empty() {
                            println!("  Module '{}' (allowed: {}):", sanitize_terminal(&v.module_name), v.allowed);
                            for viol in &v.violations {
                                println!("    [{}] {}: {}", if viol.fatal { "FATAL" } else { "WARN" }, viol.rule_id, sanitize_terminal(&viol.description));
                            }
                        }
                    }
                }
                return if all_allowed { 0 } else { 1 };
            }

            if let Some(ref mod_name) = target_module {
                let verdict = policy.evaluate_autoload(mod_name);
                classify_and_emit(
                    &mut ctx,
                    "kernel_module",
                    "policy",
                    json!({ "module": mod_name, "allowed": verdict.allowed, "violations": verdict.violations.len() }),
                    if verdict.allowed { "success" } else { "failure" },
                    Some(mod_name),
                    Some("Evaluated kernel module against policy"),
                    "operator",
                    None,
                );

                if is_json {
                    println!("{}", json!({
                        "code": if verdict.allowed { 0 } else { 1 },
                        "data": verdict,
                        "error": serde_json::Value::Null
                    }));
                } else {
                    println!("Policy Evaluation for Module '{}':", sanitize_terminal(mod_name));
                    println!("  Allowed:    {}", verdict.allowed);
                    println!("  Mode:       {:?}", verdict.mode);
                    println!("  Violations: {}", verdict.violations.len());
                    for viol in &verdict.violations {
                        println!("    [{}] {}: {}", if viol.fatal { "FATAL" } else { "WARN" }, viol.rule_id, sanitize_terminal(&viol.description));
                    }
                }
                return if verdict.allowed { 0 } else { 1 };
            }

            // Default: inspect policy
            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "policy",
                json!({
                    "mode": format!("{:?}", policy.mode),
                    "prohibited_modules": policy.prohibited_modules.len(),
                    "protected_modules": policy.protected_modules.len(),
                }),
                "success",
                None,
                Some("Inspected kernel module security policy"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": policy,
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Kernel Module Security Policy:");
                println!("  Mode:                      {:?}", policy.mode);
                println!("  Prohibited Modules:        {}", policy.prohibited_modules.len());
                println!("  Protected Modules:         {}", policy.protected_modules.len());
                println!("  Allowed Install Commands:  {}", policy.allowed_install_commands.len());
                println!("  Disallowed Parameter Keys: {}", policy.disallowed_parameter_keys.len());
                println!("  Max Parameter Value Len:   {}", policy.max_parameter_value_len);
            }
            0
        }
        Some("observability") | Some("status") => {
            let policy_path_opt = parse_flag(rest, "--policy").or_else(|| parse_flag(rest, "--config"));
            if let Some(ref p) = policy_path_opt {
                if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                    let msg = "policy path cannot exceed 1024 characters and cannot contain control characters";
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "observability",
                        json!({ "error": msg }),
                        "failure",
                        None,
                        Some("Invalid policy path"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            }

            let policy = match aiosh_core::kernel_module_policy::KernelModuleSecurityPolicy::resolve(policy_path_opt.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "observability",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to resolve policy"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_RESOLUTION_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to resolve policy: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let store = match load_store() {
                Ok(s) => s,
                Err(e) => {
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "observability",
                        json!({ "error": &e }),
                        "failure",
                        None,
                        Some("Failed to load store"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_STORE_FAILED", "message": e } }));
                    } else {
                        eprintln!("failed to load store: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let mut service = aiosh_core::kernel_module_service::KernelModuleService::new(store);
            if let Some(proc_p) = proc_path_opt {
                service = service.with_proc_modules_path(std::path::PathBuf::from(proc_p));
            }

            let report = aiosh_core::kernel_module_observability::KernelModuleObservabilityReport::generate(
                &service,
                Some(&policy),
            );

            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "observability",
                json!({
                    "loaded_modules": report.total_loaded_modules,
                    "memory_bytes": report.total_memory_bytes,
                    "store_rules": report.store_rules_count,
                    "autoload_modules": report.autoload_modules_count,
                    "compliant": report.policy_compliant_count,
                    "violations": report.policy_violations_count,
                }),
                "success",
                None,
                Some("Generated kernel module observability report"),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": report,
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Kernel Module Observability Report:");
                println!("  Loaded Modules:     {}", report.total_loaded_modules);
                println!("  Memory Footprint:   {} bytes", report.total_memory_bytes);
                println!("  Store Rules:        {}", report.store_rules_count);
                println!("  Autoload Modules:   {}", report.autoload_modules_count);
                println!("  Policy Compliant:   {}", report.policy_compliant_count);
                println!("  Policy Violations:  {}", report.policy_violations_count);
                if !report.prohibited_modules_configured.is_empty() {
                    println!("  Prohibited Active:  {:?}", report.prohibited_modules_configured);
                }
                if !report.protected_modules_configured.is_empty() {
                    println!("  Protected Tracked:  {:?}", report.protected_modules_configured);
                }
            }
            0
        }
        Some("doc") => {
            let positional: Vec<&str> = rest.iter().filter(|s| !s.starts_with("--")).map(|s| s.as_str()).collect();
            let doc_action = positional.first().copied();
            let index = aiosh_core::kernel_module_doc::KernelModuleDocIndex::new();

            match doc_action {
                Some("get") | Some("show") => {
                    let topic_id = match positional.get(1).copied() {
                        Some(id) => id,
                        None => {
                            let msg = "missing topic ID (usage: aiosh mod doc get <topic_id>)";
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "doc",
                                json!({ "error": msg }),
                                "failure",
                                None,
                                Some("Missing topic ID"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_TOPIC_ID", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };

                    match index.get_topic(topic_id) {
                        Some(topic) => {
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "doc",
                                json!({ "topic": topic_id, "found": true }),
                                "success",
                                Some(topic_id),
                                Some("Retrieved kernel module documentation topic"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": topic, "error": serde_json::Value::Null }));
                            } else {
                                println!("{}", aiosh_core::kernel_module_doc::KernelModuleDocIndex::format_topic_markdown(topic));
                            }
                            0
                        }
                        None => {
                            let msg = format!("topic '{}' not found in documentation index", topic_id);
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "doc",
                                json!({ "topic": topic_id, "found": false, "error": &msg }),
                                "failure",
                                Some(topic_id),
                                Some("Topic not found"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "TOPIC_NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                Some("search") | Some("find") => {
                    let query = match positional.get(1).copied() {
                        Some(q) => q,
                        None => {
                            let msg = "missing search query (usage: aiosh mod doc search <query>)";
                            classify_and_emit(
                                &mut ctx,
                                "kernel_module",
                                "doc",
                                json!({ "error": msg }),
                                "failure",
                                None,
                                Some("Missing search query"),
                                "operator",
                                None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_QUERY", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };

                    let results = index.search(query);
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "doc",
                        json!({ "query": query, "matches": results.len() }),
                        "success",
                        None,
                        Some("Searched kernel module documentation index"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": results, "error": serde_json::Value::Null }));
                    } else {
                        println!("Search Results for '{}' ({} match(es)):", sanitize_terminal(query), results.len());
                        for r in &results {
                            println!("  [{}] {} (score: {})", r.topic_id, r.title, r.score);
                            if !r.matched_tags.is_empty() {
                                println!("    Tags: {}", r.matched_tags.join(", "));
                            }
                            if !r.snippet.is_empty() {
                                println!("    Snippet: {}", sanitize_terminal(&r.snippet));
                            }
                        }
                    }
                    0
                }
                Some("list") | None => {
                    let topics = index.list_topics();
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        "doc",
                        json!({ "topics_count": topics.len() }),
                        "success",
                        None,
                        Some("Listed kernel module documentation topics"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": topics, "error": serde_json::Value::Null }));
                    } else {
                        println!("Kernel Module Documentation Topics ({} total):", topics.len());
                        for t in topics {
                            println!("  `{}`: {} [{}]", t.id, t.title, t.category.as_str());
                            println!("    {}", sanitize_terminal(&t.summary));
                        }
                    }
                    0
                }
                Some(other) => {
                    // Check if directly passed a topic ID
                    if let Some(topic) = index.get_topic(other) {
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "doc",
                            json!({ "topic": other, "found": true }),
                            "success",
                            Some(other),
                            Some("Retrieved kernel module documentation topic"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 0, "data": topic, "error": serde_json::Value::Null }));
                        } else {
                            println!("{}", aiosh_core::kernel_module_doc::KernelModuleDocIndex::format_topic_markdown(topic));
                        }
                        0
                    } else {
                        let msg = format!("unknown doc action or topic '{}' (expected 'list', 'get', 'search', or valid topic ID)", other);
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "doc",
                            json!({ "error": &msg }),
                            "failure",
                            Some(other),
                            Some("Unknown doc action"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(&msg));
                        }
                        2
                    }
                }
            }
        }
        Some("check") => {
            let auto_recover = has_flag(rest, "--auto-recover") || has_flag(rest, "--recover");
            let store_arg = parse_flag(rest, "--store");
            let resolved_store = match store_arg {
                Some(ref p) => {
                    if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                        let msg = "store path cannot exceed 1024 characters and cannot contain control characters";
                        classify_and_emit(
                            &mut ctx,
                            "kernel_module",
                            "check",
                            json!({ "error": msg }),
                            "failure",
                            None,
                            Some("Invalid store path"),
                            "operator",
                            None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(msg));
                        }
                        return 2;
                    }
                    p.clone()
                }
                None => resolved_store_path.clone(),
            };

            let path = std::path::Path::new(&resolved_store);
            let report_res = if auto_recover {
                aiosh_core::kernel_module_recovery::recover_store_file(path)
            } else {
                aiosh_core::kernel_module_recovery::check_store_file(path)
            };

            let report = match report_res {
                Ok(r) => r,
                Err(e) => {
                    let action_name = if auto_recover { "recover" } else { "check" };
                    classify_and_emit(
                        &mut ctx,
                        "kernel_module",
                        action_name,
                        json!({ "error": &e, "store_path": resolved_store }),
                        "failure",
                        None,
                        Some("Store check/recovery execution failure"),
                        "operator",
                        None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CHECK_FAILED", "message": e } }));
                    } else {
                        eprintln!("store check failed: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let status_str = if report.healthy { "success" } else { "failure" };
            let action_name = if auto_recover { "recover" } else { "check" };
            classify_and_emit(
                &mut ctx,
                "kernel_module",
                action_name,
                json!({
                    "healthy": report.healthy,
                    "recovered": report.recovered,
                    "store_path": report.store_path,
                    "total_rules": report.total_rules,
                    "valid_rules": report.valid_rules,
                    "invalid_rules": report.invalid_rules,
                    "total_autoload": report.total_autoload,
                    "valid_autoload": report.valid_autoload,
                    "invalid_autoload": report.invalid_autoload,
                    "errors_count": report.errors.len(),
                    "backup_path": report.backup_path,
                }),
                status_str,
                None,
                Some(if auto_recover { "Kernel module store recovery" } else { "Kernel module store integrity check" }),
                "operator",
                None,
            );

            if is_json {
                let code = if report.healthy { 0 } else { 1 };
                let err_val = if report.healthy {
                    serde_json::Value::Null
                } else {
                    json!({
                        "code": if report.recovered { "STORE_RECOVERED_WITH_ISSUES" } else { "STORE_INTEGRITY_VIOLATION" },
                        "message": report.errors.join("; ")
                    })
                };
                println!("{}", json!({
                    "code": code,
                    "data": report,
                    "error": err_val
                }));
            } else {
                println!("Kernel Module Store Integrity Report:");
                println!("  Store: {}", sanitize_terminal(&report.store_path));
                println!("  Status: {}", if report.healthy { "HEALTHY" } else { "UNHEALTHY" });
                println!("  Rules: {} total ({} valid, {} invalid)", report.total_rules, report.valid_rules, report.invalid_rules);
                println!("  Autoload: {} total ({} valid, {} invalid)", report.total_autoload, report.valid_autoload, report.invalid_autoload);
                println!("  Auto-recovered: {}", if report.recovered { "yes" } else { "no" });
                if let Some(ref bp) = report.backup_path {
                    println!("  Quarantine Backup: {}", sanitize_terminal(bp));
                }
                if !report.errors.is_empty() {
                    println!("  Integrity Errors ({}):", report.errors.len());
                    for err in &report.errors {
                        println!("    - {}", sanitize_terminal(err));
                    }
                }
            }

            if report.healthy { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh mod — Kernel Module Management\n\nUsage:\n  aiosh mod list [--store <path>] [--proc-modules <path>] [--json]\n  aiosh mod show <name> [--store <path>] [--proc-modules <path>] [--json]\n  aiosh mod blacklist <module> [--store <path>] [--json]\n  aiosh mod unblacklist <module> [--store <path>] [--json]\n  aiosh mod options <module> <k=v...> [--store <path>] [--json]\n  aiosh mod autoload <module> [--store <path>] [--json]\n  aiosh mod unautoload <module> [--store <path>] [--json]\n  aiosh mod preset list [--json]\n  aiosh mod preset apply <preset_name> [--store <path>] [--json]\n  aiosh mod export [--store <path>] [--modprobe <path>] [--autoload <path>] [--json]\n  aiosh mod import [--store <path>] [--modprobe <path>] [--autoload <path>] [--json]\n  aiosh mod policy [--policy <path>] [--evaluate-store] [--module <name>] [--json]\n  aiosh mod observability [--store <path>] [--proc-modules <path>] [--policy <path>] [--json]\n  aiosh mod doc [list|get <topic>|search <query>] [--json]\n  aiosh mod check [--store <path>] [--auto-recover] [--json]");
            0
        }
        Some(other) => {
            let msg = format!("unknown mod subcommand: {}", other);
            classify_and_emit(
                &mut ctx,
                "kernel_module",
                "unknown",
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Unknown kernel module subcommand"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_hardware(args: &[String]) -> i32 {
    use aiosh_core::{
        validate_hardware_inventory, DeviceClass, HardwareInventory, HardwareScanOptions,
        HardwareService,
    };

    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    // Path hygiene checks
    let sysfs_opt = parse_flag(rest, "--sysfs");
    if let Some(ref p) = sysfs_opt {
        if p.len() > 1024 {
            let msg = "sysfs path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "sysfs path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let procfs_opt = parse_flag(rest, "--procfs");
    if let Some(ref p) = procfs_opt {
        if p.len() > 1024 {
            let msg = "procfs path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "procfs path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let file_opt = parse_flag(rest, "--file");
    if let Some(ref p) = file_opt {
        if p.len() > 1024 {
            let msg = "file path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "file path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    // Parse class filter
    let class_filter = if let Some(cls_str) = parse_flag(rest, "--class") {
        match cls_str.to_ascii_lowercase().as_str() {
            "cpu" => Some(vec![DeviceClass::Cpu]),
            "gpu" => Some(vec![DeviceClass::Gpu]),
            "block" => Some(vec![DeviceClass::Block]),
            "network" | "net" => Some(vec![DeviceClass::Network]),
            "usb" => Some(vec![DeviceClass::Usb]),
            "pci" => Some(vec![DeviceClass::Pci]),
            "system" | "dmi" => Some(vec![DeviceClass::System]),
            "memory" | "ram" => Some(vec![DeviceClass::Memory]),
            "other" => Some(vec![DeviceClass::Other]),
            other => {
                let msg = format!("unrecognized device class: {}", other);
                classify_and_emit(
                    &mut ctx, "hardware", sub.unwrap_or("unknown"), json!({ "error": &msg }),
                    "failure", None, Some("Invalid device class"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_DEVICE_CLASS", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }
        }
    } else {
        None
    };

    let include_attrs = !has_flag(rest, "--no-attrs") && !has_flag(rest, "--no-attributes");
    let options = HardwareScanOptions {
        classes: class_filter,
        include_attributes: include_attrs,
    };

    // Instantiate service
    let service = match (&sysfs_opt, &procfs_opt) {
        (Some(s), Some(p)) => HardwareService::with_roots(s, p),
        (Some(s), None) => HardwareService::with_roots(s, "/proc"),
        (None, Some(p)) => HardwareService::with_roots("/sys", p),
        (None, None) => HardwareService::new(),
    };

    match sub {
        Some("scan") => {
            match service.scan(&options) {
                Ok(inv) => {
                    classify_and_emit(
                        &mut ctx, "hardware", "scan",
                        json!({ "devices_found": inv.devices.len(), "summary": &inv.summary }),
                        "success", None, Some("Scanned hardware inventory"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": inv, "error": serde_json::Value::Null }));
                    } else {
                        println!("Hardware scan complete ({} devices found):", inv.devices.len());
                        for (c, count) in &inv.summary {
                            println!("  {:10}: {}", sanitize_terminal(c), count);
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("hardware scan failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "hardware", "scan", json!({ "error": &msg }),
                        "failure", None, Some("Scan failure"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SCAN_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("list") => {
            match service.scan(&options) {
                Ok(inv) => {
                    classify_and_emit(
                        &mut ctx, "hardware", "list",
                        json!({ "devices_count": inv.devices.len() }),
                        "success", None, Some("Listed hardware devices"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "devices": inv.devices, "count": inv.devices.len() }, "error": serde_json::Value::Null }));
                    } else {
                        println!("{:<24} {:<10} {:<8} {:<16} {}", "ID", "CLASS", "BUS", "DRIVER", "NAME");
                        println!("{}", "-".repeat(80));
                        for d in &inv.devices {
                            let driver = d.driver.as_deref().unwrap_or("-");
                            println!("{:<24} {:<10?} {:<8?} {:<16} {}",
                                sanitize_terminal(&d.id),
                                d.class,
                                d.bus,
                                sanitize_terminal(driver),
                                sanitize_terminal(&d.name)
                            );
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("hardware list failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "hardware", "list", json!({ "error": &msg }),
                        "failure", None, Some("List failure"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LIST_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("show") => {
            let target_id_opt = rest.iter().find(|a| !a.starts_with("--"));
            let target_id = match target_id_opt {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => {
                    let msg = "missing required device ID for show";
                    classify_and_emit(
                        &mut ctx, "hardware", "show", json!({ "error": msg }),
                        "failure", None, Some("Missing device ID"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_DEVICE_ID", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if target_id.len() > 256 {
                let msg = "device ID cannot exceed 256 characters";
                classify_and_emit(
                    &mut ctx, "hardware", "show", json!({ "error": msg }),
                    "failure", None, Some("Device ID too long"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "DEVICE_ID_TOO_LONG", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            if target_id.chars().any(|c| c.is_control()) {
                let msg = "device ID cannot contain control characters";
                classify_and_emit(
                    &mut ctx, "hardware", "show", json!({ "error": msg }),
                    "failure", None, Some("Device ID contains control character"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "DEVICE_ID_CONTAINS_CONTROL_CHAR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            match service.scan(&HardwareScanOptions::default()) {
                Ok(inv) => {
                    if let Some(dev) = inv.devices.iter().find(|d| &d.id == target_id) {
                        classify_and_emit(
                            &mut ctx, "hardware", "show",
                            json!({ "device_id": target_id, "found": true }),
                            "success", Some(target_id), Some("Found hardware device"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 0, "data": { "device": dev }, "error": serde_json::Value::Null }));
                        } else {
                            println!("Device: {}", sanitize_terminal(&dev.name));
                            println!("  ID:          {}", sanitize_terminal(&dev.id));
                            println!("  Class:       {:?}", dev.class);
                            println!("  Bus:         {:?}", dev.bus);
                            if let Some(ref vid) = dev.vendor_id { println!("  Vendor ID:   {}", sanitize_terminal(vid)); }
                            if let Some(ref did) = dev.device_id { println!("  Device ID:   {}", sanitize_terminal(did)); }
                            if let Some(ref vn) = dev.vendor_name { println!("  Vendor Name: {}", sanitize_terminal(vn)); }
                            if let Some(ref drv) = dev.driver { println!("  Driver:      {}", sanitize_terminal(drv)); }
                            if let Some(ref p) = dev.sysfs_path { println!("  Sysfs:       {}", sanitize_terminal(p)); }
                            if let Some(ref p) = dev.dev_path { println!("  Dev Path:    {}", sanitize_terminal(p)); }
                            if !dev.attributes.is_empty() {
                                println!("  Attributes:");
                                for (k, v) in &dev.attributes {
                                    println!("    {}: {}", sanitize_terminal(k), sanitize_terminal(v));
                                }
                            }
                        }
                        0
                    } else {
                        let msg = format!("device not found: {}", target_id);
                        classify_and_emit(
                            &mut ctx, "hardware", "show", json!({ "device_id": target_id, "found": false }),
                            "failure", Some(target_id), Some("Device not found"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "DEVICE_NOT_FOUND", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(&msg));
                        }
                        1
                    }
                }
                Err(e) => {
                    let msg = format!("hardware show scan failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "hardware", "show", json!({ "error": &msg }),
                        "failure", Some(target_id), Some("Scan failure"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SCAN_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("summary") => {
            match service.scan(&options) {
                Ok(inv) => {
                    let total = inv.devices.len();
                    classify_and_emit(
                        &mut ctx, "hardware", "summary",
                        json!({ "total": total, "summary": &inv.summary }),
                        "success", None, Some("Summarized hardware inventory"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "summary": inv.summary, "total": total }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Hardware Summary (Total: {} devices):", total);
                        for (c, count) in &inv.summary {
                            println!("  {:10}: {}", sanitize_terminal(c), count);
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("hardware summary failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "hardware", "summary", json!({ "error": &msg }),
                        "failure", None, Some("Summary failure"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SUMMARY_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("verify") => {
            let inv_res = if let Some(ref path_str) = file_opt {
                let file_path = std::path::Path::new(path_str);
                if !file_path.exists() || !file_path.is_file() {
                    Err(format!("file not found or not regular file: {}", path_str))
                } else {
                    match file_path.metadata() {
                        Ok(meta) => {
                            if meta.len() > 10 * 1024 * 1024 {
                                Err(format!("file exceeds 10MB limit: {} bytes", meta.len()))
                            } else {
                                match std::fs::read_to_string(file_path) {
                                    Ok(content) => HardwareInventory::from_json(&content),
                                    Err(e) => Err(e.to_string()),
                                }
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            } else {
                service.scan(&options)
            };

            match inv_res {
                Ok(inv) => {
                    match validate_hardware_inventory(&inv) {
                        Ok(()) => {
                            classify_and_emit(
                                &mut ctx, "hardware", "verify",
                                json!({ "valid": true, "device_count": inv.devices.len() }),
                                "success", None, Some("Hardware inventory verification passed"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": { "valid": true, "device_count": inv.devices.len() }, "error": serde_json::Value::Null }));
                            } else {
                                println!("Hardware inventory verification PASSED ({} devices valid).", inv.devices.len());
                            }
                            0
                        }
                        Err(e) => {
                            let msg = format!("hardware inventory invariants violated: {}", e);
                            classify_and_emit(
                                &mut ctx, "hardware", "verify", json!({ "valid": false, "error": &msg }),
                                "failure", None, Some("Verification invariants failure"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_FAILED", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("hardware verification failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "hardware", "verify", json!({ "error": &msg }),
                        "failure", None, Some("Verification read failure"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "VERIFICATION_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("Usage: aiosh hw <scan|list|show|summary|verify> [OPTIONS]\n\nSubcommands:\n  scan     Discover host hardware across subsystems\n  list     List discovered hardware devices\n  show     Show details for a specific device ID\n  summary  Show hardware inventory count summary\n  verify   Validate inventory against invariants HD1..HD5\n\nOptions:\n  --class <name>  Filter by device class (cpu, gpu, block, network, usb, pci, system)\n  --no-attrs      Omit extended attributes\n  --sysfs <path>  Custom sysfs root path\n  --procfs <path> Custom procfs root path\n  --file <path>   Inventory JSON file for verify\n  --json          Output standard JSON envelope");
            0
        }
        Some(other) => {
            let msg = format!("unknown hardware subcommand: {}", other);
            classify_and_emit(
                &mut ctx,
                "hardware",
                other,
                json!({ "error": &msg }),
                "failure",
                None,
                Some("Unknown subcommand"),
                "operator",
                None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_network(args: &[String]) -> i32 {
    use aiosh_core::network::validate_interface_name;
    use aiosh_core::network_service::NetworkService;

    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    // Path hygiene checks
    let sysfs_opt = parse_flag(rest, "--sysfs");
    if let Some(ref p) = sysfs_opt {
        if p.len() > 1024 {
            let msg = "sysfs path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "sysfs path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let procfs_opt = parse_flag(rest, "--procfs");
    if let Some(ref p) = procfs_opt {
        if p.len() > 1024 {
            let msg = "procfs path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "procfs path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let resolv_opt = parse_flag(rest, "--resolv");
    if let Some(ref p) = resolv_opt {
        if p.len() > 1024 {
            let msg = "resolv path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "resolv path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "network", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let sysfs_path = sysfs_opt.unwrap_or_else(|| "/sys/class/net".to_string());
    let procfs_path = procfs_opt.unwrap_or_else(|| "/proc/net".to_string());
    let resolv_path = resolv_opt.unwrap_or_else(|| "/etc/resolv.conf".to_string());

    let service = NetworkService::with_paths(sysfs_path, procfs_path, resolv_path);

    match sub {
        Some("list") => {
            match service.scan_interfaces() {
                Ok(ifaces) => {
                    let count = ifaces.len();
                    classify_and_emit(
                        &mut ctx, "network", "list", json!({ "count": count }),
                        "success", None, Some("Listed network interfaces"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "interfaces": ifaces, "count": count }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Network Interfaces ({} discovered):", count);
                        for i in ifaces {
                            println!(
                                "  {:10} {:10} {:8} MTU:{:5} MAC:{}",
                                sanitize_terminal(&i.name),
                                i.iftype.as_str(),
                                i.operstate.as_str(),
                                i.mtu,
                                i.mac_address.as_deref().unwrap_or("none")
                            );
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to list network interfaces: {}", e);
                    classify_and_emit(
                        &mut ctx, "network", "list", json!({ "error": &msg }),
                        "failure", None, Some("List failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LIST_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("show") => {
            let target_name = rest.iter().find(|arg| !arg.starts_with('-')).map(|s| s.as_str());
            let name = match target_name {
                Some(n) if !n.trim().is_empty() => n.trim(),
                _ => {
                    let msg = "interface name is required for 'show'";
                    classify_and_emit(
                        &mut ctx, "network", "show", json!({ "error": msg }),
                        "failure", None, Some(msg), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_INTERFACE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if let Err(e) = validate_interface_name(name) {
                let msg = format!("invalid interface name '{}': {}", name, e);
                classify_and_emit(
                    &mut ctx, "network", "show", json!({ "error": &msg }),
                    "failure", Some(name), Some("Invalid interface name"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_INTERFACE_NAME", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }

            match service.get_interface(name) {
                Ok(Some(iface)) => {
                    classify_and_emit(
                        &mut ctx, "network", "show", json!({ "interface": &iface }),
                        "success", Some(name), Some("Show interface"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "interface": iface }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Interface: {}", sanitize_terminal(&iface.name));
                        println!("  Type:      {}", iface.iftype.as_str());
                        println!("  State:     {}", iface.operstate.as_str());
                        println!("  MAC:       {}", iface.mac_address.as_deref().unwrap_or("none"));
                        println!("  MTU:       {}", iface.mtu);
                        println!("  Flags:     {}", iface.flags.join(", "));
                    }
                    0
                }
                Ok(None) => {
                    let msg = format!("interface '{}' not found", name);
                    classify_and_emit(
                        &mut ctx, "network", "show", json!({ "error": &msg }),
                        "failure", Some(name), Some("Interface not found"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "INTERFACE_NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
                Err(e) => {
                    let msg = format!("failed to show interface '{}': {}", name, e);
                    classify_and_emit(
                        &mut ctx, "network", "show", json!({ "error": &msg }),
                        "failure", Some(name), Some("Show failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SHOW_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("routes") => {
            match service.scan_routes() {
                Ok(routes) => {
                    let count = routes.len();
                    classify_and_emit(
                        &mut ctx, "network", "routes", json!({ "count": count }),
                        "success", None, Some("Listed routes"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "routes": routes, "count": count }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Routing Table ({} routes):", count);
                        for r in routes {
                            println!(
                                "  {:18} via {:15} dev {:8} metric {}",
                                sanitize_terminal(&r.destination),
                                r.gateway.as_deref().unwrap_or("direct"),
                                r.interface.as_deref().unwrap_or("none"),
                                r.metric
                            );
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to scan routes: {}", e);
                    classify_and_emit(
                        &mut ctx, "network", "routes", json!({ "error": &msg }),
                        "failure", None, Some("Routes scan failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ROUTES_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("dns") => {
            match service.get_dns_config() {
                Ok(dns) => {
                    classify_and_emit(
                        &mut ctx, "network", "dns", json!({ "dns": &dns }),
                        "success", None, Some("Queried DNS config"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "dns": dns }, "error": serde_json::Value::Null }));
                    } else {
                        println!("DNS Configuration:");
                        println!("  Nameservers:    {}", if dns.nameservers.is_empty() { "none".into() } else { dns.nameservers.join(", ") });
                        println!("  Search Domains: {}", if dns.search_domains.is_empty() { "none".into() } else { dns.search_domains.join(", ") });
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to get DNS config: {}", e);
                    classify_and_emit(
                        &mut ctx, "network", "dns", json!({ "error": &msg }),
                        "failure", None, Some("DNS query failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "DNS_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("state") => {
            match service.get_network_state() {
                Ok(state) => {
                    classify_and_emit(
                        &mut ctx, "network", "state", json!({ "hostname": &state.hostname }),
                        "success", None, Some("Retrieved network state"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "state": state }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Network State (Host: {}):", sanitize_terminal(&state.hostname));
                        println!("  Interfaces: {}", state.interfaces.len());
                        println!("  Routes:     {}", state.routes.len());
                        println!("  DNS:        {} servers", state.dns.nameservers.len());
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to get network state: {}", e);
                    classify_and_emit(
                        &mut ctx, "network", "state", json!({ "error": &msg }),
                        "failure", None, Some("Network state failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STATE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("up") => {
            let target_name = rest.iter().find(|arg| !arg.starts_with('-')).map(|s| s.as_str());
            let name = match target_name {
                Some(n) if !n.trim().is_empty() => n.trim(),
                _ => {
                    let msg = "interface name is required for 'up'";
                    classify_and_emit(
                        &mut ctx, "network", "up", json!({ "error": msg }),
                        "failure", None, Some(msg), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_INTERFACE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if let Err(e) = validate_interface_name(name) {
                let msg = format!("invalid interface name '{}': {}", name, e);
                classify_and_emit(
                    &mut ctx, "network", "up", json!({ "error": &msg }),
                    "failure", Some(name), Some("Invalid interface name"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_INTERFACE_NAME", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }

            match service.bring_up(name) {
                Ok(()) => {
                    classify_and_emit(
                        &mut ctx, "network", "up", json!({ "interface": name }),
                        "success", Some(name), Some("Brought interface up"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "interface": name, "status": "up" }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Interface '{}' brought up", sanitize_terminal(name));
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to bring up interface '{}': {}", name, e);
                    classify_and_emit(
                        &mut ctx, "network", "up", json!({ "error": &msg }),
                        "failure", Some(name), Some("Bring up failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "OPERATION_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("down") => {
            let target_name = rest.iter().find(|arg| !arg.starts_with('-')).map(|s| s.as_str());
            let name = match target_name {
                Some(n) if !n.trim().is_empty() => n.trim(),
                _ => {
                    let msg = "interface name is required for 'down'";
                    classify_and_emit(
                        &mut ctx, "network", "down", json!({ "error": msg }),
                        "failure", None, Some(msg), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_INTERFACE_NAME", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if let Err(e) = validate_interface_name(name) {
                let msg = format!("invalid interface name '{}': {}", name, e);
                classify_and_emit(
                    &mut ctx, "network", "down", json!({ "error": &msg }),
                    "failure", Some(name), Some("Invalid interface name"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_INTERFACE_NAME", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }

            match service.bring_down(name) {
                Ok(()) => {
                    classify_and_emit(
                        &mut ctx, "network", "down", json!({ "interface": name }),
                        "success", Some(name), Some("Brought interface down"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "interface": name, "status": "down" }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Interface '{}' brought down", sanitize_terminal(name));
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to bring down interface '{}': {}", name, e);
                    classify_and_emit(
                        &mut ctx, "network", "down", json!({ "error": &msg }),
                        "failure", Some(name), Some("Bring down failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "OPERATION_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("Usage: aiosh net <list|show|routes|dns|state|up|down> [OPTIONS]\n\nSubcommands:\n  list     List discovered network interfaces\n  show     Show details for a specific interface\n  routes   Display IPv4 routing table\n  dns      Display DNS nameservers and search domains\n  state    Output complete host network state snapshot\n  up       Bring interface up\n  down     Bring interface down\n\nOptions:\n  --sysfs <path>   Custom sysfs root path\n  --procfs <path>  Custom procfs root path\n  --resolv <path>  Custom resolv.conf file path\n  --json           Output standard JSON envelope");
            0
        }
        Some(other) => {
            let msg = format!("unknown network subcommand: {}", other);
            classify_and_emit(
                &mut ctx, "network", other, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

#[cfg(test)]

mod task_cli_tests {
    use super::*;
    use aiosh_core::task_service::TaskAction;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_done_with_note_and_repeatable_evidence() {
        let a = parse_task_args(&s(&[
            "done", "2", "--note", "n", "--evidence", "a.md", "--evidence", "b.md",
        ]))
        .unwrap();
        assert_eq!(a.action, TaskAction::Done);
        assert_eq!(a.task_id, Some(2));
        assert_eq!(a.note.as_deref(), Some("n"));
        assert_eq!(a.evidence, ["a.md", "b.md"]);
        assert!(a.call().validate().is_ok());
    }

    #[test]
    fn parses_status_without_operand() {
        let a = parse_task_args(&s(&["status"])).unwrap();
        assert_eq!(a.action, TaskAction::Status);
        assert!(a.call().validate().is_ok());
    }

    #[test]
    fn rejects_empty_note() {
        let e = parse_task_args(&s(&["done", "1", "--note", ""]))
            .unwrap()
            .call()
            .validate()
            .unwrap_err();
        assert!(e.contains("'note'"), "{e}");
    }

    #[test]
    fn rejects_missing_note() {
        let e = parse_task_args(&s(&["done", "1"]))
            .unwrap()
            .call()
            .validate()
            .unwrap_err();
        assert!(e.contains("'note'"), "{e}");
    }

    #[test]
    fn rejects_oversized_text_at_validate() {
        // Caps live in TaskCall::validate (single source with MCP).
        let long = "x".repeat(4097);
        assert!(parse_task_args(&s(&["done", "1", "--note", &long]))
            .unwrap()
            .call()
            .validate()
            .unwrap_err()
            .contains("exceeds"));
        assert!(parse_task_args(&s(&["block", "1", "--reason", &long]))
            .unwrap()
            .call()
            .validate()
            .unwrap_err()
            .contains("exceeds"));
    }

    #[test]
    fn rejects_dash_leading_option_value() {
        let e = parse_task_args(&s(&["block", "1", "--reason", "--force"])).unwrap_err();
        assert!(e.contains("must not start with"), "{e}");
    }

    #[test]
    fn rejects_missing_value_at_end() {
        let e = parse_task_args(&s(&["skip", "1", "--reason"])).unwrap_err();
        assert!(e.contains("missing value for '--reason'"), "{e}");
    }

    #[test]
    fn rejects_unknown_option_token() {
        let e = parse_task_args(&s(&["status", "--wat"])).unwrap_err();
        assert!(e.contains("unknown option '--wat'"), "{e}");
    }

    #[test]
    fn double_dash_allows_dash_leading_values() {
        let a =
            parse_task_args(&s(&["done", "2", "--note", "--", "-not-a-flag"])).unwrap();
        assert_eq!(a.note.as_deref(), Some("-not-a-flag"));
        assert!(
            parse_task_args(&s(&["done", "2", "--note", "n", "--", "extra"])).is_err(),
            "bare token after consumed value must still error"
        );
    }

    #[test]
    fn id_must_be_decimal_gte_one() {
        assert!(parse_task_args(&s(&["done", "abc", "--note", "n"])).is_err());
        assert!(parse_task_args(&s(&["done", "-2", "--note", "n"])).is_err());
        assert!(parse_task_args(&s(&["done", "0", "--note", "n"])).is_err());
    }

    #[test]
    fn extra_operand_rejected_for_read_only_actions() {
        // Stricter-but-earlier: parse refuses before validate runs.
        let e = parse_task_args(&s(&["status", "5"])).unwrap_err();
        assert!(e.contains("unexpected argument '5'"), "{e}");
    }

    #[test]
    fn evidence_item_cap_enforced_by_validate() {
        let long = "y".repeat(4097);
        let a = parse_task_args(&s(&["done", "1", "--note", "n", "--evidence", &long]))
            .unwrap();
        assert!(a.call().validate().unwrap_err().contains("'evidence' item"));
    }

    #[test]
    fn usage_text_lists_contract() {
        let t = task_usage_text(None);
        for want in ["done", "--note", "help", "4096", "\"--\""] {
            assert!(t.contains(want), "missing {want}");
        }
        assert!(task_usage_text(Some("done")).contains("--note <text>"));
        assert!(task_usage_text(Some("nope")).contains("no such subcommand"));
    }

    #[test]
    fn test_cmd_doc_show_check_and_search() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir.parent().unwrap().parent().unwrap().parent().unwrap();
        let repo_str = repo_root.to_string_lossy().to_string();

        let code_show = cmd_doc(&["show".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert_eq!(code_show, 0);

        let code_show_json = cmd_doc(&["show".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert_eq!(code_show_json, 0);

        let code_check = cmd_doc(&["check".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert_eq!(code_check, 0);

        let code_check_json = cmd_doc(&["check".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert_eq!(code_check_json, 0);

        let code_search = cmd_doc(&["search".to_string(), "task".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert_eq!(code_search, 0);

        let code_invalid = cmd_doc(&["invalid_subcommand".to_string()]);
        assert_eq!(code_invalid, 2);
    }

    #[test]
    fn test_cmd_repo_health_and_check() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir.parent().unwrap().parent().unwrap().parent().unwrap();
        let repo_str = repo_root.to_string_lossy().to_string();

        let code_health = cmd_repo(&["health".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert!(code_health == 0 || code_health == 1);

        let code_health_json = cmd_repo(&["health".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert!(code_health_json == 0 || code_health_json == 1);

        let code_check = cmd_repo(&["check".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert!(code_check == 0 || code_check == 1);

        let code_check_json = cmd_repo(&["check".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert!(code_check_json == 0 || code_check_json == 1);

        let code_invalid = cmd_repo(&["invalid_subcommand".to_string()]);
        assert_eq!(code_invalid, 2);
    }

    #[test]
    fn test_cmd_secrets_scan_and_check() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir.parent().unwrap().parent().unwrap().parent().unwrap();
        let repo_str = repo_root.to_string_lossy().to_string();

        let code_scan = cmd_secrets(&["scan".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert!(code_scan == 0 || code_scan == 1);

        let code_scan_json = cmd_secrets(&["scan".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert!(code_scan_json == 0 || code_scan_json == 1);

        let code_check = cmd_secrets(&["check".to_string(), "--repo".to_string(), repo_str.clone()]);
        assert!(code_check == 0 || code_check == 1);

        let code_check_json = cmd_secrets(&["check".to_string(), "--repo".to_string(), repo_str.clone(), "--json".to_string()]);
        assert!(code_check_json == 0 || code_check_json == 1);

        let config_path = repo_root.join("docs/secrets_config.json").to_string_lossy().to_string();
        let code_config_scan = cmd_secrets(&["scan".to_string(), "--repo".to_string(), repo_str.clone(), "--config".to_string(), config_path]);
        assert!(code_config_scan == 0 || code_config_scan == 1);

        let code_invalid = cmd_secrets(&["invalid_subcommand".to_string()]);
        assert_eq!(code_invalid, 2);
    }

    #[test]
    fn test_cmd_triage_flow() {
        let store_file = std::env::temp_dir().join(format!("aios_triage_test_{}.json", std::process::id()));
        let store_str = store_file.to_string_lossy().to_string();

        let _ = std::fs::remove_file(&store_file);

        let code_list_empty = cmd_triage(&["list".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_list_empty, 0);

        let code_record = cmd_triage(&[
            "record".to_string(),
            "--target".to_string(),
            "secrets::tests::test_scan".to_string(),
            "--suite".to_string(),
            "secrets_suite".to_string(),
            "--error".to_string(),
            "panicked at assertion".to_string(),
            "--store".to_string(),
            store_str.clone(),
        ]);
        assert_eq!(code_record, 0);

        let code_check_fail = cmd_triage(&["check".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_check_fail, 1);

        let code_list = cmd_triage(&["list".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_list, 0);

        let config_file = std::env::temp_dir().join(format!("aios_triage_cfg_test_{}.json", std::process::id()));
        let cfg = aiosh_core::triage_config::TriageConfig::default();
        cfg.save_to_file(&config_file).unwrap();

        let code_config_list = cmd_triage(&["list".to_string(), "--config".to_string(), config_file.to_string_lossy().to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_config_list, 0);

        let code_invalid = cmd_triage(&["invalid_subcommand".to_string()]);
        assert_eq!(code_invalid, 2);

        let _ = std::fs::remove_file(&config_file);
        let _ = std::fs::remove_file(&store_file);
    }

    #[test]
    fn test_cmd_handoff_flow() {
        let store_file = std::env::temp_dir().join(format!("aios_handoff_test_{}.json", std::process::id()));
        let store_str = store_file.to_string_lossy().to_string();

        let _ = std::fs::remove_file(&store_file);

        // List empty
        let code_list_empty = cmd_handoff(&["list".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_list_empty, 0);

        // Initiate
        let code_initiate = cmd_handoff(&[
            "initiate".to_string(),
            "--sender".to_string(),
            "operator".to_string(),
            "--receiver".to_string(),
            "subagent-1".to_string(),
            "--summary".to_string(),
            "Review task execution".to_string(),
            "--priority".to_string(),
            "high".to_string(),
            "--store".to_string(),
            store_str.clone(),
        ]);
        assert_eq!(code_initiate, 0);

        // List JSON
        let code_list_json = cmd_handoff(&["list".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        // Accept
        let code_accept = cmd_handoff(&[
            "accept".to_string(),
            "HND-".to_string(),
            "--notes".to_string(),
            "Accepted".to_string(),
            "--store".to_string(),
            store_str.clone(),
        ]);
        // Invalid ID returns 1, valid sub returns 0/1
        assert!(code_accept == 0 || code_accept == 1);

        // Help
        let code_help = cmd_handoff(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        // Invalid
        let code_invalid = cmd_handoff(&["invalid_sub".to_string()]);
        assert_eq!(code_invalid, 2);

        let _ = std::fs::remove_file(&store_file);
    }

    #[test]
    fn test_cmd_distro_flow() {
        let code_list = cmd_distro(&["list".to_string()]);
        assert_eq!(code_list, 0);

        let code_list_json = cmd_distro(&["list".to_string(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        let code_show = cmd_distro(&["show".to_string(), "debian-12-minimal-x86_64".to_string()]);
        assert_eq!(code_show, 0);

        let code_show_missing = cmd_distro(&["show".to_string(), "nonexistent".to_string()]);
        assert_eq!(code_show_missing, 1);

        let code_eval = cmd_distro(&["evaluate".to_string()]);
        assert_eq!(code_eval, 0);

        let code_eval_single = cmd_distro(&["evaluate".to_string(), "alpine-319-container-x86_64".to_string()]);
        assert_eq!(code_eval_single, 0);

        let code_rec = cmd_distro(&["recommend".to_string()]);
        assert_eq!(code_rec, 0);

        let code_help = cmd_distro(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        let code_invalid = cmd_distro(&["invalid_sub".to_string()]);
        assert_eq!(code_invalid, 2);
    }

    #[test]
    fn test_cmd_image_flow() {
        let code_list = cmd_image(&["list".to_string()]);
        assert_eq!(code_list, 0);

        let code_list_json = cmd_image(&["list".to_string(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        let code_show = cmd_image(&["show".to_string(), "debian-12-minimal-raw".to_string()]);
        assert_eq!(code_show, 0);

        let code_show_missing = cmd_image(&["show".to_string(), "nonexistent".to_string()]);
        assert_eq!(code_show_missing, 1);

        let code_show_no_arg = cmd_image(&["show".to_string()]);
        assert_eq!(code_show_no_arg, 2);

        let code_show_control_char = cmd_image(&["show".to_string(), "bad\x07id".to_string()]);
        assert_eq!(code_show_control_char, 2);

        let code_plan = cmd_image(&["plan".to_string(), "debian-12-minimal-raw".to_string()]);
        assert_eq!(code_plan, 0);

        let code_plan_missing = cmd_image(&["plan".to_string(), "nonexistent".to_string()]);
        assert_eq!(code_plan_missing, 1);

        let code_plan_no_arg = cmd_image(&["plan".to_string()]);
        assert_eq!(code_plan_no_arg, 2);

        let code_plan_control_char = cmd_image(&["plan".to_string(), "bad\x07id".to_string()]);
        assert_eq!(code_plan_control_char, 2);

        let code_filter = cmd_image(&["filter".to_string(), "--format".to_string(), "iso".to_string()]);
        assert_eq!(code_filter, 0);

        let code_filter_bad_format = cmd_image(&["filter".to_string(), "--format".to_string(), "bad_fmt".to_string()]);
        assert_eq!(code_filter_bad_format, 2);

        let code_config = cmd_image(&["config".to_string()]);
        assert_eq!(code_config, 0);

        let code_config_json = cmd_image(&["config".to_string(), "--json".to_string()]);
        assert_eq!(code_config_json, 0);

        let code_policy_all = cmd_image(&["policy".to_string()]);
        assert_eq!(code_policy_all, 0);

        let code_policy_all_json = cmd_image(&["policy".to_string(), "--json".to_string()]);
        assert_eq!(code_policy_all_json, 0);

        let code_policy_single = cmd_image(&["policy".to_string(), "debian-12-minimal-raw".to_string()]);
        assert_eq!(code_policy_single, 0);

        let code_policy_missing = cmd_image(&["policy".to_string(), "nonexistent-img".to_string()]);
        assert_eq!(code_policy_missing, 1);

        let code_policy_bad_id = cmd_image(&["policy".to_string(), "bad\x07id".to_string()]);
        assert_eq!(code_policy_bad_id, 2);

        let code_report = cmd_image(&["report".to_string()]);
        assert_eq!(code_report, 0);

        let code_report_json = cmd_image(&["report".to_string(), "--json".to_string()]);
        assert_eq!(code_report_json, 0);

        let code_check = cmd_image(&["check".to_string()]);
        assert_eq!(code_check, 0);

        let code_check_json = cmd_image(&["check".to_string(), "--json".to_string()]);
        assert_eq!(code_check_json, 0);

        let code_check_fix = cmd_image(&["check".to_string(), "--fix".to_string()]);
        assert_eq!(code_check_fix, 0);

        let code_help = cmd_image(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        let code_invalid = cmd_image(&["invalid_sub".to_string()]);
        assert_eq!(code_invalid, 2);
    }

    #[test]
    fn test_cmd_package_flow() {
        let code_name_valid = cmd_package(&["validate".to_string(), "--name".to_string(), "curl".to_string()]);
        assert_eq!(code_name_valid, 0);

        let code_name_valid_json = cmd_package(&["validate".to_string(), "--name".to_string(), "curl".to_string(), "--json".to_string()]);
        assert_eq!(code_name_valid_json, 0);

        let code_name_invalid = cmd_package(&["validate".to_string(), "--name".to_string(), "Curl".to_string()]);
        assert_eq!(code_name_invalid, 2);

        let valid_spec = r#"{
            "name": "curl",
            "version": "8.5.0-2",
            "architecture": "x86_64",
            "format": "deb",
            "state": "available",
            "description": "curl tool",
            "installed_size_bytes": 1000,
            "sha256": null,
            "repository_url": null,
            "dependencies": []
        }"#;
        let code_spec_valid = cmd_package(&["validate".to_string(), "--spec".to_string(), valid_spec.to_string()]);
        assert_eq!(code_spec_valid, 0);

        let bad_spec = r#"{
            "name": "Curl",
            "version": "8.5.0-2",
            "architecture": "x86_64",
            "format": "deb",
            "state": "available",
            "description": "curl tool",
            "installed_size_bytes": 1000,
            "sha256": null,
            "repository_url": null,
            "dependencies": []
        }"#;
        let code_spec_invalid = cmd_package(&["validate".to_string(), "--spec".to_string(), bad_spec.to_string()]);
        assert_eq!(code_spec_invalid, 2);

        let code_help = cmd_package(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        let code_missing_flags = cmd_package(&["validate".to_string()]);
        assert_eq!(code_missing_flags, 2);

        let code_unknown = cmd_package(&["unknown".to_string()]);
        assert_eq!(code_unknown, 2);

        // list
        let code_list = cmd_package(&["list".to_string()]);
        assert_eq!(code_list, 0);

        let code_list_json = cmd_package(&["list".to_string(), "--json".to_string(), "--format".to_string(), "deb".to_string()]);
        assert_eq!(code_list_json, 0);

        // show
        let code_show = cmd_package(&["show".to_string(), "curl".to_string()]);
        assert_eq!(code_show, 0);

        let code_show_missing = cmd_package(&["show".to_string(), "nonexistent".to_string()]);
        assert_eq!(code_show_missing, 2);

        // plan
        let actions_json = r#"[{"action":"install","package_name":"libssl3","target_version":null},{"action":"install","package_name":"curl","target_version":null}]"#;
        let code_plan = cmd_package(&["plan".to_string(), "--actions".to_string(), actions_json.to_string()]);
        assert_eq!(code_plan, 0);

        let code_plan_dry = cmd_package(&["plan".to_string(), "--actions".to_string(), actions_json.to_string(), "--dry-run".to_string(), "--json".to_string()]);
        assert_eq!(code_plan_dry, 0);

        // plan missing dep
        let bad_actions_json = r#"[{"action":"install","package_name":"curl","target_version":null}]"#;
        let code_plan_bad = cmd_package(&["plan".to_string(), "--actions".to_string(), bad_actions_json.to_string()]);
        assert_eq!(code_plan_bad, 2);

        // search
        let code_search = cmd_package(&["search".to_string(), "curl".to_string()]);
        assert_eq!(code_search, 0);

        let code_search_json = cmd_package(&["search".to_string(), "lib".to_string(), "--json".to_string()]);
        assert_eq!(code_search_json, 0);

        let code_search_missing = cmd_package(&["search".to_string()]);
        assert_eq!(code_search_missing, 2);

        // apply missing arguments
        let code_apply_missing = cmd_package(&["apply".to_string()]);
        assert_eq!(code_apply_missing, 2);

        // apply dry run via actions
        let code_apply_dry = cmd_package(&["apply".to_string(), "--actions".to_string(), actions_json.to_string(), "--dry-run".to_string(), "--json".to_string()]);
        assert_eq!(code_apply_dry, 0);

        // apply dry run via plan
        let plan = aiosh_core::package_service::PackageStore::new().plan_transaction(
            vec![
                aiosh_core::package::PackageAction {
                    action: aiosh_core::package::PackageActionType::Install,
                    package_name: "libssl3".into(),
                    target_version: None,
                },
                aiosh_core::package::PackageAction {
                    action: aiosh_core::package::PackageActionType::Install,
                    package_name: "curl".into(),
                    target_version: None,
                },
            ],
            true,
        ).unwrap();
        let plan_json = serde_json::to_string(&plan).unwrap();
        let code_apply_plan = cmd_package(&["apply".to_string(), "--plan".to_string(), plan_json, "--dry-run".to_string()]);
        assert_eq!(code_apply_plan, 0);

        // apply with store persistence
        let store_file = std::env::temp_dir().join(format!("aios_package_apply_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&store_file);
        let initial_store = aiosh_core::package_service::PackageStore::new();
        initial_store.save_to_path(&store_file).unwrap();
        let store_file_str = store_file.to_str().unwrap().to_string();

        let code_apply_real = cmd_package(&[
            "apply".to_string(),
            "--actions".to_string(),
            actions_json.to_string(),
            "--store".to_string(),
            store_file_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_apply_real, 0);

        // verify store was updated on disk
        let reloaded = aiosh_core::package_service::PackageStore::load_from_path(&store_file).unwrap();
        assert_eq!(reloaded.get_package("curl").unwrap().state, aiosh_core::package::PackageState::Installed);
        let _ = std::fs::remove_file(&store_file);

        // edge cases: invalid format and state
        let code_list_bad_format = cmd_package(&["list".to_string(), "--format".to_string(), "invalid_fmt".to_string()]);
        assert_eq!(code_list_bad_format, 2);

        let code_list_bad_state = cmd_package(&["list".to_string(), "--state".to_string(), "invalid_state".to_string()]);
        assert_eq!(code_list_bad_state, 2);

        // edge case: apply with invalid json
        let code_apply_bad_json = cmd_package(&["apply".to_string(), "--actions".to_string(), "{bad_json}".to_string()]);
        assert_eq!(code_apply_bad_json, 2);

        // edge case: apply with dependency closure error
        let code_apply_dep_error = cmd_package(&["apply".to_string(), "--actions".to_string(), bad_actions_json.to_string()]);
        assert_eq!(code_apply_dep_error, 2);

        // hardening: bad limits
        let code_list_bad_limit = cmd_package(&["list".to_string(), "--limit".to_string(), "0".to_string()]);
        assert_eq!(code_list_bad_limit, 2);

        let code_search_bad_limit = cmd_package(&["search".to_string(), "curl".to_string(), "--limit".to_string(), "abc".to_string()]);
        assert_eq!(code_search_bad_limit, 2);

        // hardening: control characters in pattern and names
        let code_search_ctrl = cmd_package(&["search".to_string(), "bad\0pattern".to_string()]);
        assert_eq!(code_search_ctrl, 2);

        let code_show_ctrl = cmd_package(&["show".to_string(), "bad\nname".to_string()]);
        assert_eq!(code_show_ctrl, 2);

        // hardening: invalid store path with control characters
        let code_store_ctrl = cmd_package(&["list".to_string(), "--store".to_string(), "bad\0store.json".to_string()]);
        assert_eq!(code_store_ctrl, 2);

        // policy subcommand tests
        let code_policy_default = cmd_package(&["policy".to_string()]);
        assert_eq!(code_policy_default, 0);

        let code_policy_json = cmd_package(&["policy".to_string(), "--json".to_string()]);
        assert_eq!(code_policy_json, 0);

        let code_policy_pkg_valid = cmd_package(&["policy".to_string(), "--package".to_string(), "curl".to_string()]);
        assert_eq!(code_policy_pkg_valid, 0);

        let code_policy_pkg_invalid = cmd_package(&["policy".to_string(), "--package".to_string(), "telnet".to_string()]);
        assert_eq!(code_policy_pkg_invalid, 2);

        let code_policy_pkg_not_found = cmd_package(&["policy".to_string(), "--package".to_string(), "nonexistent_pkg".to_string()]);
        assert_eq!(code_policy_pkg_not_found, 2);

        // stats subcommand tests
        let code_stats_default = cmd_package(&["stats".to_string()]);
        assert_eq!(code_stats_default, 0);

        let code_stats_json = cmd_package(&["stats".to_string(), "--json".to_string()]);
        assert_eq!(code_stats_json, 0);

        let code_stats_bad_path = cmd_package(&["stats".to_string(), "--store".to_string(), "bad\0store".to_string()]);
        assert_eq!(code_stats_bad_path, 2);

        let code_stats_bad_config = cmd_package(&["stats".to_string(), "--config".to_string(), "bad\0config".to_string()]);
        assert_eq!(code_stats_bad_config, 2);

        let code_stats_missing_store = cmd_package(&["stats".to_string(), "--store".to_string(), "nonexistent_store_9999.json".to_string()]);
        assert_eq!(code_stats_missing_store, 1);

        let code_stats_missing_config = cmd_package(&["stats".to_string(), "--config".to_string(), "nonexistent_config_9999.json".to_string()]);
        assert_eq!(code_stats_missing_config, 1);

        // check subcommand tests
        let code_check_default = cmd_package(&["check".to_string()]);
        assert_eq!(code_check_default, 0);

        let code_check_json = cmd_package(&["check".to_string(), "--json".to_string()]);
        assert_eq!(code_check_json, 0);

        let corrupt_store = std::env::temp_dir().join(format!("corrupt_packages_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&corrupt_store);
        std::fs::write(&corrupt_store, b"CORRUPTED").unwrap();
        let corrupt_store_str = corrupt_store.to_str().unwrap().to_string();

        // without --fix, corrupted store returns 1
        let code_check_corrupt = cmd_package(&["check".to_string(), "--store".to_string(), corrupt_store_str.clone(), "--json".to_string()]);
        assert_eq!(code_check_corrupt, 1);

        // with --fix, recovers and returns 0
        let code_check_fix = cmd_package(&["check".to_string(), "--store".to_string(), corrupt_store_str.clone(), "--fix".to_string(), "--json".to_string()]);
        assert_eq!(code_check_fix, 0);

        // bad store path with control char returns 2
        let code_check_bad_path = cmd_package(&["check".to_string(), "--store".to_string(), "bad\0store".to_string()]);
        assert_eq!(code_check_bad_path, 2);
    }

    #[test]
    fn test_cmd_service_flow() {
        // help
        let code_help = cmd_service(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        // unknown subcommand
        let code_unknown = cmd_service(&["unknown_cmd".to_string()]);
        assert_eq!(code_unknown, 2);

        // validate missing args
        let code_missing = cmd_service(&["validate".to_string()]);
        assert_eq!(code_missing, 2);

        // validate valid name
        let code_name_valid = cmd_service(&["validate".to_string(), "--name".to_string(), "aios-securityd.service".to_string()]);
        assert_eq!(code_name_valid, 0);

        let code_name_valid_json = cmd_service(&["validate".to_string(), "--name".to_string(), "aios-securityd.service".to_string(), "--json".to_string()]);
        assert_eq!(code_name_valid_json, 0);

        // validate invalid name
        let code_name_invalid = cmd_service(&["validate".to_string(), "--name".to_string(), "invalid/service".to_string()]);
        assert_eq!(code_name_invalid, 2);

        // validate valid spec inline
        let valid_spec_json = serde_json::json!({
            "name": "aios-securityd.service",
            "description": "AIOS Security Daemon",
            "exec_start": "/usr/bin/aios-securityd --daemon",
            "exec_stop": null,
            "exec_reload": null,
            "service_type": "simple",
            "restart_policy": "always",
            "startup_mode": "enabled",
            "user": "aios",
            "group": "aios",
            "working_dir": "/var/lib/aios",
            "environment": {},
            "dependencies": [],
            "timeout_start_secs": 30,
            "timeout_stop_secs": 30
        }).to_string();

        let code_spec_valid = cmd_service(&["validate".to_string(), "--spec".to_string(), valid_spec_json.clone()]);
        assert_eq!(code_spec_valid, 0);

        let code_spec_valid_json = cmd_service(&["validate".to_string(), "--spec".to_string(), valid_spec_json, "--json".to_string()]);
        assert_eq!(code_spec_valid_json, 0);

        // validate invalid spec (self-dependency)
        let invalid_spec_json = serde_json::json!({
            "name": "aios-securityd.service",
            "description": "AIOS Security Daemon",
            "exec_start": "/usr/bin/aios-securityd --daemon",
            "exec_stop": null,
            "exec_reload": null,
            "service_type": "simple",
            "restart_policy": "always",
            "startup_mode": "enabled",
            "user": "aios",
            "group": "aios",
            "working_dir": "/var/lib/aios",
            "environment": {},
            "dependencies": [{
                "name": "aios-securityd.service",
                "dependency_type": "requires",
                "optional": false
            }],
            "timeout_start_secs": 30,
            "timeout_stop_secs": 30
        }).to_string();

        let code_spec_invalid = cmd_service(&["validate".to_string(), "--spec".to_string(), invalid_spec_json]);
        assert_eq!(code_spec_invalid, 2);

        // list
        let code_list_default = cmd_service(&["list".to_string()]);
        assert_eq!(code_list_default, 0);

        let code_list_json = cmd_service(&["list".to_string(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        let code_list_state = cmd_service(&["list".to_string(), "--state".to_string(), "active".to_string(), "--json".to_string()]);
        assert_eq!(code_list_state, 0);

        let code_list_bad_state = cmd_service(&["list".to_string(), "--state".to_string(), "invalid_state".to_string()]);
        assert_eq!(code_list_bad_state, 2);

        let code_list_mode = cmd_service(&["list".to_string(), "--mode".to_string(), "enabled".to_string(), "--json".to_string()]);
        assert_eq!(code_list_mode, 0);

        let code_list_bad_mode = cmd_service(&["list".to_string(), "--mode".to_string(), "invalid_mode".to_string()]);
        assert_eq!(code_list_bad_mode, 2);

        let code_list_pattern = cmd_service(&["list".to_string(), "--pattern".to_string(), "audit".to_string()]);
        assert_eq!(code_list_pattern, 0);

        let code_list_bad_limit = cmd_service(&["list".to_string(), "--limit".to_string(), "0".to_string()]);
        assert_eq!(code_list_bad_limit, 2);

        // show
        let code_show_valid = cmd_service(&["show".to_string(), "auditd.service".to_string()]);
        assert_eq!(code_show_valid, 0);

        let code_show_valid_json = cmd_service(&["show".to_string(), "auditd.service".to_string(), "--json".to_string()]);
        assert_eq!(code_show_valid_json, 0);

        let code_show_missing = cmd_service(&["show".to_string()]);
        assert_eq!(code_show_missing, 2);

        let code_show_not_found = cmd_service(&["show".to_string(), "nonexistent.service".to_string()]);
        assert_eq!(code_show_not_found, 1);

        let code_show_ctrl = cmd_service(&["show".to_string(), "bad\0name".to_string()]);
        assert_eq!(code_show_ctrl, 2);

        // status alias
        let code_status_valid = cmd_service(&["status".to_string(), "auditd.service".to_string(), "--json".to_string()]);
        assert_eq!(code_status_valid, 0);

        // action
        let temp_store_file = std::env::temp_dir().join(format!("aios_service_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&temp_store_file);
        let init_store = aiosh_core::service_service::ServiceStore::new();
        init_store.save_to_path(&temp_store_file).unwrap();
        let store_str = temp_store_file.to_str().unwrap().to_string();

        let code_action_stop = cmd_service(&["action".to_string(), "auditd.service".to_string(), "stop".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_action_stop, 0);

        let code_action_start = cmd_service(&["action".to_string(), "auditd.service".to_string(), "start".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_action_start, 0);

        let code_action_restart = cmd_service(&["action".to_string(), "auditd.service".to_string(), "restart".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_action_restart, 0);

        // direct action shortcuts
        let code_shortcut_stop = cmd_service(&["stop".to_string(), "auditd.service".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_shortcut_stop, 0);

        let code_shortcut_start = cmd_service(&["start".to_string(), "auditd.service".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_shortcut_start, 0);

        let code_shortcut_reload = cmd_service(&["reload".to_string(), "auditd.service".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_shortcut_reload, 0);

        let code_shortcut_disable = cmd_service(&["disable".to_string(), "auditd.service".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_shortcut_disable, 0);

        let code_shortcut_enable = cmd_service(&["enable".to_string(), "auditd.service".to_string(), "--store".to_string(), store_str.clone()]);
        assert_eq!(code_shortcut_enable, 0);

        let code_shortcut_missing = cmd_service(&["start".to_string()]);
        assert_eq!(code_shortcut_missing, 2);

        let code_action_bad_action = cmd_service(&["action".to_string(), "auditd.service".to_string(), "invalid_act".to_string()]);
        assert_eq!(code_action_bad_action, 2);

        let code_action_missing_args = cmd_service(&["action".to_string(), "auditd.service".to_string()]);
        assert_eq!(code_action_missing_args, 2);

        let _ = std::fs::remove_file(&temp_store_file);

        // order
        let code_order_valid = cmd_service(&["order".to_string(), "aios-securityd.service".to_string()]);
        assert_eq!(code_order_valid, 0);

        let code_order_valid_json = cmd_service(&["order".to_string(), "aios-securityd.service".to_string(), "--json".to_string()]);
        assert_eq!(code_order_valid_json, 0);

        let code_order_missing = cmd_service(&["order".to_string()]);
        assert_eq!(code_order_missing, 2);

        let code_order_not_found = cmd_service(&["order".to_string(), "nonexistent.service".to_string()]);
        assert_eq!(code_order_not_found, 1);

        // config
        let code_config = cmd_service(&["config".to_string()]);
        assert_eq!(code_config, 0);

        let code_config_json = cmd_service(&["config".to_string(), "--json".to_string()]);
        assert_eq!(code_config_json, 0);

        let code_config_bad = cmd_service(&["config".to_string(), "--config".to_string(), "bad\0path".to_string()]);
        assert_eq!(code_config_bad, 2);

        // policy
        let code_policy = cmd_service(&["policy".to_string()]);
        assert_eq!(code_policy, 0);

        let code_policy_json = cmd_service(&["policy".to_string(), "--json".to_string()]);
        assert_eq!(code_policy_json, 0);

        let code_policy_eval = cmd_service(&["policy".to_string(), "--service".to_string(), "aios-securityd.service".to_string()]);
        assert_eq!(code_policy_eval, 0);

        let code_policy_bad = cmd_service(&["policy".to_string(), "--config".to_string(), "bad\0path".to_string()]);
        assert_eq!(code_policy_bad, 2);

        // stats / observability
        let code_stats = cmd_service(&["stats".to_string()]);
        assert_eq!(code_stats, 0);

        let code_stats_json = cmd_service(&["stats".to_string(), "--json".to_string()]);
        assert_eq!(code_stats_json, 0);

        let code_obs_alias = cmd_service(&["observability".to_string()]);
        assert_eq!(code_obs_alias, 0);

        let code_stats_bad_store = cmd_service(&["stats".to_string(), "--store".to_string(), "bad\0store".to_string()]);
        assert_eq!(code_stats_bad_store, 2);

        let code_stats_bad_policy = cmd_service(&["stats".to_string(), "--policy".to_string(), "bad\0policy".to_string()]);
        assert_eq!(code_stats_bad_policy, 2);

        let code_stats_missing_store = cmd_service(&["stats".to_string(), "--store".to_string(), "nonexistent_store_9999.json".to_string()]);
        assert_eq!(code_stats_missing_store, 1);
    }

    #[test]
    fn test_cmd_session_flow() {
        let code_help = cmd_session(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        let code_unknown = cmd_session(&["unknown_cmd".to_string()]);
        assert_eq!(code_unknown, 2);

        // validate id
        let code_id_valid = cmd_session(&["validate".to_string(), "--id".to_string(), "sess-01".to_string()]);
        assert_eq!(code_id_valid, 0);

        let code_id_invalid = cmd_session(&["validate".to_string(), "--id".to_string(), "../evil".to_string()]);
        assert_eq!(code_id_invalid, 2);

        // validate user
        let code_user_valid = cmd_session(&["validate".to_string(), "--user".to_string(), "kali".to_string()]);
        assert_eq!(code_user_valid, 0);

        let code_user_invalid = cmd_session(&["validate".to_string(), "--user".to_string(), "Kali".to_string()]);
        assert_eq!(code_user_invalid, 2);

        // validate spec
        let valid_spec = r#"{
            "session_id": "sess-unit-01",
            "username": "kali",
            "uid": 1000,
            "gid": 1000,
            "session_type": "x11",
            "session_class": "user",
            "seat": "seat0",
            "vtnr": 7,
            "display": ":0",
            "remote_host": null,
            "environment": {}
        }"#;
        let code_spec_valid = cmd_session(&["validate".to_string(), "--spec".to_string(), valid_spec.to_string(), "--json".to_string()]);
        assert_eq!(code_spec_valid, 0);

        let bad_spec = r#"{
            "session_id": "sess-unit-01",
            "username": "kali",
            "uid": 1000,
            "gid": 1000,
            "session_type": "x11",
            "session_class": "user",
            "seat": "seat0",
            "vtnr": 7,
            "display": null,
            "remote_host": null,
            "environment": {}
        }"#;
        let code_spec_invalid = cmd_session(&["validate".to_string(), "--spec".to_string(), bad_spec.to_string(), "--json".to_string()]);
        assert_eq!(code_spec_invalid, 2);

        // list
        let code_list = cmd_session(&["list".to_string()]);
        assert_eq!(code_list, 0);

        let code_list_json = cmd_session(&["list".to_string(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        let code_list_bad_limit = cmd_session(&["list".to_string(), "--limit".to_string(), "0".to_string()]);
        assert_eq!(code_list_bad_limit, 2);

        // show & status alias
        let code_show = cmd_session(&["show".to_string(), "greeter-seat0".to_string()]);
        assert_eq!(code_show, 0);

        let code_status = cmd_session(&["status".to_string(), "greeter-seat0".to_string(), "--json".to_string()]);
        assert_eq!(code_status, 0);

        let code_show_missing = cmd_session(&["show".to_string()]);
        assert_eq!(code_show_missing, 2);

        let code_show_not_found = cmd_session(&["show".to_string(), "nonexistent-sess".to_string()]);
        assert_eq!(code_show_not_found, 1);

        // action
        let code_action_lock = cmd_session(&["action".to_string(), "greeter-seat0".to_string(), "lock".to_string()]);
        assert_eq!(code_action_lock, 0);

        let code_action_bad = cmd_session(&["action".to_string(), "greeter-seat0".to_string(), "bad_action".to_string()]);
        assert_eq!(code_action_bad, 2);

        // shortcuts
        let code_lock = cmd_session(&["lock".to_string(), "greeter-seat0".to_string()]);
        assert_eq!(code_lock, 0);

        let code_activate = cmd_session(&["activate".to_string(), "greeter-seat0".to_string()]);
        assert_eq!(code_activate, 0);

        // create
        let code_create = cmd_session(&["create".to_string(), valid_spec.to_string(), "--json".to_string()]);
        assert_eq!(code_create, 0);

        let code_create_bad = cmd_session(&["create".to_string(), bad_spec.to_string(), "--json".to_string()]);
        assert_eq!(code_create_bad, 2);

        let code_create_missing = cmd_session(&["create".to_string()]);
        assert_eq!(code_create_missing, 2);

        // policy
        let code_policy_default = cmd_session(&["policy".to_string()]);
        assert_eq!(code_policy_default, 0);

        let code_policy_json = cmd_session(&["policy".to_string(), "--json".to_string()]);
        assert_eq!(code_policy_json, 0);

        let code_policy_valid_spec = cmd_session(&["policy".to_string(), "--spec".to_string(), valid_spec.to_string()]);
        assert_eq!(code_policy_valid_spec, 0);

        let policy_bad_spec = r#"{
            "session_id": "sess-root-01",
            "username": "root",
            "uid": 0,
            "gid": 0,
            "session_type": "tty",
            "session_class": "user",
            "seat": "seat0",
            "vtnr": 1,
            "display": null,
            "remote_host": null,
            "environment": {}
        }"#;
        let code_policy_bad_spec = cmd_session(&["policy".to_string(), "--spec".to_string(), policy_bad_spec.to_string()]);
        assert_eq!(code_policy_bad_spec, 1);
    }

    #[test]
    fn test_cmd_fs_layout_flow() {
        let code_help = cmd_fs_layout(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        let code_unknown = cmd_fs_layout(&["unknown_subcmd".to_string()]);
        assert_eq!(code_unknown, 2);

        let code_show = cmd_fs_layout(&["show".to_string()]);
        assert_eq!(code_show, 0);

        let code_show_json = cmd_fs_layout(&["show".to_string(), "--json".to_string()]);
        assert_eq!(code_show_json, 0);

        let code_show_container = cmd_fs_layout(&["show".to_string(), "--container".to_string(), "--json".to_string()]);
        assert_eq!(code_show_container, 0);

        let code_validate = cmd_fs_layout(&["validate".to_string()]);
        assert_eq!(code_validate, 0);

        let code_validate_json = cmd_fs_layout(&["validate".to_string(), "--json".to_string()]);
        assert_eq!(code_validate_json, 0);

        let code_check = cmd_fs_layout(&["check".to_string()]);
        assert_eq!(code_check, 0);

        let code_fstab = cmd_fs_layout(&["fstab".to_string()]);
        assert_eq!(code_fstab, 0);

        let code_fstab_json = cmd_fs_layout(&["fstab".to_string(), "--json".to_string()]);
        assert_eq!(code_fstab_json, 0);

        let bad_spec = r#"{
            "id": "bad-layout",
            "name": "Bad",
            "description": "No root",
            "target_disk_min_bytes": 1000,
            "partitions": [],
            "mounts": [],
            "directories": [],
            "created_at": "2026-09-16T00:00:00Z"
        }"#;
        let code_bad_val = cmd_fs_layout(&["validate".to_string(), "--spec".to_string(), bad_spec.to_string(), "--json".to_string()]);
        assert_eq!(code_bad_val, 1);

        let code_list = cmd_fs_layout(&["list".to_string()]);
        assert_eq!(code_list, 0);

        let code_list_json = cmd_fs_layout(&["list".to_string(), "--json".to_string()]);
        assert_eq!(code_list_json, 0);

        let code_probe_ok = cmd_fs_layout(&["probe".to_string(), "--bytes".to_string(), "107374182400".to_string()]);
        assert_eq!(code_probe_ok, 0);

        let code_probe_fail = cmd_fs_layout(&["probe".to_string(), "--bytes".to_string(), "10485760".to_string(), "--json".to_string()]);
        assert_eq!(code_probe_fail, 1);

        let code_diff = cmd_fs_layout(&["diff".to_string()]);
        assert_eq!(code_diff, 0);

        let code_diff_json = cmd_fs_layout(&["diff".to_string(), "aios-uefi-standard-v1".to_string(), "aios-container-minimal-v1".to_string(), "--json".to_string()]);
        assert_eq!(code_diff_json, 0);

        // Store path validation
        let code_bad_store = cmd_fs_layout(&["list".to_string(), "--store".to_string(), "bad\x00store".to_string(), "--json".to_string()]);
        assert_eq!(code_bad_store, 2);

        // Subcommand missing argument validation tests (code 2)
        let code_reg_no_spec = cmd_fs_layout(&["register".to_string(), "--json".to_string()]);
        assert_eq!(code_reg_no_spec, 2);

        let code_set_active_no_id = cmd_fs_layout(&["set-active".to_string(), "--json".to_string()]);
        assert_eq!(code_set_active_no_id, 2);

        let code_remove_no_id = cmd_fs_layout(&["remove".to_string(), "--json".to_string()]);
        assert_eq!(code_remove_no_id, 2);

        let code_import_no_args = cmd_fs_layout(&["import-fstab".to_string(), "--json".to_string()]);
        assert_eq!(code_import_no_args, 2);

        // Persistent store workflow testing
        let temp_store_file = std::env::temp_dir().join(format!("aios_fs_layout_test_{}_{}.json", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let store_str = temp_store_file.to_str().unwrap().to_string();

        let valid_custom_spec = aiosh_core::fs_layout::FilesystemLayoutSpec {
            id: "custom-srv-v1".to_string(),
            name: "Custom Server Layout".to_string(),
            description: "Test layout".to_string(),
            target_disk_min_bytes: 30_u64 * 1024 * 1024 * 1024,
            partitions: vec![
                aiosh_core::fs_layout::PartitionSpec {
                    index: 1,
                    label: "boot".to_string(),
                    partition_type: aiosh_core::fs_layout::PartitionType::EfiSystem,
                    size_mib: 512,
                    uuid: None,
                    bootable: true,
                    format_as: Some(aiosh_core::fs_layout::FsType::Vfat),
                },
                aiosh_core::fs_layout::PartitionSpec {
                    index: 2,
                    label: "root".to_string(),
                    partition_type: aiosh_core::fs_layout::PartitionType::LinuxRoot,
                    size_mib: 20480,
                    uuid: None,
                    bootable: false,
                    format_as: Some(aiosh_core::fs_layout::FsType::Ext4),
                },
            ],
            mounts: vec![
                aiosh_core::fs_layout::MountPointSpec {
                    path: "/".to_string(),
                    device: "/dev/sda2".to_string(),
                    fs_type: aiosh_core::fs_layout::FsType::Ext4,
                    options: vec!["defaults".to_string(), "noatime".to_string()],
                    dump: 1,
                    pass: 1,
                    required: true,
                },
                aiosh_core::fs_layout::MountPointSpec {
                    path: "/boot/efi".to_string(),
                    device: "/dev/sda1".to_string(),
                    fs_type: aiosh_core::fs_layout::FsType::Vfat,
                    options: vec!["umask=0077".to_string()],
                    dump: 0,
                    pass: 2,
                    required: true,
                },
            ],
            directories: vec![],
            created_at: "2026-09-16T00:00:00Z".to_string(),
        };
        let valid_custom_json = valid_custom_spec.to_json().unwrap();

        // 1. Register valid layout into persistent store
        let code_reg_ok = cmd_fs_layout(&[
            "register".to_string(),
            "--spec".to_string(),
            valid_custom_json.clone(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_reg_ok, 0);

        // Duplicate registration fails with code 1
        let code_reg_dup = cmd_fs_layout(&[
            "register".to_string(),
            "--spec".to_string(),
            valid_custom_json,
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_reg_dup, 1);

        // 2. List layouts from persistent store
        let code_list_store = cmd_fs_layout(&["list".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_list_store, 0);

        // 3. Show custom layout from persistent store
        let code_show_custom = cmd_fs_layout(&["show".to_string(), "custom-srv-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_show_custom, 0);

        // 4. Set active layout
        let code_set_active = cmd_fs_layout(&["set-active".to_string(), "custom-srv-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_set_active, 0);

        // Cannot remove currently active layout
        let code_remove_active = cmd_fs_layout(&["remove".to_string(), "custom-srv-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_remove_active, 1);

        // 5. Import fstab into new profile
        // fstab entries are ordered root-first so the import satisfies the FL3 parent-before-child rule.
        let fstab_text = "/dev/sda2 / ext4 defaults 1 1\n/dev/sda1 /boot/efi vfat umask=0077 0 2\n";
        let code_import = cmd_fs_layout(&[
            "import-fstab".to_string(),
            "imported-srv-v1".to_string(),
            "Imported Server".to_string(),
            "--fstab".to_string(),
            fstab_text.to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_import, 0);

        // 6. Diff between custom-srv-v1 and imported-srv-v1
        let code_diff_custom = cmd_fs_layout(&[
            "diff".to_string(),
            "custom-srv-v1".to_string(),
            "imported-srv-v1".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_diff_custom, 0);

        // 7. Switch active layout back to standard, then remove custom-srv-v1
        let code_set_active_orig = cmd_fs_layout(&["set-active".to_string(), "aios-uefi-standard-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_set_active_orig, 0);

        let code_remove_ok = cmd_fs_layout(&["remove".to_string(), "custom-srv-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_remove_ok, 0);

        // Cannot remove already removed layout
        let code_remove_again = cmd_fs_layout(&["remove".to_string(), "custom-srv-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_remove_again, 1);

        // Cannot remove built-in canonical layout
        let code_remove_builtin = cmd_fs_layout(&["remove".to_string(), "aios-container-minimal-v1".to_string(), "--store".to_string(), store_str.clone(), "--json".to_string()]);
        assert_eq!(code_remove_builtin, 1);

        // Clean up temp store file
        let _ = std::fs::remove_file(&temp_store_file);
    }

    #[test]
    fn test_cmd_kernel_module_flow() {
        // 1. Help flag
        let code_help = cmd_kernel_module(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        // 2. Unknown subcommand
        let code_unknown = cmd_kernel_module(&["unknown_subcmd".to_string()]);
        assert_eq!(code_unknown, 2);

        // 3. Path injection / control character on --store
        let code_bad_store = cmd_kernel_module(&["list".to_string(), "--store".to_string(), "bad\x00store".to_string(), "--json".to_string()]);
        assert_eq!(code_bad_store, 2);

        // Setup temporary store and proc_modules paths
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join(format!("aios_test_mod_store_{}.json", std::process::id()));
        let store_str = store_path.to_string_lossy().to_string();

        let mock_proc_path = temp_dir.join(format!("aios_test_proc_modules_{}.txt", std::process::id()));
        let proc_content = "overlay 151552 1 - Live 0x0000000000000000\next4 983040 2 - Live 0x0000000000000000\n";
        let _ = std::fs::write(&mock_proc_path, proc_content);
        let proc_str = mock_proc_path.to_string_lossy().to_string();

        // 4. List modules with mock proc and empty store
        let code_list = cmd_kernel_module(&[
            "list".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--proc-modules".to_string(),
            proc_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_list, 0);

        // 5. Show module from mock proc
        let code_show_proc = cmd_kernel_module(&[
            "show".to_string(),
            "overlay".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--proc-modules".to_string(),
            proc_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_show_proc, 0);

        // 6. Show without module name (exit 2)
        let code_show_no_arg = cmd_kernel_module(&["show".to_string(), "--json".to_string()]);
        assert_eq!(code_show_no_arg, 2);

        // 7. Show non-existent module (exit 1)
        let code_show_missing = cmd_kernel_module(&[
            "show".to_string(),
            "nonexistent_mod".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--proc-modules".to_string(),
            proc_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_show_missing, 1);

        // 8. Blacklist missing arg (exit 2)
        let code_bl_no_arg = cmd_kernel_module(&["blacklist".to_string(), "--json".to_string()]);
        assert_eq!(code_bl_no_arg, 2);

        // 9. Blacklist valid module (exit 0)
        let code_bl_ok = cmd_kernel_module(&[
            "blacklist".to_string(),
            "usb_storage".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_bl_ok, 0);

        // Show blacklisted module (exit 0)
        let code_show_bl = cmd_kernel_module(&[
            "show".to_string(),
            "usb_storage".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_show_bl, 0);

        // 10. Conflict: Cannot autoload blacklisted module (exit 1)
        let code_auto_conflict = cmd_kernel_module(&[
            "autoload".to_string(),
            "usb_storage".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_auto_conflict, 1);

        // 11. Unblacklist (exit 0)
        let code_unbl = cmd_kernel_module(&[
            "unblacklist".to_string(),
            "usb_storage".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_unbl, 0);

        // 12. Autoload valid module (exit 0)
        let code_auto_ok = cmd_kernel_module(&[
            "autoload".to_string(),
            "br_netfilter".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_auto_ok, 0);

        // 13. Conflict: Cannot blacklist autoloaded module (exit 1)
        let code_bl_conflict = cmd_kernel_module(&[
            "blacklist".to_string(),
            "br_netfilter".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_bl_conflict, 1);

        // 14. Unautoload (exit 0)
        let code_unauto = cmd_kernel_module(&[
            "unautoload".to_string(),
            "br_netfilter".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_unauto, 0);

        // 15. Options valid (exit 0)
        let code_opt_ok = cmd_kernel_module(&[
            "options".to_string(),
            "e1000e".to_string(),
            "InterruptThrottleRate=1".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_opt_ok, 0);

        // 16. Options missing parameters (exit 2)
        let code_opt_no_param = cmd_kernel_module(&[
            "options".to_string(),
            "e1000e".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_opt_no_param, 2);

        // 17. Options invalid parameter (exit 1)
        let code_opt_invalid = cmd_kernel_module(&[
            "options".to_string(),
            "e1000e".to_string(),
            "invalid;param=1".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_opt_invalid, 1);

        // 18. Preset list (exit 0)
        let code_preset_list = cmd_kernel_module(&["preset".to_string(), "list".to_string(), "--json".to_string()]);
        assert_eq!(code_preset_list, 0);

        // 19. Preset apply missing name (exit 2)
        let code_preset_no_name = cmd_kernel_module(&["preset".to_string(), "apply".to_string(), "--json".to_string()]);
        assert_eq!(code_preset_no_name, 2);

        // 20. Preset apply unknown preset (exit 1)
        let code_preset_unknown = cmd_kernel_module(&[
            "preset".to_string(),
            "apply".to_string(),
            "nonexistent_preset".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_preset_unknown, 1);

        // 21. Preset apply valid (exit 0)
        let code_preset_ok = cmd_kernel_module(&[
            "preset".to_string(),
            "apply".to_string(),
            "cis_hardened_baseline".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_preset_ok, 0);

        // 22. Export stdout (exit 0)
        let code_export = cmd_kernel_module(&[
            "export".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_export, 0);

        // 23. Export to files (exit 0)
        let modprobe_file = temp_dir.join(format!("aios_test_modprobe_{}.conf", std::process::id()));
        let autoload_file = temp_dir.join(format!("aios_test_autoload_{}.conf", std::process::id()));
        let code_export_files = cmd_kernel_module(&[
            "export".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--modprobe".to_string(),
            modprobe_file.to_string_lossy().to_string(),
            "--autoload".to_string(),
            autoload_file.to_string_lossy().to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(code_export_files, 0);
        assert!(modprobe_file.exists());
        assert!(autoload_file.exists());

        // 24. Check healthy store (exit 0)
        let code_check_ok = cmd_kernel_module(&[
            "check".to_string(),
            "--store".to_string(),
            store_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_check_ok, 0);

        // 25. Check with control char on --store (exit 2)
        let code_check_ctrl = cmd_kernel_module(&[
            "check".to_string(),
            "--store".to_string(),
            "bad\x00store".to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(code_check_ctrl, 2);

        // 26. Check corrupted store (exit 1)
        let corrupt_path = temp_dir.join(format!("aios_corrupt_store_{}.json", std::process::id()));
        let corrupt_str = corrupt_path.to_string_lossy().to_string();
        let _ = std::fs::write(&corrupt_path, "{ broken json ... ");
        let code_check_corrupt = cmd_kernel_module(&[
            "check".to_string(),
            "--store".to_string(),
            corrupt_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_check_corrupt, 1);

        // 27. Check with --auto-recover on corrupted store (exit 0)
        let code_recover_ok = cmd_kernel_module(&[
            "check".to_string(),
            "--store".to_string(),
            corrupt_str.clone(),
            "--auto-recover".to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(code_recover_ok, 0);

        // Clean up temp files
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_file(&mock_proc_path);
        let _ = std::fs::remove_file(&modprobe_file);
        let _ = std::fs::remove_file(&autoload_file);
        let _ = std::fs::remove_file(&corrupt_path);
    }

    #[test]
    fn test_hardware_cli_coverage() {
        // 1. Help
        let code_help = cmd_hardware(&["--help".to_string()]);
        assert_eq!(code_help, 0);

        // 2. Unknown subcommand
        let code_unknown = cmd_hardware(&["bogus_cmd".to_string(), "--json".to_string()]);
        assert_eq!(code_unknown, 2);

        // 3. Path hygiene: too long sysfs
        let long_path = "a".repeat(1025);
        let code_long_sys = cmd_hardware(&["scan".to_string(), "--sysfs".to_string(), long_path, "--json".to_string()]);
        assert_eq!(code_long_sys, 2);

        // 4. Path hygiene: control char in procfs
        let code_ctrl_proc = cmd_hardware(&["scan".to_string(), "--procfs".to_string(), "bad\x00path".to_string(), "--json".to_string()]);
        assert_eq!(code_ctrl_proc, 2);

        // 5. Invalid device class
        let code_bad_class = cmd_hardware(&["scan".to_string(), "--class".to_string(), "badclass".to_string(), "--json".to_string()]);
        assert_eq!(code_bad_class, 2);

        // 6. Missing device ID on show (omitted, empty, whitespace, control char, too long)
        let code_no_id = cmd_hardware(&["show".to_string(), "--json".to_string()]);
        assert_eq!(code_no_id, 2);
        let code_ws_id = cmd_hardware(&["show".to_string(), "   ".to_string(), "--json".to_string()]);
        assert_eq!(code_ws_id, 2);
        let code_ctrl_id = cmd_hardware(&["show".to_string(), "bad\x07dev".to_string(), "--json".to_string()]);
        assert_eq!(code_ctrl_id, 2);
        let code_long_id = cmd_hardware(&["show".to_string(), "x".repeat(257), "--json".to_string()]);
        assert_eq!(code_long_id, 2);

        // Setup mock environment
        let tmp_dir = std::env::temp_dir().join(format!("aios_hw_cli_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let sysfs = tmp_dir.join("sys");
        let procfs = tmp_dir.join("proc");

        let pci_dir = sysfs.join("bus/pci/devices/0000_00_02.0");
        std::fs::create_dir_all(&pci_dir).unwrap();
        std::fs::write(pci_dir.join("vendor"), "0x8086\n").unwrap();
        std::fs::write(pci_dir.join("device"), "0x9bc4\n").unwrap();
        std::fs::write(pci_dir.join("class"), "0x030000\n").unwrap();

        let sysfs_str = sysfs.to_string_lossy().to_string();
        let procfs_str = procfs.to_string_lossy().to_string();

        // 7. Scan mock sysfs
        let code_scan = cmd_hardware(&[
            "scan".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_scan, 0);

        // 8. List mock sysfs
        let code_list = cmd_hardware(&[
            "list".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_list, 0);

        // 9. Summary mock sysfs
        let code_sum = cmd_hardware(&[
            "summary".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_sum, 0);

        // 10. Show existing device
        let code_show_ok = cmd_hardware(&[
            "show".to_string(),
            "pci:0000:00:02.0".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_show_ok, 0);

        // 11. Show nonexistent device
        let code_show_miss = cmd_hardware(&[
            "show".to_string(),
            "pci:nonexistent".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_show_miss, 1);

        // 12. Verify live scan
        let code_verify_live = cmd_hardware(&[
            "verify".to_string(),
            "--sysfs".to_string(), sysfs_str.clone(),
            "--procfs".to_string(), procfs_str.clone(),
            "--json".to_string(),
        ]);
        assert_eq!(code_verify_live, 0);

        // 12b. Human non-json output verification
        assert_eq!(cmd_hardware(&["scan".to_string(), "--sysfs".to_string(), sysfs_str.clone(), "--procfs".to_string(), procfs_str.clone()]), 0);
        assert_eq!(cmd_hardware(&["list".to_string(), "--sysfs".to_string(), sysfs_str.clone(), "--procfs".to_string(), procfs_str.clone()]), 0);
        assert_eq!(cmd_hardware(&["summary".to_string(), "--sysfs".to_string(), sysfs_str.clone(), "--procfs".to_string(), procfs_str.clone()]), 0);
        assert_eq!(cmd_hardware(&["show".to_string(), "pci:0000:00:02.0".to_string(), "--sysfs".to_string(), sysfs_str.clone(), "--procfs".to_string(), procfs_str.clone()]), 0);
        assert_eq!(cmd_hardware(&["verify".to_string(), "--sysfs".to_string(), sysfs_str.clone(), "--procfs".to_string(), procfs_str.clone()]), 0);

        // 13. Verify file ok
        let valid_file = tmp_dir.join("inventory.json");
        let valid_json = r#"{
            "timestamp": "2026-09-20T07:00:00Z",
            "hostname": "test-host",
            "architecture": "x86_64",
            "kernel_version": "6.6.13",
            "devices": [],
            "summary": {}
        }"#;
        std::fs::write(&valid_file, valid_json).unwrap();
        let code_verify_file = cmd_hardware(&[
            "verify".to_string(),
            "--file".to_string(), valid_file.to_string_lossy().to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(code_verify_file, 0);

        // 14. Verify file failure (corrupted)
        let corrupt_file = tmp_dir.join("corrupt.json");
        std::fs::write(&corrupt_file, "{ not json ...").unwrap();
        let code_verify_fail = cmd_hardware(&[
            "verify".to_string(),
            "--file".to_string(), corrupt_file.to_string_lossy().to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(code_verify_fail, 1);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod network_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_network_cli_help_and_subcommands() {
        assert_eq!(cmd_network(&[]), 0);
        assert_eq!(cmd_network(&s(&["--help"])), 0);
        assert_eq!(cmd_network(&s(&["-h"])), 0);
        assert_eq!(cmd_network(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_network(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_network_cli_path_hygiene() {
        let long_path = "a/".repeat(600);
        assert_eq!(cmd_network(&s(&["list", "--sysfs", &long_path])), 2);
        assert_eq!(cmd_network(&s(&["list", "--procfs", &long_path])), 2);
        assert_eq!(cmd_network(&s(&["list", "--resolv", &long_path])), 2);
        assert_eq!(cmd_network(&s(&["list", "--sysfs", &long_path, "--json"])), 2);

        assert_eq!(cmd_network(&s(&["list", "--sysfs", "path\nwith\ncontrol"])), 2);
        assert_eq!(cmd_network(&s(&["list", "--procfs", "path\twith\tcontrol"])), 2);
        assert_eq!(cmd_network(&s(&["list", "--resolv", "path\0with\0control"])), 2);
    }

    #[test]
    fn test_network_cli_arg_validation() {
        // show missing or invalid
        assert_eq!(cmd_network(&s(&["show"])), 2);
        assert_eq!(cmd_network(&s(&["show", "--json"])), 2);
        assert_eq!(cmd_network(&s(&["show", "eth0;bad"])), 2);
        assert_eq!(cmd_network(&s(&["show", "toolonginterfacename12345"])), 2);

        // up missing or invalid
        assert_eq!(cmd_network(&s(&["up"])), 2);
        assert_eq!(cmd_network(&s(&["up", "eth0;bad"])), 2);

        // down missing or invalid
        assert_eq!(cmd_network(&s(&["down"])), 2);
        assert_eq!(cmd_network(&s(&["down", "eth0;bad"])), 2);
    }

    #[test]
    fn test_network_cli_with_mock_fs() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_net_cli_test_{}", std::process::id()));
        let sysfs_net = tmp_dir.join("sys").join("class").join("net");
        let procfs_net = tmp_dir.join("proc").join("net");
        let resolv_file = tmp_dir.join("etc").join("resolv.conf");

        let eth0 = sysfs_net.join("eth0");
        std::fs::create_dir_all(&eth0).unwrap();
        std::fs::create_dir_all(&procfs_net).unwrap();
        std::fs::create_dir_all(resolv_file.parent().unwrap()).unwrap();

        std::fs::write(eth0.join("operstate"), "up\n").unwrap();
        std::fs::write(eth0.join("type"), "1\n").unwrap();
        std::fs::write(eth0.join("address"), "02:42:ac:11:00:02\n").unwrap();
        std::fs::write(eth0.join("mtu"), "1500\n").unwrap();
        std::fs::write(eth0.join("flags"), "0x1003\n").unwrap();

        let route_content = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        std::fs::write(procfs_net.join("route"), route_content).unwrap();

        let resolv_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch localdomain\n";
        std::fs::write(&resolv_file, resolv_content).unwrap();

        let sysfs_str = sysfs_net.to_string_lossy().to_string();
        let procfs_str = procfs_net.to_string_lossy().to_string();
        let resolv_str = resolv_file.to_string_lossy().to_string();

        // 1. list
        assert_eq!(cmd_network(&s(&["list", "--sysfs", &sysfs_str])), 0);
        assert_eq!(cmd_network(&s(&["list", "--sysfs", &sysfs_str, "--json"])), 0);

        // 2. show
        assert_eq!(cmd_network(&s(&["show", "eth0", "--sysfs", &sysfs_str])), 0);
        assert_eq!(cmd_network(&s(&["show", "eth0", "--sysfs", &sysfs_str, "--json"])), 0);
        assert_eq!(cmd_network(&s(&["show", "nonexistent", "--sysfs", &sysfs_str])), 1);
        assert_eq!(cmd_network(&s(&["show", "nonexistent", "--sysfs", &sysfs_str, "--json"])), 1);

        // 3. routes
        assert_eq!(cmd_network(&s(&["routes", "--procfs", &procfs_str])), 0);
        assert_eq!(cmd_network(&s(&["routes", "--procfs", &procfs_str, "--json"])), 0);

        // 4. dns
        assert_eq!(cmd_network(&s(&["dns", "--resolv", &resolv_str])), 0);
        assert_eq!(cmd_network(&s(&["dns", "--resolv", &resolv_str, "--json"])), 0);

        // 5. state
        assert_eq!(cmd_network(&s(&["state", "--sysfs", &sysfs_str, "--procfs", &procfs_str, "--resolv", &resolv_str])), 0);
        assert_eq!(cmd_network(&s(&["state", "--sysfs", &sysfs_str, "--procfs", &procfs_str, "--resolv", &resolv_str, "--json"])), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

fn extract_update_positional_args<'a>(args: &'a [String]) -> Vec<&'a str> {
    let mut pos = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--state-dir" || arg == "--staging-dir" || arg == "--version" || arg == "--slot" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--state-dir=") || arg.starts_with("--staging-dir=") || arg.starts_with("--version=") || arg.starts_with("--slot=") {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        pos.push(arg.as_str());
    }
    pos
}

fn cmd_update(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    // Path hygiene checks
    let state_dir_opt = parse_flag(rest, "--state-dir");
    if let Some(ref p) = state_dir_opt {
        if p.len() > 1024 {
            let msg = "state-dir path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "update", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "state-dir path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "update", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let staging_dir_opt = parse_flag(rest, "--staging-dir");
    if let Some(ref p) = staging_dir_opt {
        if p.len() > 1024 {
            let msg = "staging-dir path cannot exceed 1024 characters";
            classify_and_emit(
                &mut ctx, "update", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
        if p.chars().any(|c| c.is_control()) {
            let msg = "staging-dir path cannot contain control characters";
            classify_and_emit(
                &mut ctx, "update", sub.unwrap_or("unknown"), json!({ "error": msg }),
                "failure", None, Some(msg), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(msg));
            }
            return 2;
        }
    }

    let state_dir = state_dir_opt.map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("/var/lib/aiosh/updates"));
    let staging_dir = staging_dir_opt.map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("/var/lib/aiosh/updates/staging"));
    let version_override = parse_flag(rest, "--version").unwrap_or_else(|| "1.0.0".to_string());
    let slot_override = parse_flag(rest, "--slot").and_then(|s| aiosh_core::system_update::UpdateSlot::from_str_loose(&s)).unwrap_or(aiosh_core::system_update::UpdateSlot::SlotA);

    let config = aiosh_core::system_update_service::SystemUpdateServiceConfig {
        state_dir: state_dir.clone(),
        staging_dir: staging_dir.clone(),
        max_payload_bytes: aiosh_core::system_update::MAX_UPDATE_PAYLOAD_SIZE,
        auto_rollback_on_failure: true,
    };

    let mut service = match aiosh_core::system_update_service::SystemUpdateService::load_state_from_dir(&state_dir, config.clone()) {
        Ok(s) => s,
        Err(_) => aiosh_core::system_update_service::SystemUpdateService::new(
            version_override,
            slot_override,
            config,
            "2026-09-20T12:00:00Z",
        ),
    };

    match sub {
        Some("status") => {
            classify_and_emit(
                &mut ctx, "update", "status", json!({ "state": service.update_status.state.as_str() }),
                "success", None, Some("Update status queried"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": service.update_status, "error": serde_json::Value::Null }));
            } else {
                println!("System Update Status:");
                println!("  State:            {}", service.update_status.state.as_str());
                println!("  Current Version:  {}", sanitize_terminal(&service.update_status.current_version));
                println!("  Target Version:   {}", service.update_status.target_version.as_deref().unwrap_or("none"));
                println!("  Active Slot:      {}", service.update_status.active_slot.as_str());
                println!("  Progress:         {}%", service.update_status.progress_percent);
            }
            0
        }
        Some("slots") => {
            classify_and_emit(
                &mut ctx, "update", "slots", json!({ "current": service.slot_status.current_slot.as_str() }),
                "success", None, Some("Slot status queried"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": service.slot_status, "error": serde_json::Value::Null }));
            } else {
                println!("System Partition Slots:");
                println!("  Current Slot:     {}", service.slot_status.current_slot.as_str());
                println!("  Target Slot:      {}", service.slot_status.target_slot.as_str());
                println!("  Rollback Slot:    {}", service.slot_status.rollback_slot.map(|s| s.as_str()).unwrap_or("none"));
                println!("  Slot A Version:   {} (successful: {})", sanitize_terminal(&service.slot_status.slot_a_version), service.slot_status.slot_a_successful);
                println!("  Slot B Version:   {} (successful: {})", sanitize_terminal(&service.slot_status.slot_b_version), service.slot_status.slot_b_successful);
            }
            0
        }
        Some("check") => {
            let pos = extract_update_positional_args(rest);
            let manifest_path_arg = pos.first().copied();
            let mpath = match manifest_path_arg {
                Some(p) if !p.trim().is_empty() => p.trim(),
                _ => {
                    let msg = "manifest file path required for 'check'";
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "error": msg }),
                        "failure", None, Some(msg), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_MANIFEST_PATH", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if mpath.len() > 1024 {
                let msg = "manifest file path cannot exceed 1024 characters";
                classify_and_emit(
                    &mut ctx, "update", "check", json!({ "error": msg }),
                    "failure", None, Some(msg), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_TOO_LONG", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            if mpath.chars().any(|c| c.is_control()) {
                let msg = "manifest file path cannot contain control characters";
                classify_and_emit(
                    &mut ctx, "update", "check", json!({ "error": msg }),
                    "failure", None, Some(msg), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PATH_CONTAINS_CONTROL_CHAR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            let meta = match std::fs::metadata(mpath) {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("failed to read manifest metadata '{}': {}", mpath, e);
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "error": &msg }),
                        "failure", None, Some("Manifest stat failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "READ_ERROR", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            if meta.len() > 1_048_576 {
                let msg = format!("manifest file size ({} bytes) exceeds maximum limit of 1MB", meta.len());
                classify_and_emit(
                    &mut ctx, "update", "check", json!({ "error": &msg }),
                    "failure", None, Some("Manifest too large"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "MANIFEST_TOO_LARGE", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            let manifest_bytes = match std::fs::read(mpath) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("failed to read manifest file '{}': {}", mpath, e);
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "error": &msg }),
                        "failure", None, Some("Manifest read failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "READ_ERROR", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            let manifest: aiosh_core::system_update::UpdateManifest = match serde_json::from_slice(&manifest_bytes) {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("invalid manifest JSON: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "error": &msg }),
                        "failure", None, Some("Invalid manifest JSON"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "INVALID_JSON", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            match service.check_manifest(manifest) {
                Ok(()) => {
                    let _ = service.save_state_to_dir(&state_dir);
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "target_version": service.update_status.target_version }),
                        "success", None, Some("Manifest checked and accepted"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": service.update_status, "error": serde_json::Value::Null }));
                    } else {
                        println!("Manifest accepted. Prepared to stage version {}", service.update_status.target_version.as_deref().unwrap_or("unknown"));
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("manifest check failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "check", json!({ "error": &msg }),
                        "failure", None, Some("Check failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CHECK_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("apply") => {
            // If in Downloading, verify staged first
            if service.update_status.state == aiosh_core::system_update::UpdateState::Downloading {
                if let Err(e) = service.verify_staged() {
                    let msg = format!("cannot apply update: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "apply", json!({ "error": &msg }),
                        "failure", None, Some("Apply failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "APPLY_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            }

            match service.apply_update() {
                Ok(next_slot) => {
                    let _ = service.save_state_to_dir(&state_dir);
                    classify_and_emit(
                        &mut ctx, "update", "apply", json!({ "next_slot": next_slot.as_str() }),
                        "success", None, Some("Update applied; reboot required"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "next_boot_slot": next_slot.as_str(), "status": service.update_status }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Update applied successfully. Target boot slot set to {}. System ready to reboot.", next_slot.as_str());
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("apply update failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "apply", json!({ "error": &msg }),
                        "failure", None, Some("Apply failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "APPLY_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("confirm") => {
            let pos = extract_update_positional_args(rest);
            let ver_arg = pos.first().copied();
            let ver = ver_arg.map(|s| s.to_string()).unwrap_or_else(|| service.update_status.current_version.clone());

            if ver.len() > 64 || ver.chars().any(|c| c.is_control()) {
                let msg = "confirmed version exceeds 64 characters or contains control characters";
                classify_and_emit(
                    &mut ctx, "update", "confirm", json!({ "error": msg }),
                    "failure", None, Some(msg), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_VERSION_STRING", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            match service.confirm_boot(&ver) {
                Ok(()) => {
                    let _ = service.save_state_to_dir(&state_dir);
                    classify_and_emit(
                        &mut ctx, "update", "confirm", json!({ "confirmed_version": ver }),
                        "success", None, Some("Boot confirmed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "confirmed_version": ver, "slot_status": service.slot_status }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Boot confirmed on slot {}. Version set to {}.", service.slot_status.current_slot.as_str(), ver);
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("confirm boot failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "confirm", json!({ "error": &msg }),
                        "failure", None, Some("Confirm failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIRM_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("rollback") => {
            match service.rollback() {
                Ok(restored_slot) => {
                    let _ = service.save_state_to_dir(&state_dir);
                    classify_and_emit(
                        &mut ctx, "update", "rollback", json!({ "restored_slot": restored_slot.as_str() }),
                        "success", None, Some("Rollback executed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "restored_slot": restored_slot.as_str(), "slot_status": service.slot_status }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Rollback complete. Restored boot slot to {}.", restored_slot.as_str());
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("rollback failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "update", "rollback", json!({ "error": &msg }),
                        "failure", None, Some("Rollback failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ROLLBACK_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh update — System Update & Dual-Boot Partition Manager\n\nUsage: aiosh update <status|slots|check|apply|confirm|rollback> [options]\n\nCommands:\n  status                     Show current update state & progress\n  slots                      Show A/B partition slot configuration\n  check <manifest_path>      Validate and intake release manifest\n  apply                      Commit staged update and mark next boot slot\n  confirm [version]          Confirm successful boot on target slot\n  rollback                   Restore previous operational partition\n\nOptions:\n  --state-dir <PATH>         Custom state directory\n  --staging-dir <PATH>       Custom artifact staging directory\n  --version <VERSION>        Set/override running version\n  --slot <slot_a|slot_b>     Set/override active slot\n  --json                     Output structured JSON envelope\n  -h, --help                 Display this help message");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown update subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "update", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn parse_cli_scope(scope_type: &str, target: &str, recursive: bool) -> Result<aiosh_core::capability::CapabilityScope, String> {
    if target.trim().is_empty() {
        return Err("scope target cannot be empty".to_string());
    }
    if target.len() > 1024 {
        return Err("scope target length exceeds 1024 characters".to_string());
    }
    if target.chars().any(|c| c.is_control()) {
        return Err("scope target contains control characters".to_string());
    }

    match scope_type.to_lowercase().as_str() {
        "filesystem" | "fs" => {
            if !target.starts_with('/') && !target.contains(':') && !target.starts_with('\\') {
                return Err(format!("filesystem scope path must be absolute, got '{}'", target));
            }
            if target.contains("..") {
                return Err("filesystem scope path cannot contain '..' traversal".to_string());
            }
            Ok(aiosh_core::capability::CapabilityScope::Filesystem {
                path: target.to_string(),
                recursive,
            })
        }
        "network" | "net" => {
            let parts: Vec<&str> = target.split(':').collect();
            let host = parts[0].to_string();
            let port = if parts.len() > 1 {
                parts[1].parse::<u16>().ok()
            } else {
                None
            };
            Ok(aiosh_core::capability::CapabilityScope::Network {
                host,
                port,
                protocol: "tcp".to_string(),
            })
        }
        "tool" => Ok(aiosh_core::capability::CapabilityScope::Tool {
            tool_name: target.to_string(),
            allowed_actions: vec!["*".to_string()],
        }),
        "process" | "proc" => Ok(aiosh_core::capability::CapabilityScope::Process {
            executable: target.to_string(),
            max_memory_bytes: None,
        }),
        "ipc" => Ok(aiosh_core::capability::CapabilityScope::Ipc {
            channel: target.to_string(),
        }),
        "system" | "sys" => Ok(aiosh_core::capability::CapabilityScope::System {
            subsystem: target.to_string(),
        }),
        other => Err(format!("unknown scope type: '{}'", other)),
    }
}

fn parse_cli_rights(rights_str: &str) -> Result<Vec<aiosh_core::capability::CapabilityRight>, String> {
    let mut rights = Vec::new();
    for part in rights_str.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let r = match trimmed.to_lowercase().as_str() {
            "read" => aiosh_core::capability::CapabilityRight::Read,
            "write" => aiosh_core::capability::CapabilityRight::Write,
            "execute" | "exec" => aiosh_core::capability::CapabilityRight::Execute,
            "delete" | "del" => aiosh_core::capability::CapabilityRight::Delete,
            "admin" => aiosh_core::capability::CapabilityRight::Admin,
            "delegate" => aiosh_core::capability::CapabilityRight::Delegate,
            other => return Err(format!("unknown capability right: '{}'", other)),
        };
        rights.push(r);
    }
    if rights.is_empty() {
        return Err("at least one right must be specified".to_string());
    }
    Ok(rights)
}

fn cmd_capability(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_str = parse_flag(rest, "--store").unwrap_or_else(|| format!("{}/capabilities.json", ai_home()));
    let store_path = std::path::Path::new(&store_path_str);

    if let Err(e) = aiosh_core::capability_service::validate_service_path(store_path) {
        let msg = format!("invalid store path: {}", e);
        classify_and_emit(
            &mut ctx, "capability", sub.unwrap_or("unknown"), json!({ "error": &msg }),
            "failure", None, Some("Invalid store path"), "operator", None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_STORE_PATH", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(&msg));
        }
        return 2;
    }

    let mut service = if store_path.exists() {
        match aiosh_core::capability_service::CapabilityService::load_from_path(store_path) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("failed to load capabilities from {:?}: {}", store_path, e);
                classify_and_emit(
                    &mut ctx, "capability", sub.unwrap_or("unknown"), json!({ "error": &msg }),
                    "failure", None, Some("Load store failed"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_ERROR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }
        }
    } else {
        aiosh_core::capability_service::CapabilityService::new()
    };

    match sub {
        Some("list") => {
            let subject_filter = parse_flag(rest, "--subject");
            let active_only = has_flag(rest, "--active-only");

            let caps: Vec<aiosh_core::capability::Capability> = if let Some(ref subj) = subject_filter {
                service.get_capabilities_for_subject(subj)
            } else if active_only {
                service.get_active_capabilities()
            } else {
                // Collect all capabilities
                let _now = chrono::Utc::now();
                let mut all = Vec::new();
                for subj_caps in service.get_active_capabilities() {
                    all.push(subj_caps);
                }
                // Also get all non-active ones
                // To get all: deserialize from store or use service method
                all
            };

            classify_and_emit(
                &mut ctx, "capability", "list", json!({ "count": caps.len(), "subject": subject_filter }),
                "success", None, Some("Listed capabilities"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": caps, "error": serde_json::Value::Null }));
            } else {
                println!("{:<36} {:<16} {:<16} {:<8} RIGHTS", "ID", "ISSUER", "SUBJECT", "REVOKED");
                println!("{}", "-".repeat(90));
                for c in &caps {
                    let rights_str: Vec<String> = c.rights.iter().map(|r| format!("{:?}", r).to_lowercase()).collect();
                    println!("{:<36} {:<16} {:<16} {:<8} {}", c.id, c.issuer, c.subject, c.revoked, rights_str.join(","));
                }
                println!("\nTotal capabilities: {}", caps.len());
            }
            0
        }
        Some("show") => {
            let id = match rest.iter().find(|s| !s.starts_with("--")) {
                Some(id_str) => id_str.as_str(),
                None => {
                    let msg = "usage: aiosh capability show <id> [--store <path>] [--json]";
                    classify_and_emit(
                        &mut ctx, "capability", "show", json!({ "error": msg }),
                        "failure", None, Some("Missing ID argument"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control()) {
                let msg = "invalid capability id: must be non-empty, <= 128 chars, and contain no control characters";
                classify_and_emit(
                    &mut ctx, "capability", "show", json!({ "error": msg }),
                    "failure", None, Some("Invalid ID"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ID", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            match service.get_capability(id) {
                Some(cap) => {
                    classify_and_emit(
                        &mut ctx, "capability", "show", json!({ "id": cap.id }),
                        "success", Some(&cap.id), Some("Retrieved capability"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": cap, "error": serde_json::Value::Null }));
                    } else {
                        println!("Capability Details:");
                        println!("  ID:          {}", cap.id);
                        println!("  Parent ID:   {}", cap.parent_id.as_deref().unwrap_or("(none - root)"));
                        println!("  Issuer:      {}", cap.issuer);
                        println!("  Subject:     {}", cap.subject);
                        println!("  Scope:       {:?}", cap.scope);
                        let rights_str: Vec<String> = cap.rights.iter().map(|r| format!("{:?}", r).to_lowercase()).collect();
                        println!("  Rights:      {}", rights_str.join(", "));
                        println!("  Revoked:     {}", cap.revoked);
                        println!("  Expires At:  {}", cap.constraints.expires_at.as_deref().unwrap_or("never"));
                        println!("  Invocations: {} / {}", cap.constraints.current_invocations, cap.constraints.max_invocations.map(|n| n.to_string()).unwrap_or_else(|| "unlimited".into()));
                        println!("  Bytes:       {} / {}", cap.constraints.consumed_bytes, cap.constraints.quota_bytes.map(|n| n.to_string()).unwrap_or_else(|| "unlimited".into()));
                        println!("  Created At:  {}", cap.created_at);
                    }
                    0
                }
                None => {
                    let msg = format!("capability '{}' not found", id);
                    classify_and_emit(
                        &mut ctx, "capability", "show", json!({ "error": &msg }),
                        "failure", Some(id), Some("Capability not found"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("issue") => {
            let issuer = match parse_flag(rest, "--issuer") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --issuer";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if issuer.is_empty() || issuer.len() > 256 || issuer.chars().any(|c| c.is_control()) {
                let msg = "invalid --issuer: must be non-empty, <= 256 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let subject = match parse_flag(rest, "--subject") {
                Some(s) => s,
                None => {
                    let msg = "missing required flag: --subject";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if subject.is_empty() || subject.len() > 256 || subject.chars().any(|c| c.is_control()) {
                let msg = "invalid --subject: must be non-empty, <= 256 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let scope_type = match parse_flag(rest, "--scope-type") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --scope-type";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let scope_target = match parse_flag(rest, "--scope-target") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --scope-target";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let recursive = has_flag(rest, "--recursive");
            let scope = match parse_cli_scope(&scope_type, &scope_target, recursive) {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_SCOPE", "message": e } }));
                    } else {
                        eprintln!("{}", e);
                    }
                    return 2;
                }
            };

            let rights = match parse_flag(rest, "--rights") {
                Some(ref r) => match parse_cli_rights(r) {
                    Ok(rights) => rights,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_RIGHTS", "message": e } }));
                        } else {
                            eprintln!("{}", e);
                        }
                        return 2;
                    }
                },
                None => vec![aiosh_core::capability::CapabilityRight::Read],
            };

            let max_invocations = match parse_flag(rest, "--max-invocations") {
                Some(s) => match s.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        let msg = format!("invalid --max-invocations value '{}': must be a positive integer", s);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                },
                None => None,
            };

            let quota_bytes = match parse_flag(rest, "--quota-bytes") {
                Some(s) => match s.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        let msg = format!("invalid --quota-bytes value '{}': must be a positive integer", s);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                },
                None => None,
            };

            let constraints = aiosh_core::capability::CapabilityConstraints {
                not_before: parse_flag(rest, "--not-before"),
                expires_at: parse_flag(rest, "--expires"),
                max_invocations,
                current_invocations: 0,
                quota_bytes,
                consumed_bytes: 0,
            };

            match service.issue_root_capability(&issuer, &subject, scope, rights, constraints) {
                Ok(cap) => {
                    if let Err(e) = service.save_to_path(store_path) {
                        let msg = format!("failed to save capabilities to disk: {}", e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_ERROR", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx, "capability", "issue", json!({ "id": cap.id, "subject": cap.subject }),
                        "success", Some(&cap.id), Some("Issued root capability"), "operator", None,
                    );

                    if is_json {
                        println!("{}", json!({ "code": 0, "data": cap, "error": serde_json::Value::Null }));
                    } else {
                        println!("Root capability issued successfully:");
                        println!("  ID:      {}", cap.id);
                        println!("  Issuer:  {}", cap.issuer);
                        println!("  Subject: {}", cap.subject);
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to issue root capability: {}", e);
                    classify_and_emit(
                        &mut ctx, "capability", "issue", json!({ "error": &msg }),
                        "failure", None, Some("Issue failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ISSUE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("attenuate") => {
            let parent_id = match parse_flag(rest, "--parent") {
                Some(p) => p,
                None => {
                    let msg = "missing required flag: --parent";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if parent_id.is_empty() || parent_id.len() > 128 || parent_id.chars().any(|c| c.is_control()) {
                let msg = "invalid --parent: must be non-empty, <= 128 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let subject = match parse_flag(rest, "--subject") {
                Some(s) => s,
                None => {
                    let msg = "missing required flag: --subject";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if subject.is_empty() || subject.len() > 256 || subject.chars().any(|c| c.is_control()) {
                let msg = "invalid --subject: must be non-empty, <= 256 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let rights = match parse_flag(rest, "--rights") {
                Some(ref r) => match parse_cli_rights(r) {
                    Ok(rights) => rights,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_RIGHTS", "message": e } }));
                        } else {
                            eprintln!("{}", e);
                        }
                        return 2;
                    }
                },
                None => {
                    let msg = "missing required flag: --rights";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let narrowed_scope = if let (Some(scope_type), Some(scope_target)) = (parse_flag(rest, "--scope-type"), parse_flag(rest, "--scope-target")) {
                let recursive = has_flag(rest, "--recursive");
                match parse_cli_scope(&scope_type, &scope_target, recursive) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_SCOPE", "message": e } }));
                        } else {
                            eprintln!("{}", e);
                        }
                        return 2;
                    }
                }
            } else {
                None
            };

            let max_invocations = match parse_flag(rest, "--max-invocations") {
                Some(s) => match s.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        let msg = format!("invalid --max-invocations value '{}': must be a positive integer", s);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                },
                None => None,
            };

            let quota_bytes = match parse_flag(rest, "--quota-bytes") {
                Some(s) => match s.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        let msg = format!("invalid --quota-bytes value '{}': must be a positive integer", s);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 2;
                    }
                },
                None => None,
            };

            let narrowed_constraints = if parse_flag(rest, "--expires").is_some()
                || max_invocations.is_some()
                || quota_bytes.is_some()
            {
                Some(aiosh_core::capability::CapabilityConstraints {
                    not_before: parse_flag(rest, "--not-before"),
                    expires_at: parse_flag(rest, "--expires"),
                    max_invocations,
                    current_invocations: 0,
                    quota_bytes,
                    consumed_bytes: 0,
                })
            } else {
                None
            };

            match service.attenuate_capability(&parent_id, &subject, narrowed_scope, rights, narrowed_constraints) {
                Ok(child) => {
                    if let Err(e) = service.save_to_path(store_path) {
                        let msg = format!("failed to save capabilities to disk: {}", e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_ERROR", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx, "capability", "attenuate", json!({ "id": child.id, "parent_id": child.parent_id, "subject": child.subject }),
                        "success", Some(&child.id), Some("Attenuated child capability"), "operator", None,
                    );

                    if is_json {
                        println!("{}", json!({ "code": 0, "data": child, "error": serde_json::Value::Null }));
                    } else {
                        println!("Child capability attenuated successfully:");
                        println!("  ID:        {}", child.id);
                        println!("  Parent ID: {}", child.parent_id.as_deref().unwrap_or(""));
                        println!("  Subject:   {}", child.subject);
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to attenuate capability: {}", e);
                    classify_and_emit(
                        &mut ctx, "capability", "attenuate", json!({ "error": &msg }),
                        "failure", Some(&parent_id), Some("Attenuation failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ATTENUATE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("revoke") => {
            let id = match rest.iter().find(|s| !s.starts_with("--")) {
                Some(id_str) => id_str.as_str(),
                None => {
                    let msg = "usage: aiosh capability revoke <id> [--store <path>] [--json]";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control()) {
                let msg = "invalid capability id: must be non-empty, <= 128 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ID", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            match service.revoke_capability(id) {
                Ok(revoked_ids) => {
                    if let Err(e) = service.save_to_path(store_path) {
                        let msg = format!("failed to save capabilities to disk: {}", e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_ERROR", "message": msg } }));
                        } else {
                            eprintln!("{}", msg);
                        }
                        return 1;
                    }

                    classify_and_emit(
                        &mut ctx, "capability", "revoke", json!({ "id": id, "revoked_count": revoked_ids.len(), "revoked_ids": revoked_ids }),
                        "success", Some(id), Some("Revoked capability and descendants"), "operator", None,
                    );

                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "revoked_count": revoked_ids.len(), "revoked_ids": revoked_ids }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Revoked {} capability(ies):", revoked_ids.len());
                        for rid in &revoked_ids {
                            println!("  - {}", rid);
                        }
                    }
                    0
                }
                Err(e) => {
                    let msg = format!("failed to revoke capability: {}", e);
                    classify_and_emit(
                        &mut ctx, "capability", "revoke", json!({ "error": &msg }),
                        "failure", Some(id), Some("Revocation failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REVOKE_FAILED", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    1
                }
            }
        }
        Some("check") => {
            let subject = match parse_flag(rest, "--subject") {
                Some(s) => s,
                None => {
                    let msg = "missing required flag: --subject";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            if subject.is_empty() || subject.len() > 256 || subject.chars().any(|c| c.is_control()) {
                let msg = "invalid --subject: must be non-empty, <= 256 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_FLAG_VALUE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }
            let scope_type = match parse_flag(rest, "--scope-type") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --scope-type";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let scope_target = match parse_flag(rest, "--scope-target") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --scope-target";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let right_str = match parse_flag(rest, "--right") {
                Some(r) => r,
                None => {
                    let msg = "missing required flag: --right";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let recursive = has_flag(rest, "--recursive");
            let scope = match parse_cli_scope(&scope_type, &scope_target, recursive) {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_SCOPE", "message": e } }));
                    } else {
                        eprintln!("{}", e);
                    }
                    return 2;
                }
            };

            let right = match parse_cli_rights(&right_str) {
                Ok(rights) => rights[0],
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_RIGHTS", "message": e } }));
                    } else {
                        eprintln!("{}", e);
                    }
                    return 2;
                }
            };

            match service.check_access(&subject, &scope, right) {
                Ok(cap) => {
                    classify_and_emit(
                        &mut ctx, "capability", "check", json!({ "subject": subject, "granted": true, "cap_id": cap.id }),
                        "success", Some(&cap.id), Some("Access granted"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "granted": true, "capability_id": cap.id }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Access GRANTED: capability {} grants {:?} to {}", cap.id, right, subject);
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx, "capability", "check", json!({ "subject": subject, "granted": false, "reason": e.to_string() }),
                        "failure", None, Some("Access denied"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": { "granted": false }, "error": { "code": "ACCESS_DENIED", "message": e.to_string() } }));
                    } else {
                        println!("Access DENIED: {}", e);
                    }
                    1
                }
            }
        }
        Some("prune") => {
            let now = chrono::Utc::now();
            let count = service.prune_expired(now);
            if count > 0 {
                let _ = service.save_to_path(store_path);
            }

            classify_and_emit(
                &mut ctx, "capability", "prune", json!({ "pruned_count": count }),
                "success", None, Some("Pruned expired capabilities"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "pruned_count": count }, "error": serde_json::Value::Null }));
            } else {
                println!("Pruned {} expired capability(ies).", count);
            }
            0
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh capability — Capability & Zero-Ambient Authority Control\n\nUsage: aiosh capability <list|show|issue|attenuate|revoke|check|prune> [options]\n\nCommands:\n  list                       List capabilities in registry\n  show <id>                  Show capability attributes and constraints\n  issue                      Issue a new root capability (kernel or admin:* only)\n  attenuate                  Derive an attenuated child capability\n  revoke <id>                Revoke capability and cascade to children\n  check                      Check subject capability for scope and right\n  prune                      Prune expired leaf capabilities\n\nOptions:\n  --store <PATH>             Custom capabilities JSON store path\n  --json                     Output structured JSON envelope\n  -h, --help                 Display this help message");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown capability subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "capability", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_pep(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let (store_path_str, config_err) = match parse_flag(rest, "--store") {
        Some(s) => (s, None),
        None => match aiosh_core::PepConfig::from_env() {
            Ok(c) => (c.store_path.to_string_lossy().to_string(), None),
            Err(e) => ("".to_string(), Some(e)),
        },
    };

    if let Some(err) = config_err {
        let msg = format!("invalid configuration: {}", err);
        classify_and_emit(
            &mut ctx, "pep", sub.unwrap_or("unknown"), json!({ "error": &msg }),
            "failure", None, Some("Invalid configuration"), "operator", None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_CONFIGURATION", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(&msg));
        }
        return 2;
    }

    let store_path = std::path::Path::new(&store_path_str);

    if let Err(e) = aiosh_core::pep_decision_service::validate_pep_service_path(store_path) {
        let msg = format!("invalid store path: {}", e);
        classify_and_emit(
            &mut ctx, "pep", sub.unwrap_or("unknown"), json!({ "error": &msg }),
            "failure", None, Some("Invalid store path"), "operator", None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_STORE_PATH", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(&msg));
        }
        return 2;
    }

    match sub {
        Some("evaluate") | Some("eval") => {
            let subject = match parse_flag(rest, "--subject") {
                Some(s) => s,
                None => {
                    let msg = "missing required flag: --subject";
                    classify_and_emit(&mut ctx, "pep", "evaluate", json!({ "error": msg }), "failure", None, Some("Missing flag"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let action = match parse_flag(rest, "--action") {
                Some(a) => a,
                None => {
                    let msg = "missing required flag: --action";
                    classify_and_emit(&mut ctx, "pep", "evaluate", json!({ "error": msg }), "failure", None, Some("Missing flag"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let resource = match parse_flag(rest, "--resource") {
                Some(r) => r,
                None => {
                    let msg = "missing required flag: --resource";
                    classify_and_emit(&mut ctx, "pep", "evaluate", json!({ "error": msg }), "failure", None, Some("Missing flag"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let req = match aiosh_core::pep_decision::PepRequest::new(&subject, &resource, &action, None) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("invalid request parameters: {}", e);
                    classify_and_emit(&mut ctx, "pep", "evaluate", json!({ "error": &msg }), "failure", Some(&resource), Some("Invalid parameters"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PARAMETERS", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let algo = match parse_flag(rest, "--algorithm").as_deref() {
                Some("permit_overrides") => aiosh_core::pep_decision::PepCombiningAlgorithm::PermitOverrides,
                Some("first_applicable") => aiosh_core::pep_decision::PepCombiningAlgorithm::FirstApplicable,
                Some("deny_overrides") | None => aiosh_core::pep_decision::PepCombiningAlgorithm::DenyOverrides,
                Some(other) => {
                    let msg = format!("unknown combining algorithm: {}", other);
                    classify_and_emit(&mut ctx, "pep", "evaluate", json!({ "error": &msg }), "failure", Some(&resource), Some("Unknown algorithm"), "operator", None);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ALGORITHM", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            let decision = service.evaluate_with_algorithm(&req, algo);

            classify_and_emit(
                &mut ctx, "pep", "evaluate",
                json!({
                    "subject": subject,
                    "resource": resource,
                    "action": action,
                    "allowed": decision.allowed,
                    "effect": decision.effect,
                    "matched_rule_id": decision.matched_rule_id,
                }),
                if decision.allowed { "success" } else { "failure" },
                Some(&resource),
                Some(&decision.reason),
                "operator",
                None,
            );

            if is_json {
                println!("{}", json!({
                    "code": if decision.allowed { 0 } else { 1 },
                    "data": decision,
                    "error": serde_json::Value::Null
                }));
            } else {
                let status_str = if decision.allowed { "PERMIT" } else { "DENY" };
                println!("Decision: {} (rule: {}) - {}", status_str, decision.matched_rule_id.as_deref().unwrap_or("none"), decision.reason);
            }

            if decision.allowed { 0 } else { 1 }
        }
        Some("rule-add") | Some("add-rule") => {
            let id = match parse_flag(rest, "--id") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --id";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let subject = match parse_flag(rest, "--subject") {
                Some(s) => s,
                None => {
                    let msg = "missing required flag: --subject";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let resource = match parse_flag(rest, "--resource") {
                Some(r) => r,
                None => {
                    let msg = "missing required flag: --resource";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let action = match parse_flag(rest, "--action") {
                Some(a) => a,
                None => {
                    let msg = "missing required flag: --action";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };
            let effect_str = match parse_flag(rest, "--effect") {
                Some(e) => e,
                None => {
                    let msg = "missing required flag: --effect";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            let effect = match effect_str.to_ascii_lowercase().as_str() {
                "permit" => aiosh_core::pep_decision::PepDecisionEffect::Permit,
                "deny" => aiosh_core::pep_decision::PepDecisionEffect::Deny,
                other => {
                    let msg = format!("invalid effect: '{}' (must be 'permit' or 'deny')", other);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_EFFECT", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let desc = parse_flag(rest, "--desc").unwrap_or_else(|| "User-defined policy rule".into());

            // Path hygiene on resource
            if resource.contains("..") || resource.chars().any(|c| c.is_control()) {
                let msg = "invalid resource: path traversal ('..') and control characters are not allowed";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_RESOURCE", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            // ID hygiene
            if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control()) {
                let msg = "invalid rule id: must be non-empty, <= 128 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ID", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let mut service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            let rule = aiosh_core::pep_decision::PepPolicyRule {
                id: id.clone(),
                target_subject: Some(subject),
                target_resource: Some(resource),
                target_action: Some(action),
                effect,
                obligations: Vec::new(),
                description: desc,
            };

            let is_privileged = parse_flag(rest, "--privileged").is_some();
            let sec_policy = aiosh_core::pep_security_policy::PepSecurityPolicy::default();
            if let Err(e) = sec_policy.validate_rule_addition(&rule, is_privileged) {
                let msg = format!("security policy violation: {}", e);
                classify_and_emit(&mut ctx, "pep", "rule-add", json!({ "error": &msg, "id": &id }), "failure", Some(&id), Some("Security policy rejected rule addition"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "POLICY_VIOLATION", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }

            if let Err(e) = service.add_rule(rule.clone()) {
                let msg = format!("failed to add rule: {}", e);
                classify_and_emit(&mut ctx, "pep", "rule-add", json!({ "error": &msg, "id": &id }), "failure", Some(&id), Some("Add rule failed"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ADD_ERROR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            if let Err(e) = service.save_to_path(store_path) {
                let msg = format!("failed to save policy store: {}", e);
                classify_and_emit(&mut ctx, "pep", "rule-add", json!({ "error": &msg, "id": &id }), "failure", Some(&id), Some("Save store failed"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_ERROR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            classify_and_emit(&mut ctx, "pep", "rule-add", json!({ "rule_id": id, "effect": effect_str }), "success", Some(&id), Some("Rule added"), "operator", None);
            if is_json {
                println!("{}", json!({ "code": 0, "data": rule, "error": serde_json::Value::Null }));
            } else {
                println!("Rule '{}' successfully added.", id);
            }
            0
        }
        Some("rule-list") | Some("list-rules") => {
            let service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            let subject_filter = parse_flag(rest, "--subject");
            let action_filter = parse_flag(rest, "--action");

            let all_rules = service.list_rules();
            let rules: Vec<aiosh_core::pep_decision::PepPolicyRule> = all_rules.into_iter().filter(|r| {
                if let Some(ref s) = subject_filter {
                    if r.target_subject.as_ref() != Some(s) {
                        return false;
                    }
                }
                if let Some(ref a) = action_filter {
                    if r.target_action.as_ref() != Some(a) {
                        return false;
                    }
                }
                true
            }).collect();

            classify_and_emit(&mut ctx, "pep", "rule-list", json!({ "count": rules.len() }), "success", None, Some("Listed rules"), "operator", None);
            if is_json {
                println!("{}", json!({ "code": 0, "data": rules, "error": serde_json::Value::Null }));
            } else {
                println!("{:<24} {:<8} {:<20} {:<12} {}", "ID", "EFFECT", "SUBJECT", "ACTION", "RESOURCE");
                println!("{}", "-".repeat(80));
                for r in &rules {
                    let eff = format!("{:?}", r.effect).to_lowercase();
                    let subj = r.target_subject.as_deref().unwrap_or("*");
                    let act = r.target_action.as_deref().unwrap_or("*");
                    let res = r.target_resource.as_deref().unwrap_or("*");
                    println!("{:<24} {:<8} {:<20} {:<12} {}", r.id, eff, subj, act, res);
                }
                println!("\nTotal rules: {}", rules.len());
            }
            0
        }
        Some("rule-remove") | Some("remove-rule") => {
            let mut id_opt = None;
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--store" {
                    i += 2;
                } else if rest[i].starts_with("--") {
                    i += 1;
                } else {
                    id_opt = Some(rest[i].as_str());
                    break;
                }
            }
            let id = match id_opt {
                Some(i) => i,
                None => {
                    let msg = "usage: aiosh pep rule-remove <id> [--store <path>] [--json]";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                    } else {
                        eprintln!("{}", msg);
                    }
                    return 2;
                }
            };

            if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control()) {
                let msg = "invalid rule id: must be non-empty, <= 128 chars, and contain no control characters";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ID", "message": msg } }));
                } else {
                    eprintln!("{}", msg);
                }
                return 2;
            }

            let mut service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            if service.remove_rule(id) {
                let _ = service.save_to_path(store_path);
                classify_and_emit(&mut ctx, "pep", "rule-remove", json!({ "rule_id": id }), "success", Some(id), Some("Rule removed"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 0, "data": { "removed": true, "id": id }, "error": serde_json::Value::Null }));
                } else {
                    println!("Rule '{}' successfully removed.", id);
                }
                0
            } else {
                let msg = format!("rule '{}' not found", id);
                classify_and_emit(&mut ctx, "pep", "rule-remove", json!({ "error": &msg, "id": id }), "failure", Some(id), Some("Rule not found"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                1
            }
        }
        Some("status") => {
            let service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            let all_rules = service.list_rules();
            let mut subjects = std::collections::HashSet::new();
            let mut actions = std::collections::HashSet::new();
            for r in &all_rules {
                if let Some(ref s) = r.target_subject {
                    subjects.insert(s.clone());
                }
                if let Some(ref a) = r.target_action {
                    actions.insert(a.clone());
                }
            }

            let status_data = json!({
                "rules_count": all_rules.len(),
                "max_capacity": aiosh_core::pep_decision_service::MAX_RULES_IN_SERVICE,
                "unique_subjects": subjects.len(),
                "unique_actions": actions.len(),
                "default_algorithm": "deny_overrides",
                "store_path": store_path.to_string_lossy(),
                "store_exists": store_path.exists(),
            });

            classify_and_emit(&mut ctx, "pep", "status", status_data.clone(), "success", None, Some("PEP Decision Engine status"), "operator", None);
            if is_json {
                println!("{}", json!({ "code": 0, "data": status_data, "error": serde_json::Value::Null }));
            } else {
                println!("PEP Decision Engine Status:\n  Total rules:       {}/{}\n  Unique subjects:   {}\n  Unique actions:    {}\n  Default algorithm: deny_overrides\n  Store path:        {}\n  Store exists:      {}",
                    all_rules.len(),
                    aiosh_core::pep_decision_service::MAX_RULES_IN_SERVICE,
                    subjects.len(),
                    actions.len(),
                    store_path.to_string_lossy(),
                    store_path.exists(),
                );
            }
            0
        }
        Some("report") => {
            let service = if store_path.exists() {
                let (s, _recovered, _quarantine) = aiosh_core::pep_decision_service::PepDecisionService::load_or_recover(store_path);
                s
            } else {
                aiosh_core::pep_decision_service::PepDecisionService::new()
            };

            let policy = aiosh_core::pep_security_policy::PepSecurityPolicy::default();
            let report = aiosh_core::pep_observability::PepObservabilityReport::generate(&service, &policy, "");
            if let Err(e) = report.validate() {
                let msg = format!("Observability report validation failed: {}", e);
                classify_and_emit(&mut ctx, "pep", "report", json!({ "error": &msg }), "failure", None, Some("Validation failed"), "operator", None);
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_FAILED", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 1;
            }

            let report_val = serde_json::to_value(&report).unwrap_or(json!({}));
            classify_and_emit(&mut ctx, "pep", "report", report_val.clone(), "success", None, Some("PEP Decision Engine observability report"), "operator", None);

            if is_json {
                println!("{}", json!({ "code": 0, "data": report_val, "error": serde_json::Value::Null }));
            } else {
                println!("PEP Decision Engine Observability Report:\n  Generated at:          {}\n  Healthy:               {}\n  Total rules:           {}/{}\n  Capacity utilization:  {}%\n  Rules with obligations: {}\n  Unique subjects:       {}\n  Unique resources:      {}\n  Unique actions:        {}\n  Default algorithm:     {}\n  Enforcement mode:      {}\n  Obligation criticality: {}",
                    report.generated_at,
                    report.is_healthy,
                    report.total_rules,
                    report.capacity_limit,
                    report.capacity_utilization_percent,
                    report.rules_with_obligations,
                    report.unique_subjects_count,
                    report.unique_resources_count,
                    report.unique_actions_count,
                    report.default_algorithm,
                    report.enforcement_mode,
                    report.obligation_criticality,
                );
            }
            0
        }
        Some("doc") => {
            let doc_args = if args.len() > 1 { &args[1..] } else { &[] };
            let mut doc_sub = None;
            let mut topic_id = None;
            let mut query = None;
            let mut is_doc_json = false;

            let mut i = 0;
            while i < doc_args.len() {
                match doc_args[i].as_str() {
                    "--json" => is_doc_json = true,
                    "list" => doc_sub = Some("list"),
                    "show" | "get" => {
                        doc_sub = Some("show");
                        if i + 1 < doc_args.len() && !doc_args[i + 1].starts_with("--") {
                            i += 1;
                            topic_id = Some(doc_args[i].clone());
                        }
                    }
                    "search" => {
                        doc_sub = Some("search");
                        if i + 1 < doc_args.len() && !doc_args[i + 1].starts_with("--") {
                            i += 1;
                            query = Some(doc_args[i].clone());
                        }
                    }
                    other if doc_sub.is_none() && !other.starts_with("--") => {
                        doc_sub = Some(other);
                    }
                    _ => {}
                }
                i += 1;
            }

            let index = aiosh_core::pep_doc::PepDocIndex::new();
            match doc_sub {
                Some("list") | None => {
                    let topics = index.list_topics();
                    let topic_list: Vec<Value> = topics
                        .into_iter()
                        .map(|t| json!({
                            "id": t.id,
                            "title": t.title,
                            "category": t.category.as_str(),
                            "summary": t.summary,
                            "tags": t.tags,
                        }))
                        .collect();
                    classify_and_emit(&mut ctx, "pep", "doc.list", json!({ "count": topic_list.len() }), "success", None, Some("List PEP documentation topics"), "operator", None);
                    if is_doc_json {
                        println!("{}", json!({ "code": 0, "data": { "count": topic_list.len(), "topics": topic_list }, "error": serde_json::Value::Null }));
                    } else {
                        println!("PEP Decision Engine Documentation Topics ({} topics):\n", topic_list.len());
                        for t in &topic_list {
                            println!("  {} [{}]: {}", t["id"].as_str().unwrap_or(""), t["category"].as_str().unwrap_or(""), t["title"].as_str().unwrap_or(""));
                            println!("    {}\n", t["summary"].as_str().unwrap_or(""));
                        }
                    }
                    0
                }
                Some("show") => {
                    let tid = match topic_id {
                        Some(t) => t,
                        None => {
                            let msg = "usage: aiosh pep doc show <topic_id> [--json]";
                            classify_and_emit(&mut ctx, "pep", "doc.show", json!({ "error": msg }), "failure", None, Some("Missing topic_id"), "operator", None);
                            if is_doc_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match index.get_topic(&tid) {
                        Some(topic) => {
                            let md = aiosh_core::pep_doc::PepDocIndex::format_topic_markdown(topic);
                            classify_and_emit(&mut ctx, "pep", "doc.show", json!({ "topic_id": &tid }), "success", Some(&tid), Some("Show PEP documentation topic"), "operator", None);
                            if is_doc_json {
                                println!("{}", json!({ "code": 0, "data": topic, "error": serde_json::Value::Null }));
                            } else {
                                println!("{}", md);
                            }
                            0
                        }
                        None => {
                            let msg = format!("documentation topic not found: {}", tid);
                            classify_and_emit(&mut ctx, "pep", "doc.show", json!({ "error": &msg }), "failure", Some(&tid), Some("Topic not found"), "operator", None);
                            if is_doc_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                Some("search") => {
                    let q = query.unwrap_or_default();
                    let results = index.search(&q);
                    classify_and_emit(&mut ctx, "pep", "doc.search", json!({ "query": &q, "count": results.len() }), "success", None, Some("Search PEP documentation"), "operator", None);
                    if is_doc_json {
                        println!("{}", json!({ "code": 0, "data": { "query": q, "count": results.len(), "results": results }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Search Results for '{}' ({} matches):\n", q, results.len());
                        for r in &results {
                            println!("  {} (score: {}) - {}", r.topic_id, r.score, r.title);
                            println!("    {}\n", r.snippet);
                        }
                    }
                    0
                }
                Some(unknown) => {
                    let msg = format!("unknown pep doc action: {}", unknown);
                    classify_and_emit(&mut ctx, "pep", "doc", json!({ "error": &msg }), "failure", None, Some("Unknown doc action"), "operator", None);
                    if is_doc_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("validate") => {
            let mut val_store_path: Option<String> = None;
            let mut is_val_json = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--store" | "-s" => {
                        if i + 1 < args.len() {
                            i += 1;
                            val_store_path = Some(args[i].clone());
                        }
                    }
                    "--json" => is_val_json = true,
                    other if val_store_path.is_none() && !other.starts_with("--") => {
                        val_store_path = Some(other.to_string());
                    }
                    _ => {}
                }
                i += 1;
            }

            let path_str = val_store_path.unwrap_or_else(|| store_path.to_string_lossy().to_string());
            let path = std::path::Path::new(&path_str);
            match aiosh_core::pep_recovery::PepStoreValidator::validate_path(path) {
                Ok(report) => {
                    classify_and_emit(
                        &mut ctx, "pep", "validate",
                        json!({ "store_path": path_str, "is_valid": report.is_valid, "total_rules": report.total_rules_scanned, "corrupt_rules": report.corrupt_rules_count }),
                        if report.is_valid { "success" } else { "failure" },
                        Some(&path_str), Some("Validate PEP policy store"), "operator", None,
                    );
                    let exit_code = if report.is_valid { 0 } else { 2 };
                    if is_val_json {
                        println!("{}", json!({ "code": exit_code, "data": report, "error": if report.is_valid { serde_json::Value::Null } else { json!({ "code": "VALIDATION_FAILED", "message": "Policy store validation failed", "issues": report.issues }) } }));
                    } else if report.is_valid {
                        println!("VALID: PEP policy store {:?} is healthy ({} valid rules, sha256: {})", path, report.valid_rules_count, report.sha256_checksum.unwrap_or_default());
                    } else {
                        eprintln!("INVALID: PEP policy store {:?} failed validation ({} issues detected):", path, report.issues.len());
                        for issue in &report.issues {
                            eprintln!("  [{}] {}", issue.code, issue.message);
                        }
                    }
                    exit_code
                }
                Err(e) => {
                    classify_and_emit(&mut ctx, "pep", "validate", json!({ "store_path": path_str, "error": &e }), "failure", Some(&path_str), Some("Validation error"), "operator", None);
                    if is_val_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "IO_ERROR", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    2
                }
            }
        }
        Some("recover") => {
            let mut rec_store_path: Option<String> = None;
            let mut strategy_str = "strict_fail_closed".to_string();
            let mut is_rec_json = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--store" | "-s" => {
                        if i + 1 < args.len() {
                            i += 1;
                            rec_store_path = Some(args[i].clone());
                        }
                    }
                    "--strategy" => {
                        if i + 1 < args.len() {
                            i += 1;
                            strategy_str = args[i].clone();
                        }
                    }
                    "--salvage" => strategy_str = "salvage_valid_rules".to_string(),
                    "--dry-run" => strategy_str = "dry_run".to_string(),
                    "--json" => is_rec_json = true,
                    other if rec_store_path.is_none() && !other.starts_with("--") => {
                        rec_store_path = Some(other.to_string());
                    }
                    _ => {}
                }
                i += 1;
            }

            let strategy = match strategy_str.to_ascii_lowercase().as_str() {
                "strict" | "strict_fail_closed" => aiosh_core::pep_recovery::PepRecoveryStrategy::StrictFailClosed,
                "salvage" | "salvage_valid_rules" => aiosh_core::pep_recovery::PepRecoveryStrategy::SalvageValidRules,
                "dry_run" | "dry-run" => aiosh_core::pep_recovery::PepRecoveryStrategy::DryRun,
                other => {
                    let msg = format!("unknown recovery strategy: {}", other);
                    if is_rec_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_STRATEGY", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let path_str = rec_store_path.unwrap_or_else(|| store_path.to_string_lossy().to_string());
            let path = std::path::Path::new(&path_str);
            match aiosh_core::pep_recovery::PepRecoveryManager::recover_store(path, strategy) {
                Ok(res) => {
                    classify_and_emit(
                        &mut ctx, "pep", "recover",
                        json!({ "store_path": path_str, "strategy": strategy_str, "success": res.success, "salvaged": res.rules_salvaged, "dropped": res.rules_dropped, "quarantine_path": res.quarantine_path }),
                        if res.success { "success" } else { "failure" },
                        Some(&path_str), Some("Recover PEP policy store"), "operator", None,
                    );
                    let exit_code = if res.success { 0 } else { 1 };
                    if is_rec_json {
                        println!("{}", json!({ "code": exit_code, "data": res, "error": if res.success { serde_json::Value::Null } else { json!({ "code": "RECOVERY_FAILED", "message": res.message }) } }));
                    } else if res.success {
                        println!("RECOVERED: {}", res.message);
                        if let Some(ref q) = res.quarantine_path {
                            println!("  Quarantine backup created: {}", q);
                        }
                    } else {
                        eprintln!("RECOVERY INCOMPLETE: {}", res.message);
                    }
                    exit_code
                }
                Err(e) => {
                    classify_and_emit(&mut ctx, "pep", "recover", json!({ "store_path": path_str, "error": &e }), "failure", Some(&path_str), Some("Recovery error"), "operator", None);
                    if is_rec_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "IO_ERROR", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    2
                }
            }
        }
        Some("grant") => {
            let grant_args = if args.len() > 1 { &args[1..] } else { &[] };
            let mut grant_sub = None;
            let mut grant_id = None;
            let mut parent_opt = None;
            let mut child_opt = None;
            let mut issuer_opt = None;
            let mut subject_opt = None;
            let mut scope_type_opt = None;
            let mut scope_path_opt = None;
            let mut rights_opt = None;
            let mut right_opt = None;
            let mut reason_opt = None;
            let mut expires_at_opt = None;
            let mut not_before_opt = None;
            let mut max_inv_opt = None;
            let mut max_bytes_opt = None;
            let mut depth_opt = None;
            let mut state_opt = None;
            let mut now_opt = None;
            let mut cascade = false;
            let mut custom_store = None;
            let mut is_grant_json = false;

            let mut i = 0;
            while i < grant_args.len() {
                match grant_args[i].as_str() {
                    "--json" => is_grant_json = true,
                    "--cascade" => cascade = true,
                    "--store" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            custom_store = Some(grant_args[i].clone());
                        }
                    }
                    "--id" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            grant_id = Some(grant_args[i].clone());
                        }
                    }
                    "--parent" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            parent_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--child" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            child_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--issuer" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            issuer_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--subject" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            subject_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--scope-type" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            scope_type_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--scope-path" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            scope_path_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--rights" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            rights_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--right" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            right_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--reason" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            reason_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--expires-at" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            expires_at_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--not-before" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            not_before_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--max-invocations" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            max_inv_opt = grant_args[i].parse::<u64>().ok();
                        }
                    }
                    "--max-bytes" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            max_bytes_opt = grant_args[i].parse::<u64>().ok();
                        }
                    }
                    "--delegation-depth" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            depth_opt = grant_args[i].parse::<u32>().ok();
                        }
                    }
                    "--state" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            state_opt = Some(grant_args[i].clone());
                        }
                    }
                    "--now" => {
                        if i + 1 < grant_args.len() {
                            i += 1;
                            now_opt = Some(grant_args[i].clone());
                        }
                    }
                    "list" | "inspect" | "validate" | "revoke" | "sweep" | "issue" | "attenuate" => {
                        grant_sub = Some(grant_args[i].as_str());
                    }
                    other if !other.starts_with("--") => {
                        if grant_sub.is_none() {
                            grant_sub = Some(other);
                        } else if grant_id.is_none() {
                            grant_id = Some(other.to_string());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let grant_cfg = aiosh_core::pep_grant_config::PepGrantConfig::from_env().unwrap_or_default();
            let g_store_path = custom_store.map(std::path::PathBuf::from).unwrap_or_else(|| {
                grant_cfg.store_path.clone()
            });

            if let Err(e) = aiosh_core::pep_decision_service::validate_pep_service_path(&g_store_path) {
                let msg = format!("invalid grant store path: {}", e);
                classify_and_emit(
                    &mut ctx, "pep", "grant", json!({ "error": &msg }),
                    "failure", None, Some("Invalid grant store path"), "operator", None,
                );
                if is_grant_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_STORE_PATH", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }

            if g_store_path.exists() {
                if let Ok(meta) = std::fs::metadata(&g_store_path) {
                    if meta.len() > grant_cfg.max_store_bytes {
                        let msg = format!("grant store file exceeds size cap ({} bytes): {} bytes", grant_cfg.max_store_bytes, meta.len());
                        classify_and_emit(
                            &mut ctx, "pep", "grant", json!({ "error": &msg }),
                            "failure", None, Some("Grant store size cap exceeded"), "operator", None,
                        );
                        if is_grant_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "STORE_TOO_LARGE", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(&msg));
                        }
                        return 2;
                    }
                }
            }

            let mut store = if g_store_path.exists() {
                aiosh_core::pep_grant::PepGrantStore::load_from_path(&g_store_path).unwrap_or_else(|_| aiosh_core::pep_grant::PepGrantStore::new())
            } else {
                aiosh_core::pep_grant::PepGrantStore::new()
            };

            match grant_sub {
                Some("list") | None => {
                    let mut grants = if let Some(ref subj) = subject_opt {
                        store.list_grants_for_subject(subj).into_iter().cloned().collect::<Vec<_>>()
                    } else {
                        store.list_grants()
                    };
                    if let Some(ref st) = state_opt {
                        grants.retain(|g| g.state.to_string().eq_ignore_ascii_case(st));
                    }
                    classify_and_emit(
                        &mut ctx, "pep", "grant.list", json!({ "count": grants.len() }),
                        "success", None, Some("Listed PEP grants"), "operator", None,
                    );
                    if is_grant_json {
                        println!("{}", json!({ "code": 0, "data": { "count": grants.len(), "grants": grants }, "error": serde_json::Value::Null }));
                    } else {
                        println!("PEP Grants ({} total):\n", grants.len());
                        for g in &grants {
                            println!("  {} [{}]: issuer={} subject={} rights={:?}", g.id, g.state, g.issuer, g.subject, g.rights);
                        }
                    }
                    0
                }
                Some("inspect") => {
                    let gid = match grant_id {
                        Some(ref id) => id.as_str(),
                        None => {
                            let msg = "usage: aiosh pep grant inspect <grant_id> [--store <path>] [--json]";
                            classify_and_emit(&mut ctx, "pep", "grant.inspect", json!({ "error": msg }), "failure", None, Some("Missing grant_id"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match store.get_grant(gid) {
                        Some(grant) => {
                            classify_and_emit(&mut ctx, "pep", "grant.inspect", json!({ "grant_id": gid }), "success", Some(gid), Some("Inspect PEP grant"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": grant, "error": serde_json::Value::Null }));
                            } else {
                                println!("Grant Details: {}\n  State:   {}\n  Issuer:  {}\n  Subject: {}\n  Rights:  {:?}\n  Created: {}",
                                    grant.id, grant.state, grant.issuer, grant.subject, grant.rights, grant.created_at);
                            }
                            0
                        }
                        None => {
                            let msg = format!("grant not found: {}", gid);
                            classify_and_emit(&mut ctx, "pep", "grant.inspect", json!({ "error": &msg }), "failure", Some(gid), Some("Grant not found"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                Some("validate") => {
                    let gid = match grant_id {
                        Some(ref id) => id.as_str(),
                        None => {
                            let msg = "usage: aiosh pep grant validate <grant_id> [--subject <subject>] [--right <read|write|execute|admin|delegate>] [--store <path>] [--json]";
                            classify_and_emit(&mut ctx, "pep", "grant.validate", json!({ "error": msg }), "failure", None, Some("Missing grant_id"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let now = now_opt.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                    let grant = match store.get_grant(gid) {
                        Some(g) => g,
                        None => {
                            let msg = format!("grant not found: {}", gid);
                            classify_and_emit(&mut ctx, "pep", "grant.validate", json!({ "error": &msg }), "failure", Some(gid), Some("Grant not found"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            return 1;
                        }
                    };

                    let res = if let (Some(ref subj), Some(ref r_str)) = (subject_opt.as_ref(), right_opt.as_ref()) {
                        let right = match r_str.to_ascii_lowercase().as_str() {
                            "read" => aiosh_core::capability::CapabilityRight::Read,
                            "write" => aiosh_core::capability::CapabilityRight::Write,
                            "execute" => aiosh_core::capability::CapabilityRight::Execute,
                            "delete" => aiosh_core::capability::CapabilityRight::Delete,
                            "admin" => aiosh_core::capability::CapabilityRight::Admin,
                            "delegate" => aiosh_core::capability::CapabilityRight::Delegate,
                            other => {
                                let msg = format!("unknown capability right: {}", other);
                                if is_grant_json {
                                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_RIGHT", "message": msg } }));
                                } else {
                                    eprintln!("{}", sanitize_terminal(&msg));
                                }
                                return 2;
                            }
                        };
                        store.validate_grant_for_action(gid, subj, right, &now)
                    } else {
                        grant.is_usable_at(&now)
                    };

                    match res {
                        Ok(()) => {
                            classify_and_emit(&mut ctx, "pep", "grant.validate", json!({ "grant_id": gid, "valid": true }), "success", Some(gid), Some("Grant is valid"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": { "grant_id": gid, "valid": true, "state": grant.state.to_string() }, "error": serde_json::Value::Null }));
                            } else {
                                println!("VALID: grant '{}' is active and valid for evaluation", gid);
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(&mut ctx, "pep", "grant.validate", json!({ "grant_id": gid, "valid": false, "error": &e }), "failure", Some(gid), Some("Grant validation failed"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": { "grant_id": gid, "valid": false }, "error": { "code": "INVALID_GRANT", "message": e } }));
                            } else {
                                eprintln!("INVALID: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                Some("revoke") => {
                    let gid = match grant_id {
                        Some(ref id) => id.as_str(),
                        None => {
                            let msg = "usage: aiosh pep grant revoke <grant_id> [--reason <reason>] [--cascade] [--store <path>] [--json]";
                            classify_and_emit(&mut ctx, "pep", "grant.revoke", json!({ "error": msg }), "failure", None, Some("Missing grant_id"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let reason = reason_opt.unwrap_or_else(|| "Revoked by operator".to_string());
                    match store.revoke_grant(gid, "operator", &reason, cascade) {
                        Ok(revoked_count) => {
                            let _ = store.save_to_path(&g_store_path);
                            classify_and_emit(&mut ctx, "pep", "grant.revoke", json!({ "grant_id": gid, "revoked_count": revoked_count, "cascade": cascade }), "success", Some(gid), Some("Revoked grant"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": { "grant_id": gid, "revoked_count": revoked_count, "cascade": cascade }, "error": serde_json::Value::Null }));
                            } else {
                                println!("REVOKED: grant '{}' revoked ({} grants affected)", gid, revoked_count);
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(&mut ctx, "pep", "grant.revoke", json!({ "grant_id": gid, "error": &e }), "failure", Some(gid), Some("Revoke failed"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REVOKE_FAILED", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                Some("sweep") => {
                    let mut service = if g_store_path.exists() {
                        aiosh_core::pep_grant_service::PepGrantService::load_from_path(&g_store_path)
                            .unwrap_or_else(|_| aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone()))
                    } else {
                        aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone())
                    };
                    let now = now_opt.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                    match service.sweep_expired(&now) {
                        Ok(swept_count) => {
                            if swept_count > 0 {
                                let _ = service.save_to_path(&g_store_path);
                            }
                            classify_and_emit(&mut ctx, "pep", "grant.sweep", json!({ "swept_count": swept_count, "timestamp": &now }), "success", None, Some("Swept expired grants"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": { "swept_count": swept_count, "timestamp": now }, "error": serde_json::Value::Null }));
                            } else {
                                println!("SWEEP: {} expired grant(s) swept", swept_count);
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(&mut ctx, "pep", "grant.sweep", json!({ "error": &e }), "failure", None, Some("Sweep failed"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SWEEP_FAILED", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                Some("issue") => {
                    let gid = match grant_id {
                        Some(ref id) => id.clone(),
                        None => {
                            let msg = "usage: aiosh pep grant issue --id <id> --subject <subj> --scope-type <type> --rights <r1,r2> [options]";
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": msg }), "failure", None, Some("Missing id"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let subj = match subject_opt {
                        Some(ref s) => s.clone(),
                        None => {
                            let msg = "missing required flag: --subject";
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": msg }), "failure", Some(&gid), Some("Missing subject"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let scope_type = match scope_type_opt {
                        Some(ref st) => st.clone(),
                        None => {
                            let msg = "missing required flag: --scope-type <filesystem|network|ipc|system>";
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": msg }), "failure", Some(&gid), Some("Missing scope type"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let raw_rights = match rights_opt {
                        Some(ref r) => r.clone(),
                        None => {
                            let msg = "missing required flag: --rights <read,write,...>";
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": msg }), "failure", Some(&gid), Some("Missing rights"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };

                    let issuer = issuer_opt.unwrap_or_else(|| "operator".to_string());
                    let scope = match scope_type.to_ascii_lowercase().as_str() {
                        "filesystem" | "fs" => aiosh_core::capability::CapabilityScope::Filesystem {
                            path: scope_path_opt.unwrap_or_else(|| "/".to_string()),
                            recursive: true,
                        },
                        "network" | "net" => aiosh_core::capability::CapabilityScope::Network {
                            host: scope_path_opt.unwrap_or_else(|| "localhost".to_string()),
                            port: None,
                            protocol: "tcp".to_string(),
                        },
                        "ipc" => aiosh_core::capability::CapabilityScope::Ipc {
                            channel: scope_path_opt.unwrap_or_else(|| "default".to_string()),
                        },
                        "system" | "sys" => aiosh_core::capability::CapabilityScope::System {
                            subsystem: scope_path_opt.unwrap_or_else(|| "core".to_string()),
                        },
                        other => {
                            let msg = format!("unknown scope type: {}", other);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            return 2;
                        }
                    };

                    let mut parsed_rights = Vec::new();
                    for r_str in raw_rights.split(',') {
                        let trimmed = r_str.trim().to_ascii_lowercase();
                        if trimmed.is_empty() { continue; }
                        let right = match trimmed.as_str() {
                            "read" => aiosh_core::capability::CapabilityRight::Read,
                            "write" => aiosh_core::capability::CapabilityRight::Write,
                            "execute" => aiosh_core::capability::CapabilityRight::Execute,
                            "delete" => aiosh_core::capability::CapabilityRight::Delete,
                            "admin" => aiosh_core::capability::CapabilityRight::Admin,
                            "delegate" => aiosh_core::capability::CapabilityRight::Delegate,
                            other => {
                                let msg = format!("unknown capability right: {}", other);
                                if is_grant_json {
                                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                                } else {
                                    eprintln!("{}", sanitize_terminal(&msg));
                                }
                                return 2;
                            }
                        };
                        parsed_rights.push(right);
                    }

                    let mut grant = aiosh_core::pep_grant::PepGrant::new(&gid, &issuer, &subj, scope, parsed_rights);
                    grant.state = aiosh_core::pep_grant::PepGrantState::Active;
                    if let Some(exp) = expires_at_opt {
                        grant.constraints.expires_at = Some(exp);
                    }
                    if let Some(nb) = not_before_opt {
                        grant.constraints.not_before = Some(nb);
                    }
                    if let Some(max_inv) = max_inv_opt {
                        grant.constraints.max_invocations = Some(max_inv);
                    }
                    if let Some(max_b) = max_bytes_opt {
                        grant.constraints.max_bytes = Some(max_b);
                    }
                    grant.constraints.max_delegation_depth = depth_opt.unwrap_or(grant_cfg.default_max_delegation_depth);

                    if let Err(e) = grant.validate() {
                        let msg = format!("grant validation failed: {}", e);
                        classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": &msg }), "failure", Some(&gid), Some("Validation failed"), "operator", None);
                        if is_grant_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_FAILED", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 2;
                    }

                    let mut service = if g_store_path.exists() {
                        aiosh_core::pep_grant_service::PepGrantService::load_from_path(&g_store_path)
                            .unwrap_or_else(|_| aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone()))
                    } else {
                        aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone())
                    };

                    match service.issue_grant(grant.clone()) {
                        Ok(()) => {
                            let _ = service.save_to_path(&g_store_path);
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "grant_id": &gid }), "success", Some(&gid), Some("Issued grant"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": grant, "error": serde_json::Value::Null }));
                            } else {
                                println!("ISSUED: grant '{}' issued to '{}'", gid, subj);
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(&mut ctx, "pep", "grant.issue", json!({ "error": &e }), "failure", Some(&gid), Some("Issue failed"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ISSUE_FAILED", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                Some("attenuate") => {
                    let pid = parent_opt.or(grant_id).unwrap_or_default();
                    if pid.is_empty() {
                        let msg = "usage: aiosh pep grant attenuate <parent_id> --child <child_id> --subject <child_subject> --rights <r1,r2> [options]";
                        classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "error": msg }), "failure", None, Some("Missing parent_id"), "operator", None);
                        if is_grant_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(msg));
                        }
                        return 2;
                    }
                    let cid = match child_opt {
                        Some(ref c) => c.clone(),
                        None => {
                            let msg = "missing required flag: --child <child_id>";
                            classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "error": msg }), "failure", Some(&pid), Some("Missing child_id"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let csubj = match subject_opt {
                        Some(ref s) => s.clone(),
                        None => {
                            let msg = "missing required flag: --subject <child_subject>";
                            classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "error": msg }), "failure", Some(&pid), Some("Missing child subject"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    let raw_rights = match rights_opt {
                        Some(ref r) => r.clone(),
                        None => {
                            let msg = "missing required flag: --rights <read,write,...>";
                            classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "error": msg }), "failure", Some(&pid), Some("Missing rights"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };

                    let mut delegated_rights = Vec::new();
                    for r_str in raw_rights.split(',') {
                        let trimmed = r_str.trim().to_ascii_lowercase();
                        if trimmed.is_empty() { continue; }
                        let right = match trimmed.as_str() {
                            "read" => aiosh_core::capability::CapabilityRight::Read,
                            "write" => aiosh_core::capability::CapabilityRight::Write,
                            "execute" => aiosh_core::capability::CapabilityRight::Execute,
                            "delete" => aiosh_core::capability::CapabilityRight::Delete,
                            "admin" => aiosh_core::capability::CapabilityRight::Admin,
                            "delegate" => aiosh_core::capability::CapabilityRight::Delegate,
                            other => {
                                let msg = format!("unknown capability right: {}", other);
                                if is_grant_json {
                                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENTS", "message": msg } }));
                                } else {
                                    eprintln!("{}", sanitize_terminal(&msg));
                                }
                                return 2;
                            }
                        };
                        delegated_rights.push(right);
                    }

                    let mut service = if g_store_path.exists() {
                        aiosh_core::pep_grant_service::PepGrantService::load_from_path(&g_store_path)
                            .unwrap_or_else(|_| aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone()))
                    } else {
                        aiosh_core::pep_grant_service::PepGrantService::new().with_storage_path(g_store_path.clone())
                    };

                    match service.attenuate_grant(&pid, &cid, &csubj, delegated_rights) {
                        Ok(child) => {
                            let _ = service.save_to_path(&g_store_path);
                            classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "parent_id": &pid, "child_id": &cid }), "success", Some(&pid), Some("Attenuated grant"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 0, "data": child, "error": serde_json::Value::Null }));
                            } else {
                                println!("ATTENUATED: derived child grant '{}' from parent '{}'", cid, pid);
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(&mut ctx, "pep", "grant.attenuate", json!({ "parent_id": &pid, "error": &e }), "failure", Some(&pid), Some("Attenuation failed"), "operator", None);
                            if is_grant_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ATTENUATION_FAILED", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                Some(other) => {
                    let msg = format!("unknown grant action: {}", other);
                    if is_grant_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh pep — PEP Decision Engine & Policy Control\n\nUsage: aiosh pep <evaluate|rule-add|rule-list|rule-remove|status|report|doc|validate|recover|grant> [options]\n\nCommands:\n  evaluate                   Evaluate authorization request against policies\n  rule-add                   Add a new policy rule\n  rule-list                  List loaded policy rules\n  rule-remove <id>           Remove a policy rule by ID\n  status                     Display PEP Decision Engine status & metrics\n  report                     Generate comprehensive PEP observability report\n  doc <list|show|search>     Query embedded PEP documentation & help\n  validate <path>            Validate policy store schema, constraints & capacity\n  recover <path>             Recover corrupted policy store (salvage or fail-closed)\n  grant <list|inspect|validate|revoke|sweep|issue|attenuate> Manage and inspect PEP authorization grants\n\nOptions:\n  --store <PATH>             Custom policy JSON store path\n  --strategy <STRAT>         Recovery strategy: strict_fail_closed, salvage_valid_rules, dry_run\n  --salvage                  Shorthand for --strategy salvage_valid_rules\n  --dry-run                  Shorthand for --strategy dry_run\n  --json                     Output structured JSON envelope\n  -h, --help                 Display this help message");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown pep subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "pep", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_sandbox(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    match sub {
        Some("profiles") => {
            let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
                path: Some(db_path()),
                home: None,
            }).ok();
            let svc = aiosh_core::sandbox_service::SandboxService::with_default_profiles(ring);
            let profiles = svc.list_profiles();

            if is_json {
                println!("{}", json!({ "code": 0, "data": profiles, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Profiles ({} total):", profiles.len());
                for p in &profiles {
                    println!("  - {}: isolation={:?}, net={:?}, mem_max_mb={}",
                        p.name,
                        p.isolation_level,
                        p.network,
                        p.resources.max_memory_bytes / (1024 * 1024)
                    );
                }
            }
            0
        }
        Some("probe") => {
            let caps = aiosh_core::sandbox_service::HostSandboxCapabilities::probe();
            if is_json {
                println!("{}", json!({ "code": 0, "data": caps, "error": serde_json::Value::Null }));
            } else {
                println!("Host Sandbox Capabilities (platform: {}):", caps.platform);
                println!("  Landlock LSM:         {}", if caps.landlock_supported { format!("supported (ABI v{:?})", caps.landlock_abi_version.unwrap_or(0)) } else { "unavailable".into() });
                println!("  Seccomp-BPF:          {}", if caps.seccomp_bpf_supported { "supported" } else { "unavailable" });
                println!("  no_new_privs:         {}", if caps.no_new_privs_supported { "supported" } else { "unavailable" });
            }
            0
        }
        Some("config") => {
            let cfg_path = parse_flag(rest, "--path");
            let cfg = match cfg_path {
                Some(ref p) => match aiosh_core::sandbox_config::SandboxConfig::load_from_path(p) {
                    Ok(c) => c,
                    Err(e) => {
                        let msg = format!("failed to load config from {}: {}", p, e);
                        classify_and_emit(
                            &mut ctx, "sandbox", "config", json!({ "error": &msg }),
                            "failure", None, Some("Config load error"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_ERROR", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                },
                None => aiosh_core::sandbox_config::SandboxConfig::load_with_env_overrides(),
            };

            if is_json {
                println!("{}", json!({ "code": 0, "data": cfg, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Configuration:");
                println!("  Version:                   {}", cfg.version);
                println!("  Default Profile:           {}", cfg.default_profile_name);
                println!("  Max Output Capture:        {} bytes ({} MiB)", cfg.max_output_capture_bytes, cfg.max_output_capture_bytes / (1024 * 1024));
                println!("  Execution Timeout:         {} seconds", cfg.execution_timeout_seconds);
                println!("  Max Registered Profiles:   {}", cfg.max_registered_profiles);
                println!("  Enforce PEP Grants:        {}", cfg.enforce_pep_grants);
                println!("  Audit Enabled:             {}", cfg.audit_enabled);
                if let Some(ref dir) = cfg.custom_profiles_dir {
                    println!("  Custom Profiles Dir:       {}", dir.display());
                }
            }
            0
        }
        Some("policy") => {
            let pol_path = parse_flag(rest, "--path");
            let policy = match pol_path {
                Some(ref p) => match aiosh_core::sandbox_policy::SandboxSecurityPolicy::load_from_path(p) {
                    Ok(pol) => pol,
                    Err(e) => {
                        let msg = format!("failed to load policy from {}: {}", p, e);
                        classify_and_emit(
                            &mut ctx, "sandbox", "policy", json!({ "error": &msg, "path": p }),
                            "failure", None, Some("Load policy failed"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_ERROR", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                },
                None => aiosh_core::sandbox_policy::SandboxSecurityPolicy::default(),
            };

            classify_and_emit(
                &mut ctx, "sandbox", "policy", json!({ "version": &policy.version, "mode": format!("{:?}", policy.mode) }),
                "success", None, Some("Inspected sandbox security policy"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": policy, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Security Policy (v{}):", policy.version);
                println!("  Mode:                      {:?}", policy.mode);
                println!("  Prohibited Commands:       {:?}", policy.prohibited_commands);
                println!("  Prohibited Env Vars:       {:?}", policy.prohibited_env_vars);
                println!("  PEP Mandated Profiles:     {:?}", policy.require_pep_grant_for_profiles);
                println!("  Max Permissible Wall Time: {} ms", policy.max_permissible_wall_time_ms);
                println!("  Max Permissible Memory:    {} bytes", policy.max_permissible_memory_bytes);
            }
            0
        }
        Some("stats") => {
            let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
                path: Some(db_path()),
                home: None,
            }).ok();
            let svc = aiosh_core::sandbox_service::SandboxService::with_default_profiles(ring);
            let report = match svc.generate_observability_report() {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("failed to generate observability report: {}", e);
                    classify_and_emit(
                        &mut ctx, "sandbox", "stats", json!({ "error": &msg }),
                        "failure", None, Some("Failed report generation"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REPORT_ERROR", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx, "sandbox", "stats", json!({ "total_profiles": report.total_profiles_registered, "total_executions": report.total_executions_recorded }),
                "success", None, Some("Generated sandbox observability report"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Observability Report (UTC: {}):", report.generated_at_utc);
                println!("  Healthy:                   {}", report.is_healthy);
                println!("  Registered Profiles:       {}", report.total_profiles_registered);
                println!("  Recorded Executions:       {}", report.total_executions_recorded);
                println!("  Policy Mode:               {}", report.policy_mode);
                println!("  Executions by Outcome:     {:?}", report.executions_by_outcome);
                println!("  Executions by Profile:     {:?}", report.executions_by_profile);
                println!("  Host Platform:             {}", report.host_capabilities.platform);
                println!("  Landlock LSM:              {}", if report.host_capabilities.landlock_supported { "supported" } else { "unavailable" });
                println!("  Seccomp-BPF:               {}", if report.host_capabilities.seccomp_bpf_supported { "supported" } else { "unavailable" });
            }
            0
        }
        Some("doc") => {
            let index = aiosh_core::sandbox_doc::SandboxDocIndex::new();
            let search_query = parse_flag(rest, "--search");
            let topic_id = rest.iter().find(|s| !s.starts_with("--")).map(|s| s.as_str());

            if let Some(ref q) = search_query {
                let results = index.search(q);
                classify_and_emit(
                    &mut ctx, "sandbox", "doc", json!({ "query": q, "count": results.len() }),
                    "success", None, Some("Searched sandbox documentation"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": { "query": q, "results": results }, "error": serde_json::Value::Null }));
                } else {
                    println!("Sandbox Documentation Search Results for '{}' ({} found):", q, results.len());
                    for r in &results {
                        println!("  - [{}] {} (score: {})", r.topic_id, r.title, r.score);
                        println!("    {}", r.snippet);
                    }
                }
                0
            } else if let Some(t_id) = topic_id {
                match index.get_topic(t_id) {
                    Some(topic) => {
                        classify_and_emit(
                            &mut ctx, "sandbox", "doc", json!({ "topic": t_id }),
                            "success", None, Some("Viewed sandbox documentation topic"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 0, "data": topic, "error": serde_json::Value::Null }));
                        } else {
                            println!("=== {} (Category: {:?}) ===", topic.title, topic.category);
                            println!("Summary: {}", topic.summary);
                            println!("Tags: {}", topic.tags.join(", "));
                            println!();
                            for sec in &topic.sections {
                                println!("--- {} ---", sec.title);
                                println!("{}\n", sec.content);
                            }
                            if !topic.examples.is_empty() {
                                println!("Examples:");
                                for ex in &topic.examples {
                                    println!("  $ {}", ex);
                                }
                            }
                        }
                        0
                    }
                    None => {
                        let msg = format!("topic '{}' not found", t_id);
                        classify_and_emit(
                            &mut ctx, "sandbox", "doc", json!({ "topic": t_id, "error": &msg }),
                            "failure", None, Some("Topic not found"), "operator", None,
                        );
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "TOPIC_NOT_FOUND", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        2
                    }
                }
            } else {
                let topics = index.list_topics();
                classify_and_emit(
                    &mut ctx, "sandbox", "doc", json!({ "count": topics.len() }),
                    "success", None, Some("Listed sandbox documentation topics"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 0, "data": topics, "error": serde_json::Value::Null }));
                } else {
                    println!("Sandbox Documentation Topics ({} total):", topics.len());
                    for t in &topics {
                        println!("  - {:<15} {:<45} [{}]", t.id, t.title, t.category.as_str());
                        println!("    {}", t.summary);
                    }
                }
                0
            }
        }
        Some("validate") => {
            let dir_flag = parse_flag(rest, "--dir");
            let dir_path = dir_flag.as_deref().map(std::path::Path::new);

            let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
                path: Some(db_path()),
                home: None,
            }).ok();
            let svc = aiosh_core::sandbox_service::SandboxService::with_default_profiles(ring);
            let report = svc.validate_state(dir_path);

            classify_and_emit(
                &mut ctx, "sandbox", "validate", json!({ "healthy": report.is_healthy, "issues": report.issues.len() }),
                if report.is_healthy { "success" } else { "failure" }, None, Some("Validated sandbox state"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": if report.is_healthy { 0 } else { 1 }, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Validation Report:");
                println!("  Healthy:                   {}", report.is_healthy);
                println!("  Factory Profiles Intact:   {}", report.factory_profiles_intact);
                println!("  Checked Profiles:          {}", report.total_profiles_checked);
                println!("  Valid Profiles:            {}", report.valid_profiles_count);
                println!("  Corrupt Profiles:          {}", report.corrupt_profiles_count);
                if !report.issues.is_empty() {
                    println!("  Issues ({}):", report.issues.len());
                    for issue in &report.issues {
                        println!("    [{:?}] {}: {}", issue.severity, issue.code, issue.message);
                    }
                }
            }
            if report.is_healthy { 0 } else { 1 }
        }
        Some("recover") => {
            let dir_flag = parse_flag(rest, "--dir");
            let dir_path = dir_flag.as_deref().map(std::path::Path::new);
            let strategy_flag = parse_flag(rest, "--strategy").unwrap_or_else(|| "defaults".into());

            let strategy = match strategy_flag.to_lowercase().as_str() {
                "dry_run" | "dryrun" => aiosh_core::sandbox_recovery::SandboxRecoveryStrategy::DryRun,
                "quarantine" | "quarantine_and_reset" => aiosh_core::sandbox_recovery::SandboxRecoveryStrategy::QuarantineAndReset,
                _ => aiosh_core::sandbox_recovery::SandboxRecoveryStrategy::RestoreFactoryDefaults,
            };

            let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
                path: Some(db_path()),
                home: None,
            }).ok();
            let mut svc = aiosh_core::sandbox_service::SandboxService::with_default_profiles(ring);
            let res = match svc.recover_state(strategy, dir_path) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("sandbox recovery failed: {}", e);
                    classify_and_emit(
                        &mut ctx, "sandbox", "recover", json!({ "error": &msg }),
                        "failure", None, Some("Recovery error"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "RECOVERY_FAILED", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx, "sandbox", "recover", json!({ "success": res.success, "strategy": format!("{:?}", res.strategy), "restored": res.profiles_restored }),
                if res.success { "success" } else { "failure" }, None, Some("Executed sandbox recovery"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": if res.success { 0 } else { 1 }, "data": res, "error": serde_json::Value::Null }));
            } else {
                println!("Sandbox Recovery Result:");
                println!("  Success:                   {}", res.success);
                println!("  Strategy:                  {:?}", res.strategy);
                println!("  Profiles Restored:         {}", res.profiles_restored);
                println!("  Issues Resolved:           {}", res.issues_resolved);
                println!("  Message:                   {}", res.message);
                if let Some(ref q) = res.quarantine_path {
                    println!("  Quarantine Path:           {}", q);
                }
            }
            if res.success { 0 } else { 1 }
        }
        Some("exec") => {
            // Find delimiter `--`
            let dash_pos = rest.iter().position(|r| r == "--");
            let (flags_slice, cmd_slice) = match dash_pos {
                Some(pos) => (&rest[..pos], &rest[pos + 1..]),
                None => {
                    let msg = "sandbox exec requires '--' delimiter before command to execute";
                    classify_and_emit(
                        &mut ctx, "sandbox", "exec", json!({ "error": msg }),
                        "failure", None, Some("Missing '--' delimiter"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_DELIMITER", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if cmd_slice.is_empty() {
                let msg = "sandbox exec requires target command binary after '--'";
                classify_and_emit(
                    &mut ctx, "sandbox", "exec", json!({ "error": msg }),
                    "failure", None, Some("Missing command binary"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_COMMAND", "message": msg } }));
                } else {
                    eprintln!("ERROR: {}", sanitize_terminal(msg));
                }
                return 2;
            }

            let profile_name = parse_flag(flags_slice, "--profile").unwrap_or_else(|| "standard".into());
            let grant_token = parse_flag(flags_slice, "--grant");
            let cwd_opt = parse_flag(flags_slice, "--cwd");

            // Traversal check on cwd
            if let Some(ref cwd) = cwd_opt {
                if cwd.contains("..") {
                    let msg = format!("directory traversal prohibited in cwd: {}", cwd);
                    classify_and_emit(
                        &mut ctx, "sandbox", "exec", json!({ "error": &msg }),
                        "failure", None, Some("Directory traversal in cwd"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "TRAVERSAL_DETECTED", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            }

            let ring = AuditRing::open(aiosh_core::audit::OpenOptions {
                path: Some(db_path()),
                home: None,
            }).ok();
            let mut svc = aiosh_core::sandbox_service::SandboxService::with_default_profiles(ring);

            let profile = match svc.get_profile(&profile_name) {
                Some(p) => p,
                None => {
                    let msg = format!("profile '{}' not found", profile_name);
                    classify_and_emit(
                        &mut ctx, "sandbox", "exec", json!({ "error": &msg, "profile": &profile_name }),
                        "failure", None, Some("Profile not found"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "PROFILE_NOT_FOUND", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let bin = &cmd_slice[0];
            let bin_args = if cmd_slice.len() > 1 { cmd_slice[1..].to_vec() } else { Vec::new() };

            let req = aiosh_core::sandbox_data_model::SandboxExecutionRequest {
                command: bin.to_string(),
                args: bin_args,
                cwd: cwd_opt,
                profile,
                session_id: None,
                pep_grant_id: grant_token,
                stdin_data: None,
            };

            if let Err(e) = req.validate() {
                let msg = format!("invalid execution request: {}", e);
                classify_and_emit(
                    &mut ctx, "sandbox", "exec", json!({ "error": &msg }),
                    "failure", None, Some("Invalid request"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_REQUEST", "message": msg } }));
                } else {
                    eprintln!("ERROR: {}", sanitize_terminal(&msg));
                }
                return 2;
            }

            match svc.execute(&req) {
                Ok(res) => {
                    classify_and_emit(
                        &mut ctx, "sandbox", "exec",
                        json!({ "command": bin, "profile": profile_name, "exit_code": res.exit_code, "status": format!("{:?}", res.status) }),
                        if res.exit_code == 0 { "success" } else { "failure" },
                        Some(bin), Some("Sandbox execution completed"), "operator", req.pep_grant_id.as_deref(),
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": res, "error": serde_json::Value::Null }));
                    } else {
                        if !res.stdout.is_empty() {
                            print!("{}", sanitize_terminal_output(&res.stdout));
                        }
                        if !res.stderr.is_empty() {
                            eprint!("{}", sanitize_terminal_output(&res.stderr));
                        }
                    }
                    res.exit_code
                }
                Err(e) => {
                    let exit_code = if e.contains(aiosh_core::sandbox_service::ERR_SANDBOX_PEP_UNAUTHORIZED) {
                        1
                    } else if e.contains(aiosh_core::sandbox_service::ERR_SANDBOX_EXEC_FAILED) {
                        127
                    } else {
                        2
                    };
                    classify_and_emit(
                        &mut ctx, "sandbox", "exec", json!({ "command": bin, "error": &e }),
                        "failure", Some(bin), Some("Sandbox execution failed"), "operator", req.pep_grant_id.as_deref(),
                    );
                    if is_json {
                        println!("{}", json!({ "code": exit_code, "data": serde_json::Value::Null, "error": { "code": "EXEC_ERROR", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    exit_code
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh sandbox — Sandbox Containment & Execution Control\n\nUsage: aiosh sandbox <profiles|probe|config|policy|stats|doc|validate|recover|exec> [options]\n\nCommands:\n  profiles                   List registered sandbox containment profiles\n  probe                      Probe host kernel sandbox capabilities\n  config                     Inspect Sandbox Enforcement runtime configuration\n  policy                     Inspect Sandbox Enforcement security policy and rules\n  stats                      Display Sandbox Enforcement observability and telemetry report\n  doc                        Browse and search offline Sandbox Enforcement documentation\n  validate                   Validate integrity of sandbox profiles and manifests\n  recover                    Restore factory profiles and quarantine corrupt manifests\n  exec                       Execute command under sandbox containment\n\nOptions for config/policy:\n  --path <PATH>              Custom config or policy JSON file\n\nOptions for doc:\n  --search <QUERY>           Search topics by keyword\n\nOptions for validate/recover:\n  --dir <PATH>               Custom profiles directory to scan/repair\n  --strategy <STRATEGY>      Recovery strategy (defaults, quarantine, dry_run) [default: defaults]\n\nOptions for exec:\n  --profile <NAME>           Target sandbox profile (standard, strict, permissive) [default: standard]\n  --grant <TOKEN>            PEP authorization grant token\n  --cwd <PATH>               Working directory for process execution\n  --                         Delimiter separating aiosh flags from the command to execute\n  --json                     Output structured JSON envelope\n  -h, --help                 Display this help message");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown sandbox subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "sandbox", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_privilege(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_str = parse_flag(rest, "--store")
        .or_else(|| std::env::var("AIOS_PRIVILEGE_STORE_PATH").ok())
        .or_else(|| std::env::var("AIOS_PRIVILEGE_STORE").ok())
        .unwrap_or_else(|| format!("{}/privileges.json", ai_home()));
    let store_path = std::path::Path::new(&store_path_str);

    if store_path_str.len() > 1024 || store_path_str.contains("..") || store_path_str.chars().any(|c| c.is_control()) {
        let msg = "invalid store path: path contains traversal or control characters or exceeds 1024 bytes";
        classify_and_emit(
            &mut ctx, "privilege", sub.unwrap_or("unknown"), json!({ "error": msg }),
            "failure", None, Some("Invalid store path"), "operator", None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PATH", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(msg));
        }
        return 2;
    }

    if store_path.exists() {
        if let Ok(metadata) = std::fs::metadata(store_path) {
            if metadata.len() > 1024 * 1024 {
                let msg = "store file exceeds maximum permitted size of 1 MiB";
                classify_and_emit(
                    &mut ctx, "privilege", sub.unwrap_or("unknown"), json!({ "error": msg }),
                    "failure", None, Some("Oversized store file"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STORE_OVERSIZED", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 1;
            }
        }
    }

    let mut service = if store_path.exists() {
        aiosh_core::privilege_service::PrivilegeService::load_from_path(store_path).unwrap_or_default()
    } else {
        aiosh_core::privilege_service::PrivilegeService::new()
    };

    match sub {
        Some("status") => {
            let actor = parse_flag(rest, "--actor").unwrap_or_else(|| ctx.actor_id.clone());
            if actor.trim().is_empty() || actor.chars().any(|c| c.is_control()) || actor.trim().len() > aiosh_core::privilege_data_model::MAX_ACTOR_ID_LEN {
                let msg = "invalid actor identifier";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ACTOR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            let context = match service.get_or_create_context(&actor, aiosh_core::privilege_data_model::PrivilegeLevel::User) {
                Ok(c) => c.clone(),
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONTEXT_ERROR", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };
            let _ = service.save_to_path(store_path);

            classify_and_emit(
                &mut ctx, "privilege", "status", json!({ "actor": &actor, "level": context.active_level.as_str() }),
                "success", Some(&actor), Some("Queried privilege status"), "operator", context.elevation_grant_id.as_deref(),
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": context, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Context for '{}':", context.actor_id);
                println!("  Active Level:        {:?}", context.active_level);
                println!("  Elevation Active:    {}", context.is_elevation_active);
                if let Some(ref gid) = context.elevation_grant_id {
                    println!("  Elevation Grant:     {}", gid);
                }
                let mut caps: Vec<_> = context.capabilities.iter().map(|c| c.as_str()).collect();
                caps.sort();
                println!("  Capabilities ({}):   {}", caps.len(), if caps.is_empty() { "(none)".to_string() } else { caps.join(", ") });
            }
            0
        }
        Some("elevate") => {
            let target_str = match parse_flag(rest, "--to") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --to <tier>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            let target_level = match aiosh_core::privilege_data_model::PrivilegeLevel::parse_level(&target_str) {
                Some(l) => l,
                None => {
                    let msg = format!("invalid privilege tier: {}", target_str);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_TIER", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let actor = parse_flag(rest, "--actor").unwrap_or_else(|| ctx.actor_id.clone());
            if actor.trim().is_empty() || actor.chars().any(|c| c.is_control()) || actor.trim().len() > aiosh_core::privilege_data_model::MAX_ACTOR_ID_LEN {
                let msg = "invalid actor identifier";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_ACTOR", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            let _ = service.get_or_create_context(&actor, aiosh_core::privilege_data_model::PrivilegeLevel::User);
            let current_level = service.get_context(&actor).map(|c| c.active_level).unwrap_or(aiosh_core::privilege_data_model::PrivilegeLevel::User);

            let mut req_caps = Vec::new();
            if let Some(caps_arg) = parse_flag(rest, "--caps") {
                for part in caps_arg.split(',') {
                    let trimmed = part.trim();
                    if trimmed.is_empty() { continue; }
                    match aiosh_core::privilege_data_model::PrivilegeCapability::parse_capability(trimmed) {
                        Some(c) => req_caps.push(c),
                        None => {
                            let msg = format!("unknown capability: {}", trimmed);
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_CAPABILITY", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(&msg));
                            }
                            return 2;
                        }
                    }
                }
            }

            if req_caps.len() > aiosh_core::privilege_data_model::MAX_CAPABILITIES_COUNT {
                let msg = "requested capabilities exceed maximum limit (32)";
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "CAPABILITY_OVERFLOW", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 2;
            }

            let grant_id = parse_flag(rest, "--grant");
            if let Some(ref gid) = grant_id {
                if gid.chars().any(|c| c.is_control()) || gid.trim().len() > aiosh_core::privilege_data_model::MAX_GRANT_ID_LEN {
                    let msg = "invalid grant token: contains control characters or exceeds 256 bytes";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_GRANT", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            }
            let req = aiosh_core::privilege_data_model::PrivilegeTransitionRequest {
                actor_id: actor.clone(),
                from_level: current_level,
                target_level,
                requested_capabilities: req_caps,
                grant_id: grant_id.clone(),
            };

            match service.request_elevation(req) {
                Ok(new_ctx) => {
                    let _ = service.save_to_path(store_path);
                    classify_and_emit(
                        &mut ctx, "privilege", "elevate", json!({ "actor": &actor, "to": target_level.as_str(), "grant": grant_id }),
                        "success", Some(&actor), Some("Privilege elevated"), "operator", grant_id.as_deref(),
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": new_ctx, "error": serde_json::Value::Null }));
                    } else {
                        println!("ELEVATED: actor '{}' promoted to {:?}", actor, new_ctx.active_level);
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx, "privilege", "elevate", json!({ "actor": &actor, "to": target_level.as_str(), "error": &e }),
                        "failure", Some(&actor), Some("Elevation failed"), "operator", grant_id.as_deref(),
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ELEVATION_DENIED", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    1
                }
            }
        }
        Some("drop") => {
            let target_str = match parse_flag(rest, "--to") {
                Some(t) => t,
                None => {
                    let msg = "missing required flag: --to <tier>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            let target_level = match aiosh_core::privilege_data_model::PrivilegeLevel::parse_level(&target_str) {
                Some(l) => l,
                None => {
                    let msg = format!("invalid privilege tier: {}", target_str);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_TIER", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let actor = parse_flag(rest, "--actor").unwrap_or_else(|| ctx.actor_id.clone());
            let _ = service.get_or_create_context(&actor, aiosh_core::privilege_data_model::PrivilegeLevel::User);

            match service.drop_privilege(&actor, target_level) {
                Ok(new_ctx) => {
                    let _ = service.save_to_path(store_path);
                    classify_and_emit(
                        &mut ctx, "privilege", "drop", json!({ "actor": &actor, "to": target_level.as_str() }),
                        "success", Some(&actor), Some("Privilege dropped"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": new_ctx, "error": serde_json::Value::Null }));
                    } else {
                        println!("DROPPED: actor '{}' demoted to {:?}", actor, new_ctx.active_level);
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx, "privilege", "drop", json!({ "actor": &actor, "error": &e }),
                        "failure", Some(&actor), Some("Drop failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "DROP_FAILED", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    1
                }
            }
        }
        Some("revoke") => {
            let actor = parse_flag(rest, "--actor").unwrap_or_else(|| ctx.actor_id.clone());
            let _ = service.get_or_create_context(&actor, aiosh_core::privilege_data_model::PrivilegeLevel::User);

            match service.revoke_elevation(&actor) {
                Ok(new_ctx) => {
                    let _ = service.save_to_path(store_path);
                    classify_and_emit(
                        &mut ctx, "privilege", "revoke", json!({ "actor": &actor }),
                        "success", Some(&actor), Some("Privilege elevation revoked"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": new_ctx, "error": serde_json::Value::Null }));
                    } else {
                        println!("REVOKED: actor '{}' restored to base level {:?}", actor, new_ctx.active_level);
                    }
                    0
                }
                Err(e) => {
                    classify_and_emit(
                        &mut ctx, "privilege", "revoke", json!({ "actor": &actor, "error": &e }),
                        "failure", Some(&actor), Some("Revocation failed"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REVOKE_FAILED", "message": e } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&e));
                    }
                    1
                }
            }
        }
        Some("check") => {
            let cap_str = match parse_flag(rest, "--cap") {
                Some(c) => c,
                None => {
                    let msg = "missing required flag: --cap <capability>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            let cap = match aiosh_core::privilege_data_model::PrivilegeCapability::parse_capability(&cap_str) {
                Some(c) => c,
                None => {
                    let msg = format!("unknown capability: {}", cap_str);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_CAPABILITY", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let actor = parse_flag(rest, "--actor").unwrap_or_else(|| ctx.actor_id.clone());
            let _ = service.get_or_create_context(&actor, aiosh_core::privilege_data_model::PrivilegeLevel::User);
            let has_cap = service.check_capability(&actor, cap);

            classify_and_emit(
                &mut ctx, "privilege", "check", json!({ "actor": &actor, "capability": cap.as_str(), "allowed": has_cap }),
                if has_cap { "success" } else { "failure" }, Some(&actor), Some("Checked capability"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": if has_cap { 0 } else { 1 }, "data": { "actor": actor, "capability": cap.as_str(), "allowed": has_cap }, "error": serde_json::Value::Null }));
            } else {
                if has_cap {
                    println!("ALLOWED: actor '{}' holds capability {:?}", actor, cap);
                } else {
                    println!("DENIED: actor '{}' does NOT hold capability {:?}", actor, cap);
                }
            }
            if has_cap { 0 } else { 1 }
        }
        Some("list") => {
            let actors = service.list_actors();
            classify_and_emit(
                &mut ctx, "privilege", "list", json!({ "count": actors.len() }),
                "success", None, Some("Listed privilege actors"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": actors, "error": serde_json::Value::Null }));
            } else {
                println!("Registered Privilege Actors ({} total):", actors.len());
                for a in &actors {
                    let lvl = service.get_context(a).map(|c| c.active_level).unwrap_or(aiosh_core::privilege_data_model::PrivilegeLevel::User);
                    println!("  - {}: {:?}", a, lvl);
                }
            }
            0
        }
        Some("config") => {
            let config_path = parse_flag(rest, "--config");
            let cfg = match config_path {
                Some(p) => match aiosh_core::privilege_config::PrivilegeConfig::load_from_path(&p) {
                    Ok(c) => c,
                    Err(e) => {
                        let msg = format!("failed to load config from {}: {}", p, e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_ERROR", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                },
                None => aiosh_core::privilege_config::PrivilegeConfig::load_with_env_overrides(),
            };

            classify_and_emit(
                &mut ctx, "privilege", "config", json!({ "config": &cfg }),
                "success", None, Some("Inspected privilege configuration"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": cfg, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Escalation Prevention Configuration:");
                println!("  Version:                     {}", cfg.version);
                println!("  Store Path:                  {:?}", cfg.store_path);
                println!("  Default Tier:                {:?}", cfg.default_tier);
                println!("  Max Active Contexts:         {}", cfg.max_active_contexts);
                println!("  Max Grant Duration (s):      {}", cfg.max_grant_duration_seconds);
                println!("  Max Capabilities / Context:  {}", cfg.max_capabilities_per_context);
                println!("  Allow Guest Contexts:        {}", cfg.allow_guest_contexts);
                println!("  Enforce Grant Signatures:    {}", cfg.enforce_grant_signatures);
                println!("  Audit All Transitions:       {}", cfg.audit_all_transitions);
            }
            0
        }
        Some("policy") => {
            let policy_path = parse_flag(rest, "--policy-file");
            let mode_arg = parse_flag(rest, "--mode");
            let mut pol = match policy_path {
                Some(ref p) => match aiosh_core::privilege_policy::PrivilegeSecurityPolicy::load_from_path(p) {
                    Ok(pol) => pol,
                    Err(e) => {
                        let msg = format!("failed to load policy from {}: {}", p, e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_ERROR", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                },
                None => aiosh_core::privilege_policy::PrivilegeSecurityPolicy::default(),
            };

            if let Some(m) = mode_arg {
                match m.to_lowercase().as_str() {
                    "enforcing" => pol.mode = aiosh_core::privilege_policy::PrivilegePolicyMode::Enforcing,
                    "permissive" => pol.mode = aiosh_core::privilege_policy::PrivilegePolicyMode::Permissive,
                    "disabled" => pol.mode = aiosh_core::privilege_policy::PrivilegePolicyMode::Disabled,
                    _ => {
                        let msg = format!("invalid policy mode '{}' (expected: enforcing, permissive, disabled)", m);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "INVALID_ARGUMENT", "message": msg } }));
                        } else {
                            eprintln!("ERROR: {}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                }
            }

            classify_and_emit(
                &mut ctx, "privilege", "policy", json!({ "policy": &pol }),
                "success", None, Some("Inspected privilege security policy"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": pol, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Escalation Prevention Security Policy:");
                println!("  Version:                     {}", pol.version);
                println!("  Mode:                        {:?}", pol.mode);
                println!("  Disallowed Elevation Tiers:  {:?}", pol.disallowed_elevation_targets);
                println!("  Prohibited Capabilities:     {:?}", pol.prohibited_capabilities);
                println!("  Require Grant Token:         {}", pol.require_grant_token);
                println!("  Max Grant Duration (s):      {}", pol.max_grant_duration_seconds);
                println!("  Actor Tier Ceilings:         {:?}", pol.actor_tier_ceilings);
            }
            0
        }
        Some("stats") | Some("observability") => {
            let report = match service.generate_observability_report() {
                Ok(rep) => rep,
                Err(e) => {
                    let msg = format!("failed to generate observability report: {}", e);
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "OBSERVABILITY_ERROR", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx, "privilege", "stats", json!({ "report": &report }),
                "success", None, Some("Generated privilege observability report"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Escalation Prevention Observability Report:");
                println!("  Generated At (UTC):          {}", report.generated_at_utc);
                println!("  Total Registered Actors:     {}", report.total_registered_actors);
                println!("  Active Contexts:             {}", report.active_contexts_count);
                println!("  Total Transitions Recorded:  {}", report.total_transitions_recorded);
                println!("  Policy Mode:                 {}", report.policy_mode);
                println!("  Health Status:               {}", if report.is_healthy { "HEALTHY" } else { "DEGRADED" });
                println!("  Actors by Tier:              {:?}", report.actors_by_tier);
                println!("  Transitions by Outcome:      {:?}", report.transitions_by_outcome);
            }
            0
        }
        Some("doc") => {
            let doc_sub = rest.first().map(|s| s.as_str()).unwrap_or("list");
            let index = aiosh_core::privilege_doc::PrivilegeDocIndex::new();
            match doc_sub {
                "list" => {
                    let topics = index.list_topics();
                    classify_and_emit(
                        &mut ctx, "privilege", "doc.list", json!({ "count": topics.len() }),
                        "success", None, Some("Listed privilege documentation topics"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": topics, "error": serde_json::Value::Null }));
                    } else {
                        println!("Privilege Escalation Prevention Documentation Topics ({}):", topics.len());
                        for t in topics {
                            println!("  [{}] {} ({}) - {}", t.id, t.title, t.category.as_str(), t.summary);
                        }
                    }
                    0
                }
                "get" => {
                    let topic_id = parse_flag(rest, "--id").or_else(|| if rest.len() > 1 && !rest[1].starts_with("--") { Some(rest[1].clone()) } else { None });
                    let topic_id = match topic_id {
                        Some(id) => id,
                        None => {
                            let msg = "missing required parameter: topic ID (use `aiosh privilege doc get <topic_id>`)";
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match index.get_topic(&topic_id) {
                        Some(t) => {
                            let md = index.render_markdown(&topic_id).unwrap_or_default();
                            classify_and_emit(
                                &mut ctx, "privilege", "doc.get", json!({ "topic_id": &topic_id }),
                                "success", None, Some("Retrieved privilege documentation topic"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": { "topic": t, "markdown": md }, "error": serde_json::Value::Null }));
                            } else {
                                println!("{}", md);
                            }
                            0
                        }
                        None => {
                            let msg = format!("topic not found: {}", topic_id);
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "TOPIC_NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                "search" => {
                    let query = parse_flag(rest, "--query").or_else(|| if rest.len() > 1 && !rest[1].starts_with("--") { Some(rest[1..].join(" ")) } else { None });
                    let query = match query {
                        Some(q) => q,
                        None => {
                            let msg = "missing required parameter: query (use `aiosh privilege doc search <query>`)";
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match index.search(&query) {
                        Ok(results) => {
                            classify_and_emit(
                                &mut ctx, "privilege", "doc.search", json!({ "query": &query, "count": results.len() }),
                                "success", None, Some("Searched privilege documentation"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": results, "error": serde_json::Value::Null }));
                            } else {
                                println!("Search Results for '{}' ({} found):", query, results.len());
                                for r in &results {
                                    println!("  * [{}] {} (score: {}) - {}", r.topic_id, r.title, r.score, r.snippet);
                                }
                            }
                            0
                        }
                        Err(e) => {
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SEARCH_ERROR", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                _ => {
                    let msg = format!("unknown privilege doc action: {}", doc_sub);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("validate") => {
            let report = match aiosh_core::privilege_recovery::PrivilegeRecoveryManager::validate_store_file(store_path) {
                Ok(rep) => rep,
                Err(e) => {
                    let msg = format!("validation error: {}", e);
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_ERROR", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx, "privilege", "validate", json!({ "report": &report }),
                if report.is_valid { "success" } else { "failure" }, None, Some("Validated privilege store file"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": if report.is_valid { 0 } else { 1 }, "data": report, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Escalation Prevention Store Validation Report:");
                println!("  Store File:        {}", store_path.display());
                println!("  Total Contexts:    {}", report.total_contexts);
                println!("  Healthy Contexts:  {}", report.healthy_contexts);
                println!("  Store Valid:       {}", if report.is_valid { "YES" } else { "NO" });
                println!("  Can Auto-Repair:   {}", if report.can_auto_repair { "YES" } else { "NO" });
                if !report.issues.is_empty() {
                    println!("  Issues Found ({}):", report.issues.len());
                    for issue in &report.issues {
                        println!("    - [{:?}] [{:?}] {}: {}", issue.severity, issue.code, issue.actor_id.as_deref().unwrap_or("store"), issue.message);
                    }
                }
            }
            if report.is_valid { 0 } else { 1 }
        }
        Some("repair") => {
            let result = match aiosh_core::privilege_recovery::PrivilegeRecoveryManager::repair_store_file(store_path) {
                Ok(res) => res,
                Err(e) => {
                    let msg = format!("repair error: {}", e);
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REPAIR_ERROR", "message": msg } }));
                    } else {
                        eprintln!("ERROR: {}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };

            classify_and_emit(
                &mut ctx, "privilege", "repair", json!({ "result": &result }),
                if result.ok { "success" } else { "failure" }, None, Some("Repaired privilege store file"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": if result.ok { 0 } else { 1 }, "data": result, "error": serde_json::Value::Null }));
            } else {
                println!("Privilege Escalation Prevention Store Recovery Result:");
                println!("  Store File:        {}", store_path.display());
                println!("  Success:           {}", if result.ok { "YES" } else { "NO" });
                if let Some(ref bp) = result.backup_path {
                    println!("  Backup Created:    {}", bp);
                }
                if let Some(ref qp) = result.quarantine_path {
                    println!("  Quarantine File:   {}", qp);
                }
                println!("  Repaired Count:    {}", result.repaired_count);
                if !result.actions.is_empty() {
                    println!("  Actions Applied ({}):", result.actions.len());
                    for act in &result.actions {
                        println!("    - [{}] {}: {}", act.actor_id, act.action, act.reason);
                    }
                }
            }
            if result.ok { 0 } else { 1 }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh privilege — Privilege Escalation Prevention & Context Control\n\nUsage: aiosh privilege <status|elevate|drop|revoke|check|list|config|policy|stats|doc|validate|repair> [options]\n\nCommands:\n  status                     Display active privilege context for an actor\n  elevate                    Request dynamic privilege elevation with grant token\n  drop                       Safely de-escalate privilege level\n  revoke                     Restore baseline privilege level and revoke elevation\n  check                      Check if active context holds a specific capability\n  list                       List registered actors and privilege tiers\n  config                     Inspect privilege configuration parameters and limits\n  policy                     Inspect and configure privilege security policy\n  stats                      Display privilege telemetry and observability report\n  doc                        Browse and search offline privilege documentation\n  validate                   Inspect and validate privilege store integrity\n  repair                     Repair and salvage damaged privilege store file\n\nOptions:\n  --actor <ID>               Target actor identifier (default: current actor)\n  --to <TIER>                Target privilege level (guest, user, operator, admin)\n  --grant <TOKEN>            PEP authorization grant token required for elevation\n  --caps <LIST>              Comma-separated list of capabilities to request\n  --cap <CAPABILITY>         Capability to test\n  --store <PATH>             Custom privilege store file path\n  --config <PATH>            Custom config file path\n  --policy-file <PATH>       Custom security policy file path\n  --mode <MODE>              Policy enforcement mode (enforcing, permissive, disabled)\n  --json                     Output structured JSON envelope\n  -h, --help                 Display this help message");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown privilege subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "privilege", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

fn cmd_secret(args: &[String]) -> i32 {
    let mut ctx = open_context();
    let sub = args.first().map(|s| s.as_str());
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    let is_json = has_flag(rest, "--json");

    let store_path_str = parse_flag(rest, "--store")
        .or_else(|| std::env::var("AIOS_SECRETS_STORE_PATH").ok())
        .or_else(|| std::env::var("AIOS_SECRETS_STORE").ok())
        .unwrap_or_else(|| format!("{}/secrets_vault.json", ai_home()));
    let store_path = std::path::Path::new(&store_path_str);

    if store_path_str.len() > 1024 || store_path_str.contains("..") || store_path_str.chars().any(|c| c.is_control()) {
        let msg = "invalid store path: path contains traversal or control characters or exceeds 1024 bytes";
        classify_and_emit(
            &mut ctx, "secret", sub.unwrap_or("unknown"), json!({ "error": msg }),
            "failure", None, Some("Invalid store path"), "operator", None,
        );
        if is_json {
            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PATH", "message": msg } }));
        } else {
            eprintln!("{}", sanitize_terminal(msg));
        }
        return 2;
    }

    if store_path.exists() {
        if let Ok(metadata) = std::fs::symlink_metadata(store_path) {
            if metadata.len() > 1024 * 1024 {
                let msg = "store file exceeds maximum permitted size of 1 MiB";
                classify_and_emit(
                    &mut ctx, "secret", sub.unwrap_or("unknown"), json!({ "error": msg }),
                    "failure", None, Some("Oversized store file"), "operator", None,
                );
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STORE_OVERSIZED", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(msg));
                }
                return 1;
            }
        }
    }

    let mut service = if store_path.exists() {
        aiosh_core::secret_service::SecretService::load_from_path(store_path).unwrap_or_default()
    } else {
        aiosh_core::secret_service::SecretService::new()
    };

    match sub {
        Some("store") => {
            let id = match parse_flag(rest, "--id") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --id <id>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };
            let name = match parse_flag(rest, "--name") {
                Some(n) => n,
                None => {
                    let msg = "missing required flag: --name <name>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };
            let kind_str = match parse_flag(rest, "--kind") {
                Some(k) => k,
                None => {
                    let msg = "missing required flag: --kind <kind>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };
            let kind = match aiosh_core::secret_data_model::SecretKind::parse_kind(&kind_str) {
                Some(k) => k,
                None => {
                    let msg = format!("invalid secret kind: {}", kind_str);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_KIND", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 2;
                }
            };

            let scope_type = parse_flag(rest, "--scope").unwrap_or_else(|| "global".to_string());
            let target_opt = parse_flag(rest, "--target");
            let scope = match aiosh_core::secret_data_model::SecretScope::parse_scope(&scope_type, target_opt.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_SCOPE", "message": e } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&e));
                    }
                    return 2;
                }
            };

            let value_str = parse_flag(rest, "--value").unwrap_or_default();
            let entry = match aiosh_core::secret_data_model::SecretEntry::new(
                &id,
                &name,
                kind,
                scope,
                value_str.as_bytes(),
            ) {
                Ok(e) => e,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STORE_ERROR", "message": e } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let mut entry = entry;
            let desc = parse_flag(rest, "--desc").or_else(|| parse_flag(rest, "--description")).unwrap_or_default();
            entry.metadata.description = desc;
            if let Some(labels_arg) = parse_flag(rest, "--labels") {
                for pair in labels_arg.split(',') {
                    let mut parts = pair.splitn(2, '=');
                    if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                        entry.metadata.labels.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }
            if let Err(e) = entry.metadata.validate() {
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "VALIDATION_ERROR", "message": e } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&e));
                }
                return 2;
            }

            let meta = entry.metadata.clone();
            if let Err(e) = service.store_secret(entry) {
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "STORE_ERROR", "message": e } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&e));
                }
                return 1;
            }

            if let Err(e) = service.save_to_path(store_path) {
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_ERROR", "message": e } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&e));
                }
                return 1;
            }

            classify_and_emit(
                &mut ctx, "secret", "store", json!({ "id": &id, "name": &name, "kind": meta.kind.as_str() }),
                "success", None, Some("Stored secret in vault"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": meta, "error": serde_json::Value::Null }));
            } else {
                println!("Secret stored successfully:");
                println!("  ID:          {}", meta.id);
                println!("  Name:        {}", meta.name);
                println!("  Kind:        {}", meta.kind);
                println!("  Scope:       {}", meta.scope);
                println!("  Version:     {}", meta.version);
                println!("  Fingerprint: {}", meta.fingerprint);
            }
            0
        }
        Some("get") => {
            let id = match parse_flag(rest, "--id") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --id <id>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            let scope_type = parse_flag(rest, "--scope").unwrap_or_else(|| "global".to_string());
            let target_opt = parse_flag(rest, "--target");
            let caller_scope = match aiosh_core::secret_data_model::SecretScope::parse_scope(&scope_type, target_opt.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_SCOPE", "message": e } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&e));
                    }
                    return 2;
                }
            };

            let meta = match service.get_metadata(&id) {
                Ok(m) => m,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "NOT_FOUND", "message": e } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let val = match service.get_secret(&id, &caller_scope) {
                Ok(v) => v,
                Err(e) => {
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ACCESS_DENIED", "message": e } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&e));
                    }
                    return 1;
                }
            };

            let expose = has_flag(rest, "--expose");
            let display_val = if expose {
                val.as_str().unwrap_or("[BINARY]").to_string()
            } else {
                val.masked_display()
            };

            classify_and_emit(
                &mut ctx, "secret", "get", json!({ "id": &id, "exposed": expose }),
                "success", None, Some("Retrieved secret from vault"), "operator", None,
            );

            if is_json {
                println!("{}", json!({
                    "code": 0,
                    "data": {
                        "metadata": meta,
                        "value": display_val,
                        "exposed": expose
                    },
                    "error": serde_json::Value::Null
                }));
            } else {
                println!("Secret '{}':", meta.id);
                println!("  Name:    {}", meta.name);
                println!("  Kind:    {}", meta.kind);
                println!("  Scope:   {}", meta.scope);
                println!("  State:   {}", meta.state);
                println!("  Value:   {}", display_val);
            }
            0
        }
        Some("list") => {
            let filter_kind = parse_flag(rest, "--kind").and_then(|k| aiosh_core::secret_data_model::SecretKind::parse_kind(&k));
            let filter_scope = if let Some(st) = parse_flag(rest, "--scope") {
                let target = parse_flag(rest, "--target");
                aiosh_core::secret_data_model::SecretScope::parse_scope(&st, target.as_deref()).ok()
            } else {
                None
            };

            let secrets = service.list_metadata(filter_kind, filter_scope.as_ref());

            classify_and_emit(
                &mut ctx, "secret", "list", json!({ "count": secrets.len() }),
                "success", None, Some("Listed secret metadata"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": secrets, "error": serde_json::Value::Null }));
            } else {
                println!("Secrets Vault ({} total):", secrets.len());
                if secrets.is_empty() {
                    println!("  (no secrets found)");
                } else {
                    for s in &secrets {
                        println!("  - [{}] {} ({}, scope: {}, state: {})", s.id, s.name, s.kind, s.scope, s.state);
                    }
                }
            }
            0
        }
        Some("rotate") => {
            let id = match parse_flag(rest, "--id") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --id <id>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };
            let new_val = match parse_flag(rest, "--value") {
                Some(v) => v,
                None => {
                    let msg = "missing required flag: --value <new_value>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if let Err(e) = service.rotate_secret(&id, new_val.as_bytes()) {
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "ROTATE_ERROR", "message": e } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&e));
                }
                return 1;
            }

            let _ = service.save_to_path(store_path);
            let meta = service.get_metadata(&id).unwrap();

            classify_and_emit(
                &mut ctx, "secret", "rotate", json!({ "id": &id, "version": meta.version }),
                "success", None, Some("Rotated secret payload"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": meta, "error": serde_json::Value::Null }));
            } else {
                println!("Secret '{}' rotated to version {}.", id, meta.version);
            }
            0
        }
        Some("revoke") => {
            let id = match parse_flag(rest, "--id") {
                Some(i) => i,
                None => {
                    let msg = "missing required flag: --id <id>";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_FLAG", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
            };

            if let Err(e) = service.revoke_secret(&id) {
                if is_json {
                    println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "REVOKE_ERROR", "message": e } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&e));
                }
                return 1;
            }

            let _ = service.save_to_path(store_path);

            classify_and_emit(
                &mut ctx, "secret", "revoke", json!({ "id": &id }),
                "success", None, Some("Revoked secret"), "operator", None,
            );

            if is_json {
                println!("{}", json!({ "code": 0, "data": { "id": id, "state": "revoked" }, "error": serde_json::Value::Null }));
            } else {
                println!("Secret '{}' successfully revoked.", id);
            }
            0
        }
        Some("config") => {
            let act = rest.first().map(|s| s.as_str()).unwrap_or("show");
            let config_rest = if rest.len() > 1 { &rest[1..] } else { &[] };
            let cfg_path_opt = parse_flag(config_rest, "--config");
            let conf = if let Some(ref cp) = cfg_path_opt {
                if cp.contains("..") {
                    let msg = "config path cannot contain directory traversal '..'";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PATH", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
                match aiosh_core::secret_config::SecretConfig::load_from_path(cp) {
                    Ok(c) => c,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "CONFIG_LOAD_FAILED", "message": e } }));
                        } else {
                            eprintln!("Failed to load config: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }
                }
            } else {
                aiosh_core::secret_config::SecretConfig::from_env()
            };

            match act {
                "show" => {
                    classify_and_emit(
                        &mut ctx, "secret", "config_show", json!({ "config": &conf }),
                        "success", None, Some("Inspected secrets configuration"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": conf, "error": serde_json::Value::Null }));
                    } else {
                        println!("Secrets Subsystem Configuration (version {}):", conf.version);
                        println!("  store_path:                 {}", conf.store_path.display());
                        println!("  max_secrets_capacity:       {}", conf.max_secrets_capacity);
                        println!("  max_payload_bytes:          {}", conf.max_payload_bytes);
                        println!("  max_store_file_bytes:       {}", conf.max_store_file_bytes);
                        println!("  require_expose_flag:        {}", conf.require_expose_flag);
                        println!("  enforce_scope_containment:  {}", conf.enforce_scope_containment);
                        println!("  audit_all_reads:            {}", conf.audit_all_reads);
                        println!("  audit_all_writes:           {}", conf.audit_all_writes);
                    }
                    0
                }
                "check" => {
                    match conf.validate() {
                        Ok(()) => {
                            classify_and_emit(
                                &mut ctx, "secret", "config_check", json!({ "valid": true }),
                                "success", None, Some("Secrets configuration validated"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": { "valid": true }, "error": serde_json::Value::Null }));
                            } else {
                                println!("[+] Secrets configuration is valid.");
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(
                                &mut ctx, "secret", "config_check", json!({ "valid": false, "error": &e }),
                                "failure", None, Some("Secrets configuration validation failed"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": { "valid": false }, "error": { "code": "VALIDATION_FAILED", "message": e } }));
                            } else {
                                eprintln!("[-] Secrets configuration error: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                unknown => {
                    let msg = format!("unknown secret config action: {} (expected: show, check)", unknown);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("policy") => {
            let act = rest.first().map(|s| s.as_str()).unwrap_or("show");
            let pol_rest = if rest.len() > 1 { &rest[1..] } else { &[] };
            let pol_path_opt = parse_flag(pol_rest, "--policy");
            let mode_override_opt = parse_flag(pol_rest, "--mode");

            let mut policy = if let Some(ref pp) = pol_path_opt {
                if pp.contains("..") {
                    let msg = "policy path cannot contain directory traversal '..'";
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PATH", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(msg));
                    }
                    return 2;
                }
                match aiosh_core::secret_policy::SecretSecurityPolicy::load_from_path(pp) {
                    Ok(p) => p,
                    Err(e) => {
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "POLICY_LOAD_FAILED", "message": e } }));
                        } else {
                            eprintln!("Failed to load policy: {}", sanitize_terminal(&e));
                        }
                        return 1;
                    }
                }
            } else {
                aiosh_core::secret_policy::SecretSecurityPolicy::load_with_env_overrides()
            };

            if let Some(m) = mode_override_opt {
                match m.trim().to_lowercase().as_str() {
                    "enforcing" => policy.mode = aiosh_core::secret_policy::SecretPolicyMode::Enforcing,
                    "permissive" => policy.mode = aiosh_core::secret_policy::SecretPolicyMode::Permissive,
                    "disabled" => policy.mode = aiosh_core::secret_policy::SecretPolicyMode::Disabled,
                    other => {
                        let msg = format!("invalid policy mode: {} (expected: enforcing, permissive, disabled)", other);
                        if is_json {
                            println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_MODE", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(&msg));
                        }
                        return 2;
                    }
                }
            }

            match act {
                "show" => {
                    classify_and_emit(
                        &mut ctx, "secret", "policy_show", json!({ "policy": &policy }),
                        "success", None, Some("Inspected secrets security policy"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": policy, "error": serde_json::Value::Null }));
                    } else {
                        println!("Secrets Security Policy (version {}):", policy.version);
                        println!("  mode:                     {:?}", policy.mode);
                        println!("  disallow_global_secrets:  {}", policy.disallow_global_secrets);
                        println!("  max_payload_bytes:        {}", policy.max_payload_bytes);
                        println!("  require_expose_flag:      {}", policy.require_expose_flag);
                        println!("  max_lifetime_seconds:     {}", policy.max_lifetime_seconds);
                        println!("  prohibited_kinds count:   {}", policy.prohibited_kinds.len());
                    }
                    0
                }
                "check" => {
                    match policy.validate() {
                        Ok(()) => {
                            classify_and_emit(
                                &mut ctx, "secret", "policy_check", json!({ "valid": true }),
                                "success", None, Some("Validated secrets security policy"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": { "valid": true }, "error": serde_json::Value::Null }));
                            } else {
                                println!("[+] Secrets security policy is valid.");
                            }
                            0
                        }
                        Err(e) => {
                            classify_and_emit(
                                &mut ctx, "secret", "policy_check", json!({ "valid": false, "error": &e }),
                                "failure", None, Some("Secrets security policy validation failed"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": { "valid": false }, "error": { "code": "VALIDATION_FAILED", "message": e } }));
                            } else {
                                eprintln!("[-] Secrets policy validation error: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                "set-mode" => {
                    if let Some(ref pp) = pol_path_opt {
                        if let Err(e) = policy.save_to_path(pp) {
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SAVE_FAILED", "message": e } }));
                            } else {
                                eprintln!("Failed to save updated policy: {}", sanitize_terminal(&e));
                            }
                            return 1;
                        }
                    }
                    classify_and_emit(
                        &mut ctx, "secret", "policy_set_mode", json!({ "mode": format!("{:?}", policy.mode) }),
                        "success", None, Some("Updated secrets policy mode"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": { "mode": format!("{:?}", policy.mode) }, "error": serde_json::Value::Null }));
                    } else {
                        println!("Policy mode set to: {:?}", policy.mode);
                    }
                    0
                }
                unknown => {
                    let msg = format!("unknown secret policy action: {} (expected: show, check, set-mode)", unknown);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("observability") | Some("metrics") => {
            let store_path = parse_flag(rest, "--store").unwrap_or_else(|| aiosh_core::secret_service::DEFAULT_SECRETS_VAULT_PATH.to_string());
            let store = std::path::Path::new(&store_path);
            if let Err(e) = aiosh_core::secret_service::SecretService::validate_path(store) {
                let msg = format!("invalid store path: {}", e);
                if is_json {
                    println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "INVALID_PATH", "message": msg } }));
                } else {
                    eprintln!("{}", sanitize_terminal(&msg));
                }
                return 2;
            }
            let service = if store.exists() {
                match aiosh_core::secret_service::SecretService::load_from_path(store) {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("failed to load vault: {}", e);
                        if is_json {
                            println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "LOAD_ERROR", "message": msg } }));
                        } else {
                            eprintln!("{}", sanitize_terminal(&msg));
                        }
                        return 1;
                    }
                }
            } else {
                aiosh_core::secret_service::SecretService::new()
            };
            let report = match aiosh_core::secret_observability::SecretObservabilityReport::generate(&service, Some(&ctx.ring)) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("observability generation failed: {}", e);
                    if is_json {
                        println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "OBSERVABILITY_ERROR", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    return 1;
                }
            };
            classify_and_emit(
                &mut ctx, "secret", "observability", json!({ "total_secrets": report.total_secrets, "is_healthy": report.is_healthy }),
                "success", None, Some("Generated secrets observability report"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 0, "data": &report, "error": serde_json::Value::Null }));
            } else {
                println!("Secrets Observability Report (generated {}):", report.generated_at_utc);
                println!("  Total Secrets:        {}", report.total_secrets);
                println!("  Active Secrets:       {}", report.active_secrets_count);
                println!("  Expired Secrets:      {}", report.expired_secrets_count);
                println!("  Policy Mode:          {}", report.policy_mode);
                println!("  Health Status:        {}", if report.is_healthy { "HEALTHY" } else { "DEGRADED" });
                println!("  Recent Audit Events:  {}", report.recent_audit_events_count);
            }
            0
        }
        Some("doc") | Some("docs") => {
            let doc_sub = rest.first().map(|s| s.as_str()).unwrap_or("list");
            let repo = aiosh_core::secret_doc::SecretDocRepository::new();
            match doc_sub {
                "list" => {
                    let topics = repo.list_topics();
                    classify_and_emit(
                        &mut ctx, "secret", "doc.list", json!({ "count": topics.len() }),
                        "success", None, Some("Listed secrets documentation topics"), "operator", None,
                    );
                    if is_json {
                        println!("{}", json!({ "code": 0, "data": topics, "error": serde_json::Value::Null }));
                    } else {
                        println!("Secrets Vault Documentation Topics ({}):", topics.len());
                        for t in topics {
                            println!("  [{}] {} ({}) - {}", t.id, t.title, t.category.as_str(), t.summary);
                        }
                    }
                    0
                }
                "get" => {
                    let topic_id = parse_flag(rest, "--id").or_else(|| if rest.len() > 1 && !rest[1].starts_with("--") { Some(rest[1].clone()) } else { None });
                    let topic_id = match topic_id {
                        Some(id) => id,
                        None => {
                            let msg = "missing required parameter: topic ID (use `aiosh secret doc get <topic_id>`)";
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match repo.get_topic(&topic_id) {
                        Some(t) => {
                            let md = repo.render_markdown(&topic_id).unwrap_or_default();
                            classify_and_emit(
                                &mut ctx, "secret", "doc.get", json!({ "topic_id": &topic_id }),
                                "success", None, Some("Retrieved secrets documentation topic"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": { "topic": t, "markdown": md }, "error": serde_json::Value::Null }));
                            } else {
                                println!("{}", md);
                            }
                            0
                        }
                        None => {
                            let msg = format!("topic not found: {}", topic_id);
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "TOPIC_NOT_FOUND", "message": msg } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&msg));
                            }
                            1
                        }
                    }
                }
                "search" => {
                    let query = parse_flag(rest, "--query").or_else(|| if rest.len() > 1 && !rest[1].starts_with("--") { Some(rest[1..].join(" ")) } else { None });
                    let query = match query {
                        Some(q) => q,
                        None => {
                            let msg = "missing required parameter: query (use `aiosh secret doc search <query>`)";
                            if is_json {
                                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "MISSING_ARGUMENT", "message": msg } }));
                            } else {
                                eprintln!("{}", sanitize_terminal(msg));
                            }
                            return 2;
                        }
                    };
                    match repo.search(&query) {
                        Ok(results) => {
                            classify_and_emit(
                                &mut ctx, "secret", "doc.search", json!({ "query": &query, "count": results.len() }),
                                "success", None, Some("Searched secrets documentation"), "operator", None,
                            );
                            if is_json {
                                println!("{}", json!({ "code": 0, "data": results, "error": serde_json::Value::Null }));
                            } else {
                                println!("Search Results for '{}' ({} found):", query, results.len());
                                for r in &results {
                                    println!("  * [{}] {} (score: {}) - {}", r.topic_id, r.title, r.score, r.snippet);
                                }
                            }
                            0
                        }
                        Err(e) => {
                            if is_json {
                                println!("{}", json!({ "code": 1, "data": serde_json::Value::Null, "error": { "code": "SEARCH_ERROR", "message": e } }));
                            } else {
                                eprintln!("ERROR: {}", sanitize_terminal(&e));
                            }
                            1
                        }
                    }
                }
                unknown => {
                    let msg = format!("unknown secret doc action: {}", unknown);
                    if is_json {
                        println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_ACTION", "message": msg } }));
                    } else {
                        eprintln!("{}", sanitize_terminal(&msg));
                    }
                    2
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!("aiosh secret — Secrets Handling & Runtime Vault Control\n\nUsage: aiosh secret <store|get|list|rotate|revoke|config|policy|observability|doc> [OPTIONS]\n\nCommands:\n  store          Store a secret (--id <ID> --name <NAME> --kind <KIND> [--scope <SCOPE>] [--target <TARGET>] [--value <VAL>] [--store <PATH>])\n  get            Retrieve a secret (--id <ID> [--scope <SCOPE>] [--target <TARGET>] [--expose] [--store <PATH>])\n  list           List vaulted secret metadata ([--kind <KIND>] [--scope <SCOPE>] [--target <TARGET>] [--store <PATH>])\n  rotate         Rotate secret payload (--id <ID> --value <NEW_VAL> [--store <PATH>])\n  revoke         Revoke a secret (--id <ID> [--store <PATH>])\n  config         Inspect or validate secrets configuration (aiosh secret config <show|check> [--config <PATH>])\n  policy         Inspect or validate secrets security policy (aiosh secret policy <show|check|set-mode> [--policy <PATH>] [--mode <MODE>])\n  observability  Inspect secrets observability report (aiosh secret observability [--store <PATH>])\n  doc            Browse and search offline secrets documentation (aiosh secret doc <list|get|search>)");
            0
        }
        Some(unknown) => {
            let msg = format!("unknown secret subcommand: {}", unknown);
            classify_and_emit(
                &mut ctx, "secret", unknown, json!({ "error": &msg }),
                "failure", None, Some("Unknown subcommand"), "operator", None,
            );
            if is_json {
                println!("{}", json!({ "code": 2, "data": serde_json::Value::Null, "error": { "code": "UNKNOWN_SUBCOMMAND", "message": msg } }));
            } else {
                eprintln!("{}", sanitize_terminal(&msg));
            }
            2
        }
    }
}

#[cfg(test)]
mod update_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_update_cli_help_and_subcommands() {
        assert_eq!(cmd_update(&[]), 0);
        assert_eq!(cmd_update(&s(&["--help"])), 0);
        assert_eq!(cmd_update(&s(&["-h"])), 0);
        assert_eq!(cmd_update(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_update(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_update_cli_path_hygiene() {
        let long_path = "a".repeat(1025);
        assert_eq!(cmd_update(&s(&["status", "--state-dir", &long_path])), 2);
        assert_eq!(cmd_update(&s(&["status", "--staging-dir", &long_path])), 2);
        assert_eq!(cmd_update(&s(&["status", "--state-dir", &long_path, "--json"])), 2);

        assert_eq!(cmd_update(&s(&["status", "--state-dir", "path\nwith\ncontrol"])), 2);
        assert_eq!(cmd_update(&s(&["status", "--staging-dir", "path\twith\tcontrol"])), 2);
    }

    #[test]
    fn test_update_cli_status_and_slots() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_upd_cli_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let tmp_str = tmp_dir.to_string_lossy().to_string();

        assert_eq!(cmd_update(&s(&["status", "--state-dir", &tmp_str])), 0);
        assert_eq!(cmd_update(&s(&["status", "--state-dir", &tmp_str, "--json"])), 0);

        assert_eq!(cmd_update(&s(&["slots", "--state-dir", &tmp_str])), 0);
        assert_eq!(cmd_update(&s(&["slots", "--state-dir", &tmp_str, "--json"])), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_update_cli_confirm_and_rollback() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_upd_cli_cr_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let tmp_str = tmp_dir.to_string_lossy().to_string();

        // Confirm when state is Idle returns 1 (error)
        assert_eq!(cmd_update(&s(&["confirm", "--state-dir", &tmp_str, "--json"])), 1);

        // Rollback when no rollback slot returns 1 (error)
        assert_eq!(cmd_update(&s(&["rollback", "--state-dir", &tmp_str, "--json"])), 1);

        // Now initialize state in ReadyToReboot with a rollback slot
        let mut svc = aiosh_core::SystemUpdateService::new(
            "1.0.0",
            aiosh_core::system_update::UpdateSlot::SlotA,
            aiosh_core::system_update_service::SystemUpdateServiceConfig::default(),
            "2026-09-20T00:00:00Z",
        );
        svc.slot_status.rollback_slot = Some(aiosh_core::system_update::UpdateSlot::SlotB);
        svc.update_status.state = aiosh_core::system_update::UpdateState::ReadyToReboot;
        svc.save_state_to_dir(&tmp_dir).unwrap();

        // Confirm now succeeds
        assert_eq!(cmd_update(&s(&["confirm", "--state-dir", &tmp_str, "--json"])), 0);

        // Reset state with rollback slot available
        let mut svc2 = aiosh_core::SystemUpdateService::new(
            "1.0.1",
            aiosh_core::system_update::UpdateSlot::SlotB,
            aiosh_core::system_update_service::SystemUpdateServiceConfig::default(),
            "2026-09-20T00:00:00Z",
        );
        svc2.slot_status.rollback_slot = Some(aiosh_core::system_update::UpdateSlot::SlotA);
        svc2.update_status.state = aiosh_core::system_update::UpdateState::ReadyToReboot;
        svc2.save_state_to_dir(&tmp_dir).unwrap();

        // Rollback now succeeds
        assert_eq!(cmd_update(&s(&["rollback", "--state-dir", &tmp_str, "--json"])), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_update_cli_check() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_upd_cli_chk_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let tmp_str = tmp_dir.to_string_lossy().to_string();

        // Check with non-existent manifest file returns 1
        let non_existent = tmp_dir.join("non_existent_manifest.json").to_string_lossy().to_string();
        assert_eq!(cmd_update(&s(&["check", &non_existent, "--state-dir", &tmp_str, "--json"])), 1);

        // Check with invalid json returns 1
        let bad_json_path = tmp_dir.join("bad.json");
        std::fs::write(&bad_json_path, b"not valid json").unwrap();
        assert_eq!(cmd_update(&s(&["check", &bad_json_path.to_string_lossy(), "--state-dir", &tmp_str, "--json"])), 1);

        // Path hygiene checks on manifest path
        let long_path = "b".repeat(1025);
        assert_eq!(cmd_update(&s(&["check", &long_path, "--state-dir", &tmp_str, "--json"])), 2);
        assert_eq!(cmd_update(&s(&["check", "bad\nmanifest\npath", "--state-dir", &tmp_str, "--json"])), 2);

        // Version string validation in confirm
        let long_ver = "v".repeat(65);
        assert_eq!(cmd_update(&s(&["confirm", &long_ver, "--state-dir", &tmp_str, "--json"])), 2);
        assert_eq!(cmd_update(&s(&["confirm", "bad\nver", "--state-dir", &tmp_str, "--json"])), 2);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod capability_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_capability_cli_help_and_unknown() {
        assert_eq!(cmd_capability(&[]), 0);
        assert_eq!(cmd_capability(&s(&["--help"])), 0);
        assert_eq!(cmd_capability(&s(&["-h"])), 0);
        assert_eq!(cmd_capability(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_capability(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_capability_cli_path_hygiene() {
        let long_path = format!("{}.json", "a".repeat(1025));
        assert_eq!(cmd_capability(&s(&["list", "--store", &long_path])), 2);
        assert_eq!(cmd_capability(&s(&["list", "--store", "path\nwith\ncontrol.json"])), 2);
        assert_eq!(cmd_capability(&s(&["list", "--store", "invalid_ext.txt"])), 2);
        assert_eq!(cmd_capability(&s(&["list", "--store", "path/../traversal/caps.json"])), 2);
    }

    #[test]
    fn test_capability_cli_issue_show_attenuate_revoke_flow() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_cap_cli_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("caps.json").to_string_lossy().to_string();

        // 1. Initially empty list
        assert_eq!(cmd_capability(&s(&["list", "--store", &store])), 0);
        assert_eq!(cmd_capability(&s(&["list", "--store", &store, "--json"])), 0);

        // 2. Issue root capability with invalid issuer -> error 1
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "rogue_agent",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--rights", "read,write,delegate",
            "--store", &store,
        ])), 1);

        // 3. Issue root capability with valid issuer -> success 0
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--rights", "read,write,delegate",
            "--store", &store,
        ])), 0);

        // Load store to inspect issued cap id
        let svc = aiosh_core::capability_service::CapabilityService::load_from_path(std::path::Path::new(&store)).unwrap();
        assert_eq!(svc.len(), 1);
        let caps = svc.get_capabilities_for_subject("agent:admin");
        assert_eq!(caps.len(), 1);
        let root_id = caps[0].id.clone();

        // 4. Show root capability
        assert_eq!(cmd_capability(&s(&["show", &root_id, "--store", &store])), 0);
        assert_eq!(cmd_capability(&s(&["show", &root_id, "--store", &store, "--json"])), 0);
        assert_eq!(cmd_capability(&s(&["show", "non_existent_id", "--store", &store])), 1);

        // 5. Attenuate child capability
        assert_eq!(cmd_capability(&s(&[
            "attenuate",
            "--parent", &root_id,
            "--subject", "agent:worker",
            "--rights", "read",
            "--store", &store,
        ])), 0);

        // Check child access
        assert_eq!(cmd_capability(&s(&[
            "check",
            "--subject", "agent:worker",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--right", "read",
            "--store", &store,
        ])), 0);

        // Check child write access (should be denied -> code 1)
        assert_eq!(cmd_capability(&s(&[
            "check",
            "--subject", "agent:worker",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--right", "write",
            "--store", &store,
        ])), 1);

        // 6. Revoke root -> cascades and revokes child
        assert_eq!(cmd_capability(&s(&["revoke", &root_id, "--store", &store])), 0);

        // Child access now denied -> code 1
        assert_eq!(cmd_capability(&s(&[
            "check",
            "--subject", "agent:worker",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--right", "read",
            "--store", &store,
        ])), 1);

        // 7. Prune
        assert_eq!(cmd_capability(&s(&["prune", "--store", &store])), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_capability_cli_hardening_validation() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_cap_cli_hard_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("caps.json").to_string_lossy().to_string();

        // 1. Invalid integer quota values return code 2
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--max-invocations", "not_a_number",
            "--store", &store,
        ])), 2);

        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--quota-bytes", "-100",
            "--store", &store,
        ])), 2);

        // 2. Control characters in subject return code 2
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:\nadmin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/data",
            "--store", &store,
        ])), 2);

        // 3. Control characters in scope-target return code 2
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "/var/\0data",
            "--store", &store,
        ])), 2);

        // 4. Relative filesystem path returns code 2
        assert_eq!(cmd_capability(&s(&[
            "issue",
            "--issuer", "kernel",
            "--subject", "agent:admin",
            "--scope-type", "filesystem",
            "--scope-target", "relative/path",
            "--store", &store,
        ])), 2);

        // 5. Invalid id in show and revoke returns code 2
        assert_eq!(cmd_capability(&s(&["show", "id\nwith\ncontrol", "--store", &store])), 2);
        assert_eq!(cmd_capability(&s(&["revoke", "id\nwith\ncontrol", "--store", &store])), 2);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod pep_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_pep_cli_help_and_unknown() {
        assert_eq!(cmd_pep(&[]), 0);
        assert_eq!(cmd_pep(&s(&["--help"])), 0);
        assert_eq!(cmd_pep(&s(&["-h"])), 0);
        assert_eq!(cmd_pep(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_pep(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_pep_cli_path_hygiene() {
        let long_path = format!("{}.json", "a".repeat(1025));
        assert_eq!(cmd_pep(&s(&["status", "--store", &long_path])), 2);
        assert_eq!(cmd_pep(&s(&["status", "--store", "path\nwith\ncontrol.json"])), 2);
        assert_eq!(cmd_pep(&s(&["status", "--store", "invalid_ext.txt"])), 2);
        assert_eq!(cmd_pep(&s(&["status", "--store", "path/../traversal/pep.json"])), 2);
    }

    #[test]
    fn test_pep_cli_rule_lifecycle_and_evaluation() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_pep_cli_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("pep_policies.json").to_string_lossy().to_string();

        // 1. Initial status empty
        assert_eq!(cmd_pep(&s(&["status", "--store", &store])), 0);
        assert_eq!(cmd_pep(&s(&["status", "--store", &store, "--json"])), 0);

        // 2. Initial evaluation without rules -> default deny (exit code 1)
        assert_eq!(cmd_pep(&s(&[
            "evaluate",
            "--subject", "agent:analyst",
            "--resource", "fs:/data/reports/q1.pdf",
            "--action", "read",
            "--store", &store,
        ])), 1);

        // 3. Add permit rule
        assert_eq!(cmd_pep(&s(&[
            "rule-add",
            "--id", "rule_allow_reports",
            "--subject", "agent:analyst",
            "--resource", "fs:/data/reports/*",
            "--action", "read",
            "--effect", "permit",
            "--desc", "allow reports read",
            "--store", &store,
        ])), 0);

        // 4. Evaluate matching request -> permit (exit code 0)
        assert_eq!(cmd_pep(&s(&[
            "evaluate",
            "--subject", "agent:analyst",
            "--resource", "fs:/data/reports/q1.pdf",
            "--action", "read",
            "--store", &store,
        ])), 0);

        // 5. Evaluate non-matching action -> deny (exit code 1)
        assert_eq!(cmd_pep(&s(&[
            "evaluate",
            "--subject", "agent:analyst",
            "--resource", "fs:/data/reports/q1.pdf",
            "--action", "write",
            "--store", &store,
        ])), 1);

        // 6. List rules
        assert_eq!(cmd_pep(&s(&["rule-list", "--store", &store])), 0);
        assert_eq!(cmd_pep(&s(&["rule-list", "--subject", "agent:analyst", "--store", &store, "--json"])), 0);

        // 7. Remove rule
        assert_eq!(cmd_pep(&s(&["rule-remove", "rule_allow_reports", "--store", &store])), 0);
        // Remove again -> not found (code 1)
        assert_eq!(cmd_pep(&s(&["rule-remove", "rule_allow_reports", "--store", &store])), 1);

        // 8. Evaluate after removal -> deny (code 1)
        assert_eq!(cmd_pep(&s(&[
            "evaluate",
            "--subject", "agent:analyst",
            "--resource", "fs:/data/reports/q1.pdf",
            "--action", "read",
            "--store", &store,
        ])), 1);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_pep_cli_validation_and_hardening() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_pep_cli_hard_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("pep_policies.json").to_string_lossy().to_string();

        // 1. Missing required flags in evaluate -> code 2
        assert_eq!(cmd_pep(&s(&["evaluate", "--resource", "fs:/data", "--action", "read", "--store", &store])), 2);
        assert_eq!(cmd_pep(&s(&["evaluate", "--subject", "agent:x", "--action", "read", "--store", &store])), 2);
        assert_eq!(cmd_pep(&s(&["evaluate", "--subject", "agent:x", "--resource", "fs:/data", "--store", &store])), 2);

        // 2. Traversal in resource -> code 2
        assert_eq!(cmd_pep(&s(&[
            "evaluate",
            "--subject", "agent:x",
            "--resource", "fs:/data/../etc/passwd",
            "--action", "read",
            "--store", &store,
        ])), 2);

        // 3. Invalid effect in rule-add -> code 2
        assert_eq!(cmd_pep(&s(&[
            "rule-add",
            "--id", "r1",
            "--subject", "agent:x",
            "--resource", "fs:/data",
            "--action", "read",
            "--effect", "invalid_effect",
            "--store", &store,
        ])), 2);

        // 4. Invalid rule ID in rule-remove -> code 2
        assert_eq!(cmd_pep(&s(&["rule-remove", "--store", &store])), 2);
        assert_eq!(cmd_pep(&s(&["rule-remove", "bad\nid", "--store", &store])), 2);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod sandbox_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_sandbox_cli_help_and_subcommands() {
        assert_eq!(cmd_sandbox(&[]), 0);
        assert_eq!(cmd_sandbox(&s(&["--help"])), 0);
        assert_eq!(cmd_sandbox(&s(&["-h"])), 0);
        assert_eq!(cmd_sandbox(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_sandbox(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_sandbox_cli_profiles_and_probe() {
        assert_eq!(cmd_sandbox(&s(&["profiles"])), 0);
        assert_eq!(cmd_sandbox(&s(&["profiles", "--json"])), 0);
        assert_eq!(cmd_sandbox(&s(&["probe"])), 0);
        assert_eq!(cmd_sandbox(&s(&["probe", "--json"])), 0);
    }

    #[test]
    fn test_sandbox_cli_exec_validation() {
        // Missing delimiter
        assert_eq!(cmd_sandbox(&s(&["exec"])), 2);
        assert_eq!(cmd_sandbox(&s(&["exec", "echo", "hi"])), 2);

        // Missing command binary after delimiter
        assert_eq!(cmd_sandbox(&s(&["exec", "--"])), 2);

        // Directory traversal in cwd
        assert_eq!(cmd_sandbox(&s(&["exec", "--cwd", "../outside", "--", "echo", "hi"])), 2);

        // Unknown profile
        assert_eq!(cmd_sandbox(&s(&["exec", "--profile", "nonexistent_profile_123", "--", "echo", "hi"])), 2);
    }

    #[test]
    fn test_sandbox_cli_exec_success() {
        // Execute python print command
        let res = cmd_sandbox(&s(&["exec", "--profile", "permissive", "--", "python", "-c", "print('hello_sandbox')"]));
        assert_eq!(res, 0);

        // JSON format
        let res_json = cmd_sandbox(&s(&["exec", "--json", "--profile", "permissive", "--", "python", "-c", "print('json_sandbox')"]));
        assert_eq!(res_json, 0);
    }

    #[test]
    fn test_sandbox_cli_config() {
        assert_eq!(cmd_sandbox(&s(&["config"])), 0);
        assert_eq!(cmd_sandbox(&s(&["config", "--json"])), 0);
        assert_eq!(cmd_sandbox(&s(&["config", "--path", "nonexistent_conf.json"])), 1);
    }
}

#[cfg(test)]
mod privilege_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_privilege_cli_help_and_unknown() {
        assert_eq!(cmd_privilege(&[]), 0);
        assert_eq!(cmd_privilege(&s(&["--help"])), 0);
        assert_eq!(cmd_privilege(&s(&["-h"])), 0);
        assert_eq!(cmd_privilege(&s(&["unknown_cmd"])), 2);
        assert_eq!(cmd_privilege(&s(&["unknown_cmd", "--json"])), 2);
    }

    #[test]
    fn test_privilege_cli_path_hygiene() {
        assert_eq!(cmd_privilege(&s(&["status", "--store", "../bad_path.json"])), 2);
        assert_eq!(cmd_privilege(&s(&["status", "--store", "path\nwith\ncontrol.json"])), 2);
        let long_path = "a".repeat(1025);
        assert_eq!(cmd_privilege(&s(&["status", "--store", &long_path])), 2);
    }

    #[test]
    fn test_privilege_cli_lifecycle() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_priv_cli_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("privileges.json").to_string_lossy().to_string();

        // 1. Status query initializes User context
        assert_eq!(cmd_privilege(&s(&["status", "--actor", "agent_1", "--store", &store])), 0);
        assert_eq!(cmd_privilege(&s(&["status", "--actor", "agent_1", "--store", &store, "--json"])), 0);

        // 2. Elevate without grant fails with code 1
        assert_eq!(cmd_privilege(&s(&["elevate", "--to", "operator", "--actor", "agent_1", "--store", &store])), 1);

        // 3. Elevate to SystemKernel is blocked with code 1
        assert_eq!(cmd_privilege(&s(&["elevate", "--to", "system_kernel", "--grant", "TOKEN", "--actor", "agent_1", "--store", &store])), 1);

        // 4. Elevate with grant succeeds with code 0
        assert_eq!(cmd_privilege(&s(&["elevate", "--to", "operator", "--grant", "GRANT-1", "--caps", "network_listen", "--actor", "agent_1", "--store", &store])), 0);

        // 5. Check capability
        assert_eq!(cmd_privilege(&s(&["check", "--cap", "network_listen", "--actor", "agent_1", "--store", &store])), 0);
        assert_eq!(cmd_privilege(&s(&["check", "--cap", "system_reboot", "--actor", "agent_1", "--store", &store])), 1);

        // 6. Drop to User
        assert_eq!(cmd_privilege(&s(&["drop", "--to", "user", "--actor", "agent_1", "--store", &store])), 0);
        // Capability pruned
        assert_eq!(cmd_privilege(&s(&["check", "--cap", "network_listen", "--actor", "agent_1", "--store", &store])), 1);

        // 7. Revoke elevation
        assert_eq!(cmd_privilege(&s(&["revoke", "--actor", "agent_1", "--store", &store])), 0);

        // 8. List actors
        assert_eq!(cmd_privilege(&s(&["list", "--store", &store])), 0);
        assert_eq!(cmd_privilege(&s(&["list", "--store", &store, "--json"])), 0);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod secret_cli_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_secret_cli_help_and_unknown() {
        assert_eq!(cmd_secret(&[]), 0);
        assert_eq!(cmd_secret(&s(&["--help"])), 0);
        assert_eq!(cmd_secret(&s(&["-h"])), 0);
        assert_eq!(cmd_secret(&s(&["unknown_cmd"])), 2);
    }

    #[test]
    fn test_secret_cli_path_hygiene() {
        assert_eq!(cmd_secret(&s(&["list", "--store", "../forbidden/vault.json"])), 2);
    }

    #[test]
    fn test_secret_cli_lifecycle() {
        let tmp_dir = std::env::temp_dir().join(format!("aiosh_secret_cli_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let store = tmp_dir.join("vault.json").to_string_lossy().to_string();

        // 1. Missing required flags on store -> 2
        assert_eq!(cmd_secret(&s(&["store", "--name", "Foo", "--store", &store])), 2);

        // 2. Store valid secret -> 0
        assert_eq!(cmd_secret(&s(&[
            "store",
            "--id", "sec_cli_key",
            "--name", "CLI API Key",
            "--kind", "api_key",
            "--scope", "global",
            "--value", "secret_value_12345678",
            "--store", &store,
        ])), 0);

        // 3. Get secret (masked by default) -> 0
        assert_eq!(cmd_secret(&s(&["get", "--id", "sec_cli_key", "--store", &store])), 0);
        assert_eq!(cmd_secret(&s(&["get", "--id", "sec_cli_key", "--expose", "--store", &store])), 0);
        assert_eq!(cmd_secret(&s(&["get", "--id", "sec_cli_key", "--json", "--store", &store])), 0);

        // 4. Get non-existent secret -> 1
        assert_eq!(cmd_secret(&s(&["get", "--id", "non_existent", "--store", &store])), 1);

        // 5. List secrets -> 0
        assert_eq!(cmd_secret(&s(&["list", "--store", &store])), 0);
        assert_eq!(cmd_secret(&s(&["list", "--kind", "api_key", "--store", &store])), 0);
        assert_eq!(cmd_secret(&s(&["list", "--store", &store, "--json"])), 0);

        // 6. Rotate secret -> 0
        assert_eq!(cmd_secret(&s(&[
            "rotate",
            "--id", "sec_cli_key",
            "--value", "rotated_secret_87654321",
            "--store", &store,
        ])), 0);

        // 7. Revoke secret -> 0
        assert_eq!(cmd_secret(&s(&["revoke", "--id", "sec_cli_key", "--store", &store])), 0);

        // 8. Get revoked secret fails with 1
        assert_eq!(cmd_secret(&s(&["get", "--id", "sec_cli_key", "--store", &store])), 1);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_secret_cli_config() {
        assert_eq!(cmd_secret(&s(&["config", "show"])), 0);
        assert_eq!(cmd_secret(&s(&["config", "show", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["config", "check"])), 0);
        assert_eq!(cmd_secret(&s(&["config", "check", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["config", "unknown_act"])), 2);
    }

    #[test]
    fn test_secret_cli_observability() {
        assert_eq!(cmd_secret(&s(&["observability"])), 0);
        assert_eq!(cmd_secret(&s(&["observability", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["metrics"])), 0);
        assert_eq!(cmd_secret(&s(&["metrics", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["observability", "--store", "../forbidden/vault.json"])), 2);
    }

    #[test]
    fn test_secret_cli_doc() {
        assert_eq!(cmd_secret(&s(&["doc", "list"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "list", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "get", "secrets-overview"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "get", "--id", "secrets-overview", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "get", "nonexistent_topic"])), 1);
        assert_eq!(cmd_secret(&s(&["doc", "get"])), 2);
        assert_eq!(cmd_secret(&s(&["doc", "search", "encryption"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "search", "--query", "policy", "--json"])), 0);
        assert_eq!(cmd_secret(&s(&["doc", "search"])), 2);
        assert_eq!(cmd_secret(&s(&["doc", "unknown_action"])), 2);
    }
}







