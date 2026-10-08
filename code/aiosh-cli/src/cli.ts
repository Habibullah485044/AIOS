#!/usr/bin/env node
/**
 * aiosh — the AIOS shell CLI.
 *
 * Subcommands (each emits exactly one audit row):
 *   aiosh status                 → env/Constitution/db state
 *   aiosh run <command>          → run a sandboxed host command
 *   aiosh agent <prompt>         → invoke the AI agent (stub in Sprint 0)
 *   aiosh audit tail [n]         → tail the audit ring
 *   aiosh audit verify           → verify the audit-ring hash chain
 *   aiosh grant create --scope <json>
 *                                 → issue PEP grant (audited)
 *   aiosh grant list             → list active grants
 *   aiosh grant revoke <id>      → revoke grant (audited)
 *
 * The CLI is intentionally thin: every other subsystem in AIOS talks
 * through MCP (ADR-0035 §D-2). The CLI is the user-visible surface
 * for issuing commands and inspecting the audit ring; it is not the
 * the agent's tool surface.
 */

import { Command } from "commander";

import { promisify } from "node:util";
import Database from "better-sqlite3";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";

// ESM shim: `__dirname` does not exist in ES modules.
const __dirname = dirname(fileURLToPath(import.meta.url));
import { AuditRing } from "./audit.js";
import { PepStore } from "./pep.js";
import {
  readConstitution, IMPLICIT_REVISION,
  classify,
} from "./constitution.js";
import {
  type SubCommandResult, type AuditRow, type GrantScope,
  type OutcomeKind,
} from "./types.js";
import {
  pentest_nmap, pentest_nikto, pentest_sqlmap,
  pentest_tshark, pentest_aircrack_ng,
} from "./pentest.js";
import * as retention from "./retention.js";
import * as anchors from "./anchors.js";
import * as restraint from "./restraint.js";
import * as verifier from "./verifier.js";

const aiHome = process.env["AIOSH_HOME"] ?? `${process.env["HOME"]}/.aios`;
mkdirSync(aiHome, { recursive: true });
const dbPath = join(aiHome, "audit.db");

/** Open audit ring + pep store + load active constitution. */
function openContext() {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  const ring = new AuditRing(db);
  const pep  = new PepStore(db);
  const conPath = process.env["AIOSH_CONSTITUTION"]
    ?? "/content/AIOS_MERGED/mostimportanAIfolder/AI_CONSTITUTION.md";
  const con = (() => {
    try {
      return readConstitution(conPath);
    } catch {
      return {
        revision: IMPLICIT_REVISION,
        source_path: conPath,
        loaded_at: new Date().toISOString(),
        title: "(no constitution file found)",
      };
    }
  })();
  return { ring, pep, con, db };
}

function okOut(r: SubCommandResult): void {
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = 0;
}
function errOut(r: SubCommandResult): void {
  console.error(JSON.stringify(r, null, 2));
  process.exitCode = 1;
}function emit(
  ring: AuditRing,
  con: { revision: string },
  tool: string, command: string,
  args: Record<string, unknown>,
  outcome: "ok" | "refused" | "error",
  target: string | undefined,
  outcomeDetail: string | undefined,
  actor: "user" | "agent" | "system",
  grant_token: string | undefined,
  c1: boolean, c2: boolean, c3: boolean, c4: boolean,
  classifier?: import("./constitution.js").ClassificationResult,
): AuditRow {
  // Sprint 2: when a classifier result is supplied, persist its full
  // provenance so every CLI-emitted audit row proves which rule revision
  // decided it (per ADR-0035 §D-4). When no classifier is supplied, the
  // new fields are OMITTED from the hash proto entirely (not written as
  // null), so the chain verify on the new column NULLs matches the
  // original hash. Legacy `aiosh status` / `aiosh audit verify` callers
  // pass no classifier and get exactly the same proto shape as Sprint 0.
  return ring.write({
    ts: new Date().toISOString(),
    actor,
    actor_id: `${actor}:${process.env["USER"] ?? "anon"}@${process.env["HOSTNAME"] ?? "host"}`,
    tool,
    command,
    args,
    target,
    outcome,
    outcome_detail: outcomeDetail,
    constitution_rev: con.revision,
    grant_token: grant_token ?? undefined,
    c_flags: { c1, c2, c3, c4 },
    ...(classifier ? {
      policy_revision: classifier.policy_revision,
      classify_rule_ids: classifier.rule_ids,
      classify_evidence: {
        c1: classifier.c_flags.c1.evidence,
        c2: classifier.c_flags.c2.evidence,
        c3: classifier.c_flags.c3.evidence,
        c4: classifier.c_flags.c4.evidence,
      },
      classify_overall_verdict: classifier.overall_verdict,
      classify_verdict_reason: classifier.verdict_reason,
    } : {}),
  });
}

/** Convenience wrapper: run the Sprint-1.5 classifier once, then
 * emit the audit row carrying the result. Returns the AuditRow so
 * the caller can read its id. */
function classifyAndEmit(
  ring: AuditRing,
  con: { revision: string },
  tool: string, command: string,
  args: Record<string, unknown>,
  outcome: "ok" | "refused" | "error",
  target: string | undefined,
  outcomeDetail: string | undefined,
  actor: "user" | "agent" | "system",
  grant_token: string | undefined,
): AuditRow {
  const cls = classify(tool, target, args);
  return emit(ring, con, tool, command, args, outcome, target,
              outcomeDetail, actor, grant_token,
              cls.c_flags.c1.flag, cls.c_flags.c2.flag,
              cls.c_flags.c3.flag, cls.c_flags.c4.flag,
              cls);
}

const program = new Command();
program
  .name("aiosh")
  .description("AIOS shell — Linux-substrate userspace CLI for the AIOS subsystem surface.")
  .version("0.1.0");

// ---- status ------------------------------------------------------------

program
  .command("status")
  .description("Print AIOS shell status: env, Constitution revision, audit-ring head.")
  .action(() => {
    const ctx = openContext();
    try {
      const verify = ctx.ring.verify();
      const head = ctx.ring.tail(1);
      emit(ctx.ring, ctx.con, "system.status", "aiosh status",
        {}, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "status", outcome: "ok",
        audit_id: head[0]?.id ?? -1,
        data: {
          aiosh_version: "0.1.0",
          ai_home: aiHome,
          audit_db: dbPath,
          constitution_rev: ctx.con.revision,
          constitution_title: ctx.con.title,
          constitution_source: ctx.con.source_path,
          audit_ring: {
            verify_ok: verify.ok,
            rows: verify.checked,
            head_hash: head[0]?.hash ?? null,
          },
          node: process.version,
          uptime_s: Math.round(process.uptime()),
        },
      });
    } finally { ctx.db.close(); }
  });

// ---- run ---------------------------------------------------------------

program
  .command("run <command...>")
  .description(
    "Run a host command in the AIOS sandboxed executor (Sprint 2: " +
    "Landlock + seccomp-bpf via the Rust aiosh-sandbox binary; falls " +
    "back to aiosh_mcp.sandbox (Python) only if the Rust binary is " +
    "not found; Sprint 0/1 was execFile only)."
  )
  .option("--target <target>", "Override target identifier")
  .option("--yes", "Acknowledge C-3 irreversibility (irrelevant for read-only commands)")
  .action(async (argv: string[], opts: { target?: string; yes?: boolean }) => {
    const ctx = openContext();
    try {
      const command = argv.join(" ");
      const [bin, ...args] = argv;
      // Sprint 2: wrap every process.run call through the Landlock +
      // seccomp-bpf sandbox. Preferred executor is the standalone Rust
      // binary (`aiosh-sandbox`) — no Python package required; the
      // legacy `python -m aiosh_mcp.sandbox` shim is only a fallback
      // so existing environments keep working.
      const policy = buildSandboxPolicy(command, opts.target);
      const sandbox = findSandboxExecutor();
      const sandboxArgs = [
        ...sandbox.args,
        "--policy", JSON.stringify(policy),
        "--", bin!, ...args,
      ];
      const { execFile } = await import("node:child_process");
      const exec = promisify(execFile);
      try {
        // Execute the sandbox wrapper. The sandbox wrapper itself
        // emits a one-line JSON `sandbox_applied` event to stderr so
        // we can pick it up to record the components actually
        // applied (no_new_privs, seccomp, landlock).
        const result = await exec(sandbox.cmd, sandboxArgs, {
          timeout: 30_000,
          maxBuffer: 1 << 20,
        });
        const sandboxApplied = parseSandboxApplied(result.stderr);
        const trimmed = (result.stdout + result.stderr).slice(0, 4096);
        classifyAndEmit(ctx.ring, ctx.con, "process.run", `aiosh run ${command}`,
          { bin, args, target: opts.target ?? null,
            sandbox: sandboxApplied, policy },
          "ok", opts.target ?? `${bin}`, trimmed,
          "user", undefined);
        okOut({
          ok: true, subcommand: "run", outcome: "ok",
          audit_id: -1,
          data: { bin, args, stdout: result.stdout, stderr: result.stderr,
                  truncated: (result.stdout + result.stderr).length > 4096,
                  sandbox: sandboxApplied },
        });
      } catch (e) {
        const err = e as Error & { stdout?: string; stderr?: string; code?: number };
        const sandboxApplied = parseSandboxApplied(err.stderr ?? "");
        const msg = err.message;
        classifyAndEmit(ctx.ring, ctx.con, "process.run", `aiosh run ${command}`,
          { bin, args, target: opts.target ?? null,
            sandbox: sandboxApplied, policy },
          "error", opts.target ?? `${bin}`, msg,
          "user", undefined);
        errOut({
          ok: false, subcommand: "run", outcome: "error",
          audit_id: -1, error: msg,
          data: { bin, args, sandbox: sandboxApplied },
        });
      }
    } finally { ctx.db.close(); }
  });


/** Build the sandbox policy from a process.run call. Conservative
 * defaults: read-write only /tmp and the cwd; everything else is
 * read-only. The seccomp denylist is the standard system-critical
 * blacklist (mount, reboot, ptrace, etc.) — we rely on Landlock for
 * file-access and the classifier for action-shape policy. */
function buildSandboxPolicy(
  _command: string,
  _target: string | undefined,
): Record<string, unknown> {
  return {
    paths_ro: ["/usr", "/lib", "/lib64", "/etc/ld.so.cache",
               "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/dev",
               "/proc/self"],
    paths_rw: ["/tmp"],
    paths_execute: ["/usr/bin", "/usr/local/bin", "/bin"],
    no_new_privs: true,
    seccomp_denylist: [
      "ptrace", "mount", "umount2", "reboot", "kexec_load",
      "kexec_file_load", "init_module", "finit_module",
      "delete_module", "setuid", "setgid", "setreuid", "setregid",
      "setresuid", "setresgid", "chroot", "pivot_root",
    ],
    inherit_defaults: true,
  };
}

/** Resolve the sandbox executor. Prefers the standalone Rust binary
 * (`aiosh-sandbox`) so `aiosh run` works without the Python package;
 * falls back to the legacy `python -m aiosh_mcp.sandbox` shim only
 * when the Rust binary can't be found. */
function findSandboxExecutor(): { cmd: string; args: string[] } {
  const envBin = process.env.AIOSH_SANDBOX_BIN;
  const candidates = [
    envBin,
    // Repo layouts: <root>/code/aiosh-rust/target/debug/aiosh-sandbox,
    // <root>/code/aiosh-rust/aiosh-sandbox/target/debug/aiosh-sandbox,
    // <root>/code/aiosh-rust/target/release/aiosh-sandbox.
    join(__dirname, "../../../aiosh-rust/target/debug/aiosh-sandbox"),
    join(__dirname, "../../aiosh-rust/target/debug/aiosh-sandbox"),
    join(__dirname, "../../aiosh-rust/target/release/aiosh-sandbox"),
  ].filter((p): p is string => !!p);
  for (const cand of candidates) {
    // Windows: the binary is aiosh-sandbox.exe — existsSync on the
    // extension-less path always misses there, which silently demoted
    // every Windows run to the Linux-only Python shim (T-02900).
    const exe = process.platform === "win32" ? `${cand}.exe` : cand;
    if (existsSync(exe)) {
      return { cmd: exe, args: [] };
    }
  }
  return { cmd: "python3", args: ["-m", "aiosh_mcp.sandbox"] };
}


/** Parse the one-line JSON event emitted by aiosh_mcp.sandbox's child
 * before execve. Returns null if the line isn't found or doesn't
 * parse. Used so the audit row carries which sandbox components
 * were actually applied (vs. failed due to kernel restrictions). */
function parseSandboxApplied(stderr: string): {
  components: Array<[string, string]>; event: string;
} | null {
  if (!stderr) return null;
  for (const line of stderr.split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try {
      const obj = JSON.parse(t) as {
        event?: string; components?: Array<[string, string]>;
      };
      if (obj.event === "sandbox_applied" && obj.components) {
        return {
          event: obj.event,
          components: obj.components,
        };
      }
    } catch { /* keep scanning */ }
  }
  return null;
}

// ---- agent -------------------------------------------------------------

import { runAgentLoop } from "./agent.js";

program
  .command("agent <prompt>")
  .description(
    "Invoke the AI agent loop (Sprint 2: Ollama 0.22.1 if available, " +
    "deterministic stub otherwise). Each tool call is gated by the " +
    "Sprint-1.5 rule-pack classifier and the PEP grant store, and " +
    "writes its own audit row carrying the classifier verdict."
  )
  .option("--grant <id>", "PEP grant token id (required for pentest.* tools)")
  .option("--max-steps <n>",
          "Maximum number of model+tool steps (default 8, hard cap 32)",
          "8")
  .option("--ollama-url <url>",
          "Ollama HTTP base (default http://localhost:11434)",
          "http://localhost:11434")
  .option("--ollama-model <name>",
          "Ollama model name (default qwen2.5:7b-instruct)",
          "qwen2.5:7b-instruct")
  .action(async (prompt: string,
                 opts: { grant?: string; maxSteps?: string;
                         ollamaUrl?: string; ollamaModel?: string }) => {
    const ctx = openContext();
    try {
      // Validate grant before loop (don't run any agent step with a
      // bogus grant token).
      if (opts.grant) {
        const g = ctx.pep.get(opts.grant);
        if (!g) {
          const out = classifyAndEmit(
            ctx.ring, ctx.con, "agent.invoke", "aiosh agent",
            { prompt: prompt.slice(0, 256), grant: opts.grant },
            "refused", undefined, `unknown grant ${opts.grant}`,
            "user", opts.grant);
          errOut({
            ok: false, subcommand: "agent", outcome: "refused",
            audit_id: out.id, error: `unknown grant: ${opts.grant}`,
            data: {},
          });
          return;
        }
      }
      // First audit row: agent.invoke outcome=ok captures that the
      // user has invoked the agent. Each subsequent tool call writes
      // its own audit row carrying the classifier verdict.
      classifyAndEmit(
        ctx.ring, ctx.con, "agent.invoke", "aiosh agent",
        { prompt: prompt.slice(0, 256), grant: opts.grant ?? null,
          max_steps: opts.maxSteps ?? "8" },
        "ok", undefined, undefined,
        "user", opts.grant);

      const maxSteps = Math.min(
        32, Math.max(1, Number(opts.maxSteps ?? "8") || 8));
      const result = await runAgentLoop({
        prompt,
        grant_id: opts.grant,
        ring: ctx.ring,
        constitution_rev: ctx.con.revision,
        ollama_url: opts.ollamaUrl ?? "http://localhost:11434",
        ollama_model: opts.ollamaModel ?? "qwen2.5:7b-instruct",
        max_steps: maxSteps,
        open_context_pep: ctx.pep,
      });

      okOut({
        ok: true, subcommand: "agent", outcome: "ok",
        audit_id: -1,
        data: result,
      });
    } finally { ctx.db.close(); }
  });

// ---- audit -------------------------------------------------------------

const auditCmd = program
  .command("audit")
  .description("Inspect the audit ring.");

auditCmd
  .command("tail [n]")
  .description("Tail the last N rows (default 10).")
  .action((n?: string) => {
    const ctx = openContext();
    try {
      const num = Math.max(1, Math.min(1024, Number(n ?? 10)));
      const rows = ctx.ring.tail(num);
      emit(ctx.ring, ctx.con, "audit.tail", `aiosh audit tail ${num}`,
        { n: num }, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "audit tail", outcome: "ok",
        audit_id: -1, data: { count: rows.length, rows },
      });
    } finally { ctx.db.close(); }
  });

auditCmd
  .command("verify")
  .description("Walk the ring and confirm hashes are consistent. " +
               "Sprint 3: live walk anchors at the newest rotation " +
               "checkpoint; --full also replays archived segments.")
  .option("--full", "Also replay every archived segment file end-to-end")
  .action((opts: { full?: boolean }) => {
    const ctx = openContext();
    try {
      const full = Boolean(opts.full);
      type VerifyShape = {
        ok: boolean; checked: number; brokenAt?: number;
        anchor?: string; segments?: number; mode?: string;
        archiveChecked?: number; liveChecked?: number;
        brokenSegment?: number; error?: string;
      };
      const v: VerifyShape = full
        ? retention.verifyFull(ctx.db)
        : ctx.ring.verify();
      emit(ctx.ring, ctx.con, "audit.verify",
        `aiosh audit verify${full ? " --full" : ""}`,
        { full }, v.ok ? "ok" : "refused", undefined,
        v.ok ? undefined :
          (v.error ?? `chain broken at row ${v.brokenAt}`),
        "user", undefined, false, false, false, true);
      okOut({
        ok: v.ok, subcommand: "audit verify",
        outcome: v.ok ? "ok" : "refused",
        audit_id: -1,
        data: { checked: v.checked, broken_at: v.brokenAt ?? null,
                ...(v.anchor !== undefined ? { anchor: v.anchor } : {}),
                ...(v.segments !== undefined ? { segments: v.segments } : {}),
                ...(v.archiveChecked !== undefined
                    ? { archive_checked: v.archiveChecked } : {}),
                ...(v.liveChecked !== undefined
                    ? { live_checked: v.liveChecked } : {}),
                ...(v.brokenSegment !== undefined
                    ? { broken_segment: v.brokenSegment } : {}),
                ...(v.error !== undefined ? { error: v.error } : {}),
                mode: v.mode ?? "live" },
      });
    } finally { ctx.db.close(); }
  });

// ---- audit rotate (Sprint 3 retention) ---------------------------------
// The rotation itself writes exactly one `audit.rotate` row (O-2): the
// checkpoint event is part of the chain it protects. Dry-run previews
// write nothing.

auditCmd
  .command("rotate")
  .description("Seal the oldest live rows into an archived segment " +
               "(checkpoint + JSONL archive + bloom filter) and keep " +
               "only the newest --keep rows live. Never destroys data.")
  .option("--keep <n>", "Rows to keep in the live ring", "0")
  .option("--dry-run", "Preview only; write nothing")
  .action((opts: { keep: string; dryRun?: boolean }) => {
    const ctx = openContext();
    try {
      const res = retention.rotate(ctx.db, ctx.ring, {
        keepRows: Number(opts.keep) || 0,
        dryRun: Boolean(opts.dryRun),
        actor: "user",
        actorId: `user:${process.env["USER"] ?? "anon"}@${process.env["HOSTNAME"] ?? "host"}`,
        constitutionRev: ctx.con.revision,
      });
      const out: SubCommandResult = {
        ok: res.ok,
        subcommand: "audit rotate",
        outcome: res.ok ? "ok" : "refused",
        audit_id: res.audit_id ?? -1,
        data: res,
        error: res.error,
      };
      if (res.ok) okOut(out); else errOut(out);
    } finally { ctx.db.close(); }
  });

auditCmd
  .command("segments")
  .description("List archived rotation checkpoints.")
  .action(() => {
    const ctx = openContext();
    try {
      const segs = retention.listSegments(ctx.db);
      emit(ctx.ring, ctx.con, "audit.segments", "aiosh audit segments",
        {}, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "audit segments", outcome: "ok",
        audit_id: -1, data: { count: segs.length, segments: segs },
      });
    } finally { ctx.db.close(); }
  });

auditCmd
  .command("seen <hash>")
  .description("Membership query: was this row hash ever logged? " +
               "Checks the live ring, then per-segment bloom filters. " +
               "--exact confirms bloom positives by scanning archives.")
  .option("--exact", "Confirm bloom positives via archive scan")
  .action((hash: string, opts: { exact?: boolean }) => {
    const ctx = openContext();
    try {
      const res = retention.seen(ctx.db, hash, { exact: Boolean(opts.exact) });
      emit(ctx.ring, ctx.con, "audit.seen", `aiosh audit seen ${hash}`,
        { hash, exact: Boolean(opts.exact) }, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "audit seen", outcome: "ok",
        audit_id: -1, data: res,
      });
    } finally { ctx.db.close(); }
  });

// ---- anchor (Proof of Restraint Component 3) ---------------------------

const anchorCmd = program
  .command("anchor")
  .description("Manage and verify external completeness checkpoints (Proof of Restraint Layer 2).");

anchorCmd
  .command("create")
  .description("Sign and append an external checkpoint anchor for the current audit head.")
  .option("--key <hex>", "Ed25519 private key hex (defaults to AIOSH_ANCHOR_KEY env)")
  .action((opts: { key?: string }) => {
    const ctx = openContext();
    try {
      const privKey = opts.key ?? process.env["AIOSH_ANCHOR_KEY"];
      if (!privKey) {
        errOut({ ok: false, subcommand: "anchor create", outcome: "refused", audit_id: -1, error: "No signing key provided (set AIOSH_ANCHOR_KEY or pass --key)", data: {} });
        return;
      }
      const head = ctx.ring.tail(1)[0];
      if (!head) {
        errOut({ ok: false, subcommand: "anchor create", outcome: "refused", audit_id: -1, error: "Audit ring is empty", data: {} });
        return;
      }
      const record = anchors.signCheckpoint(head.id, head.hash, head.ts, privKey);
      const anchorsPath = join(aiHome, "anchors", "anchors.jsonl");
      anchors.appendAnchor(record, anchorsPath);
      emit(ctx.ring, ctx.con, "audit.anchor", "aiosh anchor create",
        { seq: head.id, head_hash: head.hash }, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "anchor create", outcome: "ok",
        audit_id: -1, data: { anchor: record, path: anchorsPath },
      });
    } finally { ctx.db.close(); }
  });

anchorCmd
  .command("verify")
  .description("Verify audit chain integrity against external signed anchors.")
  .option("--pubkey <hex>", "Trusted Ed25519 public key hex (defaults to AIOSH_ANCHOR_PUBKEY env)")
  .action((opts: { pubkey?: string }) => {
    const ctx = openContext();
    try {
      const anchorsPath = join(aiHome, "anchors", "anchors.jsonl");
      const recordList = anchors.loadAnchors(anchorsPath);
      const trusted = opts.pubkey ?? process.env["AIOSH_ANCHOR_PUBKEY"];
      const rows = ctx.db.prepare("SELECT id, hash FROM audit_ring ORDER BY id ASC").all() as Array<{ id: number; hash: string }>;
      const result = anchors.verifyChainAgainstAnchors(rows, recordList, trusted);
      emit(ctx.ring, ctx.con, "audit.anchor", "aiosh anchor verify",
        { count: recordList.length }, result.valid ? "ok" : "refused", undefined, result.reason,
        "user", undefined, false, false, false, true);
      okOut({
        ok: result.valid, subcommand: "anchor verify",
        outcome: result.valid ? "ok" : "refused",
        audit_id: -1, data: { anchors_count: recordList.length, ...result },
      });
    } finally { ctx.db.close(); }
  });

// ---- prove (Proof of Restraint Layer 2) --------------------------------

const proveCmd = program
  .command("prove")
  .description("Generate cryptographic proofs of agent restraint and non-use.");

proveCmd
  .command("restraint")
  .description("Generate self-contained Proof of Restraint package for a grant over a time window.")
  .requiredOption("--grant <id>", "Capability grant ID")
  .requiredOption("--window-start <iso>", "Start of restraint window (ISO-8601)")
  .requiredOption("--window-end <iso>", "End of restraint window (ISO-8601)")
  .option("--anchors <path>", "Path to external anchors.jsonl file")
  .option("--out <path>", "Path to write output proof JSON file")
  .action((opts: { grant: string; windowStart: string; windowEnd: string; anchors?: string; out?: string }) => {
    const ctx = openContext();
    try {
      const anchorsPath = opts.anchors ?? join(aiHome, "anchors", "anchors.jsonl");
      const proof = restraint.generateRestraintProof(
        ctx.db,
        opts.grant,
        opts.windowStart,
        opts.windowEnd,
        anchorsPath,
      );
      if (opts.out) {
        writeFileSync(opts.out, JSON.stringify(proof, null, 2), "utf-8");
      }
      emit(ctx.ring, ctx.con, "restraint.prove", `aiosh prove restraint --grant ${opts.grant}`,
        { grant_id: opts.grant, window_start: opts.windowStart, window_end: opts.windowEnd }, "ok", opts.grant, undefined,
        "user", opts.grant, false, false, false, true);
      okOut({
        ok: true, subcommand: "prove restraint", outcome: "ok",
        audit_id: -1, data: proof as unknown as Record<string, unknown>,
      });
    } catch (err: any) {
      errOut({
        ok: false, subcommand: "prove restraint", outcome: "refused",
        audit_id: -1, error: err?.message ?? String(err), data: {},
      });
    } finally { ctx.db.close(); }
  });

proveCmd
  .command("verify")
  .description("Verify a self-contained RestraintProofPackage purely mathematically.")
  .requiredOption("--proof <path>", "Path to restraint proof JSON file")
  .option("--pubkey <hex...>", "Trusted Ed25519 public key hex(es)")
  .action((opts: { proof: string; pubkey?: string[] | string }) => {
    try {
      const keys = opts.pubkey
        ? Array.isArray(opts.pubkey)
          ? opts.pubkey
          : [opts.pubkey]
        : process.env["AIOSH_ANCHOR_PUBKEY"]
        ? [process.env["AIOSH_ANCHOR_PUBKEY"]!]
        : [];
      if (keys.length === 0) {
        errOut({
          ok: false, subcommand: "prove verify", outcome: "refused",
          audit_id: -1, error: "No trusted public key provided (set AIOSH_ANCHOR_PUBKEY or pass --pubkey)", data: {},
        });
        return;
      }
      const res = verifier.verifyRestraintProof(opts.proof, keys);
      if (res.valid) {
        okOut({
          ok: true, subcommand: "prove verify", outcome: "ok",
          audit_id: -1, data: res as unknown as Record<string, unknown>,
        });
      } else {
        errOut({
          ok: false, subcommand: "prove verify", outcome: "refused",
          audit_id: -1, error: res.reason ?? "VERIFY_FAILED", data: res as unknown as Record<string, unknown>,
        });
      }
    } catch (err: any) {
      errOut({
        ok: false, subcommand: "prove verify", outcome: "refused",
        audit_id: -1, error: err?.message ?? String(err), data: {},
      });
    }
  });

// ---- grant -------------------------------------------------------------

const grantCmd = program
  .command("grant")
  .description("Manage PEP grant tokens.");

grantCmd
  .command("create")
  .description("Create a new PEP grant token.")
  .requiredOption("--to <subject>", "Subject (e.g. agent:pentest-bot, user:alice@host)")
  .requiredOption("--tools <globs>", "Comma-separated tool globs (e.g. 'pentest.nmap,fs.read')")
  .option("--networks <cidrs>", "Comma-separated CIDRs (e.g. '10.0.0.0/8,127.0.0.0/8')")
  .option("--allow <paths>", "Comma-separated path prefixes allowed")
  .option("--deny <paths>", "Comma-separated path prefixes denied (deny wins)")
  .option("--ttl <seconds>", "Time-to-live in seconds", "3600")
  .option("--max-irreversible <n>", "Action budget for non-reversible calls")
  .action((opts: {
    to: string; tools: string; networks?: string; allow?: string; deny?: string;
    ttl: string; maxIrreversible?: string;
  }) => {
    const ctx = openContext();
    try {
      const scope: GrantScope = {
        tools: opts.tools.split(",").map((s) => s.trim()).filter(Boolean),
        networks: opts.networks ? opts.networks.split(",").map((s) => s.trim()) : undefined,
        paths: {
          allow: opts.allow ? opts.allow.split(",").map((s) => s.trim()) : [],
          deny:  opts.deny  ? opts.deny.split(",").map((s) => s.trim())  : [],
        },
        max_irreversible: opts.maxIrreversible
          ? Number(opts.maxIrreversible) : undefined,
      };
      const grant = ctx.pep.create({
        scope, ttl_seconds: Number(opts.ttl), issued_to: opts.to,
        constitution_rev: ctx.con.revision,
      });
      emit(ctx.ring, ctx.con, "pep.grant.create", "aiosh grant create",
        { scope, ttl: Number(opts.ttl), issued_to: opts.to },
        "ok", grant.grant_id, undefined,
        "user", grant.grant_id, false, false, false, true);
      okOut({
        ok: true, subcommand: "grant create", outcome: "ok",
        audit_id: -1, data: grant,
      });
    } finally { ctx.db.close(); }
  });

grantCmd
  .command("list")
  .description("List active PEP grant tokens.")
  .action(() => {
    const ctx = openContext();
    try {
      const grants = ctx.pep.list(true);
      emit(ctx.ring, ctx.con, "pep.grant.list", "aiosh grant list",
        {}, "ok", undefined, undefined,
        "user", undefined, false, false, false, true);
      okOut({
        ok: true, subcommand: "grant list", outcome: "ok",
        audit_id: -1, data: { count: grants.length, grants },
      });
    } finally { ctx.db.close(); }
  });

grantCmd
  .command("revoke <grant_id>")
  .description("Revoke a PEP grant token (valid for future calls only — past rows remain auditable).")
  .action((grant_id: string) => {
    const ctx = openContext();
    try {
      const ok = ctx.pep.revoke(grant_id);
      emit(ctx.ring, ctx.con, "pep.grant.revoke", `aiosh grant revoke ${grant_id}`,
        { grant_id }, ok ? "ok" : "refused",
        grant_id, ok ? undefined : "grant already revoked",
        "user", undefined, false, false, false, true);
      okOut({
        ok, subcommand: "grant revoke",
        outcome: ok ? "ok" : "refused",
        audit_id: -1,
        data: { grant_id, revoked: ok },
      });
    } finally { ctx.db.close(); }
  });

// ---- pentest: Pillar A wrapper bridge (Sprint 1) ----------------------
// Mirrors the MCP-side `aiosh_mcp.pentest` in TypeScript so a user
// can drive the same audit-row-emitting wrappers directly from the
// shell. Each subcommand writes ONE hash-chained audit row through
// the same ring the MCP server writes through; net effect:
// one chain, two writers.

const pentestCmd = program
  .command("pentest")
  .description(
    "Pillar-A pentest wrapper set (Sprint 1). Each requires a PEP grant (C-1).");

pentestCmd
  .command("nmap <target>")
  .description(
    "TCP service discovery (top-100 ports, no service-version probes).")
  .option("--grant <id>", "PEP grant id (required for C-1)")
  .option("--timeout-s <n>", "Wall-clock seconds", "60")
  .action(async (target: string,
                 opts: { grant?: string; timeoutS?: string }) => {
    const ctx = openContext();
    try {
      const r = await pentest_nmap(ctx.ring, ctx.pep, ctx.con.revision,
        target, { grant_id: opts.grant,
                  timeout_s: opts.timeoutS ? Number(opts.timeoutS) : 60 });
      const outcome: OutcomeKind = r.ok ? "ok"
        : r.error?.includes("binary not on PATH") ? "refused" : "error";
      const output = { ok: r.ok, subcommand: "pentest nmap",
                       outcome, audit_id: r.audit_id, data: r };
      if (!r.ok) errOut(output); else okOut(output);
    } finally { ctx.db.close(); }
  });

pentestCmd
  .command("nikto <target>")
  .description(
    "Web-server misconfig scan (tuning 123b — excludes DoS/Disclosure).")
  .option("--grant <id>", "PEP grant id (required for C-1)")
  .option("--timeout-s <n>", "Wall-clock seconds", "90")
  .action(async (target: string,
                 opts: { grant?: string; timeoutS?: string }) => {
    const ctx = openContext();
    try {
      const r = await pentest_nikto(ctx.ring, ctx.pep, ctx.con.revision,
        target, { grant_id: opts.grant,
                  timeout_s: opts.timeoutS ? Number(opts.timeoutS) : 90 });
      const outcome: OutcomeKind = r.ok ? "ok"
        : r.error?.includes("binary not on PATH") ? "refused" : "error";
      const output = { ok: r.ok, subcommand: "pentest nikto",
                       outcome, audit_id: r.audit_id, data: r };
      if (!r.ok) errOut(output); else okOut(output);
    } finally { ctx.db.close(); }
  });

pentestCmd
  .command("sqlmap <url>")
  .description(
    "SQL injection (batch, level=1 risk=1). Do not point at hosts you don't have authorisation to test.")
  .option("--grant <id>", "PEP grant id (required for C-1)")
  .option("--timeout-s <n>", "Wall-clock seconds", "300")
  .option("--level <n>", "Detection level (1-5)", "1")
  .option("--risk <n>", "Risk profile (1-3)", "1")
  .action(async (url: string,
                 opts: { grant?: string; timeoutS?: string;
                         level?: string; risk?: string }) => {
    const ctx = openContext();
    try {
      const r = await pentest_sqlmap(ctx.ring, ctx.pep, ctx.con.revision,
        url, { grant_id: opts.grant,
               timeout_s: opts.timeoutS ? Number(opts.timeoutS) : 300,
               level: opts.level ? Number(opts.level) : 1,
               risk: opts.risk ? Number(opts.risk) : 1 });
      const outcome: OutcomeKind = r.ok ? "ok"
        : r.error?.includes("binary not on PATH") ? "refused" : "error";
      const output = { ok: r.ok, subcommand: "pentest sqlmap",
                       outcome, audit_id: r.audit_id, data: r };
      if (!r.ok) errOut(output); else okOut(output);
    } finally { ctx.db.close(); }
  });

pentestCmd
  .command("tshark <pcap_path>")
  .description(
    "Offline packet-capture reading (no live interface capture).")
  .option("--grant <id>", "PEP grant id (required for C-1)")
  .option("--timeout-s <n>", "Wall-clock seconds", "30")
  .option("--display-filter <expr>", "tshark -Y filter expression")
  .action(async (pcap_path: string,
                 opts: { grant?: string; timeoutS?: string;
                         displayFilter?: string }) => {
    const ctx = openContext();
    try {
      const r = await pentest_tshark(ctx.ring, ctx.pep, ctx.con.revision,
        pcap_path, { grant_id: opts.grant,
                     timeout_s: opts.timeoutS ? Number(opts.timeoutS) : 30,
                     display_filter: opts.displayFilter });
      const outcome: OutcomeKind = r.ok ? "ok"
        : r.error?.includes("binary not on PATH") ? "refused" : "error";
      const output = { ok: r.ok, subcommand: "pentest tshark",
                       outcome, audit_id: r.audit_id, data: r };
      if (!r.ok) errOut(output); else okOut(output);
    } finally { ctx.db.close(); }
  });

pentestCmd
  .command("aircrack-ng <capture_path> <wordlist_path>")
  .description(
    "Offline dictionary crack against pre-recorded WPA/WEP handshake.")
  .option("--grant <id>", "PEP grant id (required for C-1)")
  .option("--timeout-s <n>", "Wall-clock seconds", "120")
  .action(async (capture_path: string, wordlist_path: string,
                 opts: { grant?: string; timeoutS?: string }) => {
    const ctx = openContext();
    try {
      const r = await pentest_aircrack_ng(
        ctx.ring, ctx.pep, ctx.con.revision,
        capture_path, wordlist_path,
        { grant_id: opts.grant,
          timeout_s: opts.timeoutS ? Number(opts.timeoutS) : 120 });
      const outcome: OutcomeKind = r.ok ? "ok"
        : r.error?.includes("binary not on PATH") ? "refused" : "error";
      const output = { ok: r.ok, subcommand: "pentest aircrack-ng",
                       outcome, audit_id: r.audit_id, data: r };
      if (!r.ok) errOut(output); else okOut(output);
    } finally { ctx.db.close(); }
  });

// ---- classify ----------------------------------------------------------
//
// `aiosh classify <tool> [--target <t>] [--json-args '{...}']`
//   Runs the same rule-pack the MCP dispatch gate will use in Sprint 2,
//   produces the same {c_flags, rule_ids, evidence, overall_verdict}
//   shape, and prints it as canonical-JSON for cross-language verification.
//   This is the user-facing surface for the Sprint 1.5 Constitution
//   classifier; it intentionally does NOT write an audit row (the
//   classifier is a primitive, not an action) — the audit row is written
//   by the action that the classifier *gates*.

const classifyCmd = program
  .command("classify <tool>")
  .description(
    "Constitution rule-pack classifier (Sprint 1.5). Returns " +
    "{c_flags, rule_ids, evidence, overall_verdict, policy_revision}.");

classifyCmd
  .option("--target <t>", "Target identifier (host, path, port, etc.)")
  .option("--json-args <s>",
          "Tool arguments as a JSON object string",
          "{}")
  .action((tool: string, opts: { target?: string; jsonArgs: string }) => {
    let parsed: Record<string, unknown> = {};
    try { parsed = JSON.parse(opts.jsonArgs) as Record<string, unknown>; }
    catch (e) {
      const output: SubCommandResult = {
        ok: false, subcommand: "classify", outcome: "error",
        audit_id: 0, data: { error: `invalid --json-args: ${String(e)}` },
      };
      errOut(output);
      process.exit(2);
    }
    const result = classify(tool, opts.target, parsed);
    console.log(JSON.stringify(result, null, 2));
  });

program.parseAsync(process.argv).catch((e) => {
  console.error(JSON.stringify({ ok: false, error: String(e) }, null, 2));
  process.exit(2);
});
