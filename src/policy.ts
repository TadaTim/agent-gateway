/**
 * Policy engine + file-backed approvals queue.
 *
 * Decisions are deterministic: a tool call is matched against rules
 * (exact tool name, `server__*` prefix, or `*`), argument constraints are
 * checked, and the result is allow / ask / deny. A constraint violation is
 * always a deny, regardless of the rule action. `ask` never executes: it
 * enqueues a pending approval, and only a retry carrying the approval id
 * (after a human approves it via the CLI) may proceed, exactly once.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, posix } from "node:path";
import { randomUUID } from "node:crypto";

export type PolicyAction = "allow" | "ask" | "deny";

export interface Constraint {
  type: "maxNumber" | "minNumber" | "pathAllowlist" | "stringPattern" | "enum";
  arg: string;
  max?: number;
  min?: number;
  prefixes?: string[];
  pattern?: string;
  values?: string[];
}

export interface PolicyRule {
  tool: string; // full namespaced name, "server__*", or "*"
  action: PolicyAction;
  constraints?: Constraint[];
}

export interface PolicyConfig {
  rules: PolicyRule[];
  defaultAction: PolicyAction;
}

export interface PolicyDecision {
  action: PolicyAction;
  ruleTool: string | null;
  violations: string[];
}

function ruleMatches(ruleTool: string, tool: string): boolean {
  if (ruleTool === "*") return true;
  if (ruleTool.endsWith("*")) return tool.startsWith(ruleTool.slice(0, -1));
  return ruleTool === tool;
}

function checkConstraint(c: Constraint, args: Record<string, unknown>): string | null {
  const v = args[c.arg];
  switch (c.type) {
    case "maxNumber":
      if (typeof v !== "number" || !Number.isFinite(v)) return `${c.arg}: expected a finite number`;
      if (v > (c.max ?? Infinity)) return `${c.arg}: ${v} exceeds max ${c.max}`;
      return null;
    case "minNumber":
      if (typeof v !== "number" || !Number.isFinite(v)) return `${c.arg}: expected a finite number`;
      if (v < (c.min ?? -Infinity)) return `${c.arg}: ${v} below min ${c.min}`;
      return null;
    case "pathAllowlist": {
      if (typeof v !== "string") return `${c.arg}: expected a string path`;
      const normalized = posix.normalize(v.replace(/\\/g, "/"));
      if (normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) {
        return `${c.arg}: path traversal rejected (${v})`;
      }
      const prefixes = c.prefixes ?? [];
      if (!prefixes.some((p) => normalized === p || normalized.startsWith(p.endsWith("/") ? p : p + "/"))) {
        return `${c.arg}: ${normalized} is outside the allowlist [${prefixes.join(", ")}]`;
      }
      return null;
    }
    case "stringPattern": {
      if (typeof v !== "string") return `${c.arg}: expected a string`;
      if (!new RegExp(c.pattern ?? "").test(v)) return `${c.arg}: does not match required pattern`;
      return null;
    }
    case "enum": {
      if (!(c.values ?? []).includes(String(v))) return `${c.arg}: ${String(v)} not in allowed set`;
      return null;
    }
  }
}

export class PolicyEngine {
  constructor(private readonly cfg: PolicyConfig) {}

  evaluate(tool: string, args: Record<string, unknown>): PolicyDecision {
    const rule = this.cfg.rules.find((r) => ruleMatches(r.tool, tool));
    if (!rule) return { action: this.cfg.defaultAction, ruleTool: null, violations: [] };
    const violations: string[] = [];
    for (const c of rule.constraints ?? []) {
      const msg = checkConstraint(c, args);
      if (msg) violations.push(msg);
    }
    if (violations.length > 0) return { action: "deny", ruleTool: rule.tool, violations };
    return { action: rule.action, ruleTool: rule.tool, violations: [] };
  }
}

// ---------------------------------------------------------------------------
// Approvals queue (file-backed)
// ---------------------------------------------------------------------------

export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed";

export interface ApprovalRecord {
  id: string;
  tool: string;
  args_hash: string;
  args_redacted: unknown;
  status: ApprovalStatus;
  created_at: string;
  decided_at?: string;
}

export class ApprovalsStore {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
    if (!existsSync(file)) writeFileSync(file, "[]\n", "utf8");
  }

  private load(): ApprovalRecord[] {
    try {
      return JSON.parse(readFileSync(this.file, "utf8")) as ApprovalRecord[];
    } catch {
      return [];
    }
  }

  private save(records: ApprovalRecord[]): void {
    writeFileSync(this.file, JSON.stringify(records, null, 2) + "\n", "utf8");
  }

  /** Reuse an existing pending record for the same tool+args, else create one. */
  enqueue(tool: string, argsHash: string, argsRedacted: unknown): ApprovalRecord {
    const records = this.load();
    const existing = records.find(
      (r) => r.tool === tool && r.args_hash === argsHash && r.status === "pending",
    );
    if (existing) return existing;
    const rec: ApprovalRecord = {
      id: randomUUID(),
      tool,
      args_hash: argsHash,
      args_redacted: argsRedacted,
      status: "pending",
      created_at: new Date().toISOString(),
    };
    records.push(rec);
    this.save(records);
    return rec;
  }

  get(id: string): ApprovalRecord | undefined {
    return this.load().find((r) => r.id === id);
  }

  list(): ApprovalRecord[] {
    return this.load();
  }

  decide(id: string, status: "approved" | "denied"): boolean {
    const records = this.load();
    const rec = records.find((r) => r.id === id);
    if (!rec || rec.status !== "pending") return false;
    rec.status = status;
    rec.decided_at = new Date().toISOString();
    this.save(records);
    return true;
  }

  /** Mark an approved record consumed (single use). Returns false if not usable. */
  consume(id: string): boolean {
    const records = this.load();
    const rec = records.find((r) => r.id === id);
    if (!rec || rec.status !== "approved") return false;
    rec.status = "consumed";
    rec.decided_at = new Date().toISOString();
    this.save(records);
    return true;
  }
}
