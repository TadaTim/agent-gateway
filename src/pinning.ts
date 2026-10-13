/**
 * Tool pinning (rug-pull defense).
 *
 * On first sight of a tool, the gateway pins a hash of its name + description
 * + input schema (trust on first use, recorded in the pin store). On every
 * subsequent tools/list, the hash is recomputed; if a server's definition of
 * a tool has changed, the tool is blocked (excluded from tools/list and
 * rejected by tools/call) and an alert record is appended to alerts.jsonl.
 * Re-pinning a changed tool is an explicit operator action (`approvePin`).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalStringify, hashValue } from "./trace.js";

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export function toolDefHash(tool: ToolDef): string {
  return hashValue({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
  });
}

export interface PinRecord {
  hash: string;
  pinned_at: string;
  blocked: boolean;
  alerted_hash?: string;
}

export interface AlertRecord {
  type: "tool_definition_changed" | "degraded_mode" | "policy_subsystem_error";
  tool?: string;
  server?: string;
  old_hash?: string;
  new_hash?: string;
  detail: string;
  at: string;
}

export class AlertStore {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
  }
  append(alert: AlertRecord): void {
    appendFileSync(this.file, JSON.stringify(alert) + "\n", "utf8");
  }
}

export class PinStore {
  private pins: Record<string, PinRecord>;

  constructor(
    private readonly file: string,
    private readonly alerts: AlertStore,
  ) {
    mkdirSync(dirname(file), { recursive: true });
    if (existsSync(file)) {
      try {
        this.pins = JSON.parse(readFileSync(file, "utf8")) as Record<string, PinRecord>;
      } catch {
        this.pins = {};
      }
    } else {
      this.pins = {};
      this.save();
    }
  }

  private save(): void {
    writeFileSync(this.file, JSON.stringify(this.pins, null, 2) + "\n", "utf8");
  }

  /**
   * Check a freshly listed tool definition against its pin.
   * Returns "pinned" (first sight), "ok", or "changed" (now blocked).
   */
  check(fullName: string, server: string, tool: ToolDef): "pinned" | "ok" | "changed" {
    const hash = toolDefHash(tool);
    const existing = this.pins[fullName];
    if (!existing) {
      this.pins[fullName] = { hash, pinned_at: new Date().toISOString(), blocked: false };
      this.save();
      return "pinned";
    }
    if (existing.hash === hash) {
      if (existing.blocked) {
        existing.blocked = false;
        this.save();
      }
      return "ok";
    }
    // Definition changed: block and alert (once per distinct new hash).
    existing.blocked = true;
    if (existing.alerted_hash !== hash) {
      this.alerts.append({
        type: "tool_definition_changed",
        tool: fullName,
        server,
        old_hash: existing.hash,
        new_hash: hash,
        detail: `tool definition for ${fullName} changed after pinning; tool blocked pending operator re-pin`,
        at: new Date().toISOString(),
      });
      existing.alerted_hash = hash;
    }
    this.save();
    return "changed";
  }

  isBlocked(fullName: string): boolean {
    return this.pins[fullName]?.blocked === true;
  }

  /** Operator action: accept the current definition as the new pin. */
  approvePin(fullName: string, tool: ToolDef): void {
    this.pins[fullName] = {
      hash: toolDefHash(tool),
      pinned_at: new Date().toISOString(),
      blocked: false,
    };
    this.save();
  }

  get(fullName: string): PinRecord | undefined {
    return this.pins[fullName];
  }
}

export function describeCanonical(tool: ToolDef): string {
  return canonicalStringify({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
  });
}
