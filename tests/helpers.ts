import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Gateway } from "../src/gateway.js";
import type { GatewayConfig } from "../src/config.js";

export const DIST = resolve(process.cwd(), "dist");

export function tmpState(prefix = "gw-state-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export interface ExecEntry {
  tool: string;
  args: Record<string, unknown>;
  at: string;
}

export function readExecLog(file: string): ExecEntry[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as ExecEntry);
}

export function readTraces(stateDir: string): Record<string, unknown>[] {
  const f = join(stateDir, "traces.jsonl");
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

export function benignServer(execLog: string): GatewayConfig["servers"][number] {
  return {
    name: "benign",
    command: "node",
    args: [join(DIST, "fixtures/benign-server.js")],
    env: { EXEC_LOG: execLog },
  };
}

export function maliciousServer(
  execLog: string,
  rugAfter = 3,
): GatewayConfig["servers"][number] {
  return {
    name: "malicious",
    command: "node",
    args: [join(DIST, "fixtures/malicious-server.js")],
    env: { EXEC_LOG: execLog, MALICIOUS_RUG_AFTER: String(rugAfter) },
  };
}

export function standardPolicy(): GatewayConfig["policy"] {
  return {
    defaultAction: "allow",
    rules: [
      {
        tool: "benign__pay",
        action: "ask",
        constraints: [{ type: "maxNumber", arg: "amount", max: 100 }],
      },
      {
        tool: "benign__read_file",
        action: "allow",
        constraints: [{ type: "pathAllowlist", arg: "path", prefixes: ["/notes"] }],
      },
    ],
  };
}

export async function makeGateway(
  partial: Partial<GatewayConfig> & { stateDir: string },
): Promise<Gateway> {
  const cfg: GatewayConfig = {
    servers: partial.servers ?? [],
    policy: partial.policy ?? standardPolicy(),
    degraded: partial.degraded ?? { mode: "fail-closed", downstreamTimeoutMs: 5000 },
    toolCosts: partial.toolCosts,
    defaultCostUsd: partial.defaultCostUsd ?? 0.0002,
    stateDir: partial.stateDir,
  };
  const gw = new Gateway(cfg);
  await gw.start();
  return gw;
}

export function resultText(res: unknown): string {
  const r = res as { content?: { type: string; text?: string }[] };
  return (r?.content ?? []).map((c) => c.text ?? "").join("\n");
}
