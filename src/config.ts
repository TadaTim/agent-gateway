import { readFileSync } from "node:fs";
import type { PolicyConfig } from "./policy.js";

export interface DownstreamConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface GatewayConfig {
  servers: DownstreamConfig[];
  policy: PolicyConfig;
  degraded: {
    /** fail-closed: failures block execution. fail-open: failures favor availability (retry after downstream restart; subsystem errors alert but allow). */
    mode: "fail-open" | "fail-closed";
    downstreamTimeoutMs: number;
  };
  /** Estimated USD cost per executed tool call, keyed by full tool name; falls back to defaultCostUsd. */
  toolCosts?: Record<string, number>;
  defaultCostUsd?: number;
  stateDir: string;
}

export const PROTOCOL_VERSION = "2024-11-05";

export function loadConfig(path: string): GatewayConfig {
  return JSON.parse(readFileSync(path, "utf8")) as GatewayConfig;
}
