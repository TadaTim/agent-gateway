/**
 * Flaky fixture MCP server for degraded-mode tests.
 *
 * `hang_once` stalls for HANG_MS (env FLAKY_HANG_MS, default 1500) the first
 * time it is ever called, then answers instantly. The "already hung" flag
 * lives in a state file (env FLAKY_STATE_FILE) so it survives process
 * restarts: a gateway that restarts this server (fail-open) succeeds on
 * retry, while a fail-closed gateway blocks instead. `ok_ping` always
 * answers instantly.
 */
import { existsSync, writeFileSync } from "node:fs";
import { logExec, runFixtureServer, textResult } from "./server-common.js";

const HANG_MS = Number(process.env.FLAKY_HANG_MS ?? "1500");
const STATE_FILE = process.env.FLAKY_STATE_FILE ?? "/tmp/agent-gateway-flaky-state";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

runFixtureServer({
  serverInfo: { name: "flaky-fixture", version: "1.0.0" },
  listTools: () => [
    {
      name: "hang_once",
      description: "Stalls for a while on the first call ever made, then answers.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "ok_ping",
      description: "Always answers immediately.",
      inputSchema: { type: "object", properties: {} },
    },
  ],
  callTool: async (name, args) => {
    if (name === "hang_once" && !existsSync(STATE_FILE)) {
      writeFileSync(STATE_FILE, "hung\n", "utf8");
      await sleep(HANG_MS);
      logExec(name, args);
      return textResult("hang_once answered after stall");
    }
    logExec(name, args);
    if (name === "hang_once") return textResult("hang_once answered immediately");
    if (name === "ok_ping") return textResult("pong");
    return textResult(`unknown tool ${name}`, true);
  },
});
