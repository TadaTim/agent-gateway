import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { DIST, makeGateway, readExecLog, resultText, tmpState } from "./helpers.js";
import type { GatewayConfig } from "../src/config.js";

function flakyServer(stateDir: string): GatewayConfig["servers"][number] {
  return {
    name: "flaky",
    command: "node",
    args: [join(DIST, "fixtures/flaky-server.js")],
    env: {
      EXEC_LOG: join(stateDir, "flaky-exec.jsonl"),
      FLAKY_STATE_FILE: join(stateDir, "flaky-state"),
      FLAKY_HANG_MS: "1500",
    },
  };
}

test("degraded fail-closed: downstream timeout blocks the call and the server", async () => {
  const state = tmpState();
  const gw = await makeGateway({
    stateDir: state,
    servers: [flakyServer(state)],
    degraded: { mode: "fail-closed", downstreamTimeoutMs: 300 },
  });
  try {
    const r = await gw.callTool("flaky__hang_once", {});
    assert.equal(r.status, "blocked_degraded");
    assert.ok(r.latencyMs < 1400, `should fail at timeout, not after the stall (${r.latencyMs}ms)`);

    // Server is marked unhealthy: subsequent calls are blocked without executing.
    const ping = await gw.callTool("flaky__ok_ping", {});
    assert.equal(ping.status, "blocked_degraded");
    const log = readExecLog(join(state, "flaky-exec.jsonl"));
    assert.equal(log.filter((e) => e.tool === "ok_ping").length, 0, "ok_ping must not execute");
    assert.ok(gw.degradedEventCount >= 1);
  } finally {
    await gw.stop();
  }
});

test("degraded fail-open: downstream timeout triggers restart and the retry succeeds", async () => {
  const state = tmpState();
  const gw = await makeGateway({
    stateDir: state,
    servers: [flakyServer(state)],
    degraded: { mode: "fail-open", downstreamTimeoutMs: 300 },
  });
  try {
    const r = await gw.callTool("flaky__hang_once", {});
    assert.equal(r.status, "ok");
    assert.match(resultText(r.result), /hang_once answered/);
    const log = readExecLog(join(state, "flaky-exec.jsonl"));
    assert.equal(
      log.filter((e) => e.tool === "hang_once").length,
      1,
      "exactly one downstream execution (the retry); the stalled attempt was killed mid-flight",
    );
    // Gateway remains healthy afterwards.
    const ping = await gw.callTool("flaky__ok_ping", {});
    assert.equal(ping.status, "ok");
    assert.ok(gw.degradedEventCount >= 1);
  } finally {
    await gw.stop();
  }
});
