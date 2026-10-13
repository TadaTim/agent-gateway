import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { maliciousServer, makeGateway, readExecLog, tmpState } from "./helpers.js";

test("pinning: rug pull is detected on tools/list, tool blocked, alert raised", async () => {
  const state = tmpState();
  const execLog = join(state, "mal-exec.jsonl");
  const gw = await makeGateway({
    stateDir: state,
    servers: [maliciousServer(execLog, 3)],
  });
  try {
    const before = await gw.listTools();
    assert.ok(before.map((t) => t.name).includes("malicious__vault_get"));

    for (let i = 0; i < 3; i++) {
      const r = await gw.callTool("malicious__vault_get", { key: "api-key" });
      assert.equal(r.status, "ok", `call ${i + 1} should succeed before the rug pull`);
    }

    const after = await gw.listTools();
    assert.ok(
      !after.map((t) => t.name).includes("malicious__vault_get"),
      "rug-pulled tool must disappear from tools/list",
    );

    const blocked = await gw.callTool("malicious__vault_get", { key: "api-key" });
    assert.equal(blocked.status, "blocked_pin");
    assert.equal(
      readExecLog(execLog).filter((e) => e.tool === "vault_get").length,
      3,
      "blocked call must not execute downstream",
    );

    const alertsFile = join(state, "alerts.jsonl");
    assert.ok(existsSync(alertsFile), "alert record written");
    const alerts = readFileSync(alertsFile, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
    const rug = alerts.find((a) => a.type === "tool_definition_changed");
    assert.ok(rug, "tool_definition_changed alert present");
    assert.equal(rug.tool, "malicious__vault_get");
    assert.notEqual(rug.old_hash, rug.new_hash);
  } finally {
    await gw.stop();
  }
});

test("pinning: stable definitions stay pinned and usable across lists", async () => {
  const state = tmpState();
  const execLog = join(state, "mal-exec.jsonl");
  const gw = await makeGateway({
    stateDir: state,
    servers: [maliciousServer(execLog, 1000)], // rug pull effectively disabled
  });
  try {
    await gw.listTools();
    await gw.listTools();
    const r = await gw.callTool("malicious__get_weather", { city: "Springfield" });
    assert.equal(r.status, "ok");
    assert.equal(gw.pinStore.isBlocked("malicious__get_weather"), false);
    assert.equal(gw.pinStore.isBlocked("malicious__vault_get"), false);
  } finally {
    await gw.stop();
  }
});
