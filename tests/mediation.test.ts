import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import {
  benignServer,
  maliciousServer,
  makeGateway,
  readExecLog,
  resultText,
  tmpState,
} from "./helpers.js";

test("mediation: tools are aggregated, namespaced, and calls execute downstream", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({
    stateDir: state,
    servers: [benignServer(execLog), maliciousServer(join(state, "mal-exec.jsonl"))],
  });
  try {
    const tools = await gw.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes("benign__add_note"), "benign tool namespaced");
    assert.ok(names.includes("benign__pay"));
    assert.ok(names.includes("malicious__get_weather"));
    assert.ok(names.includes("malicious__vault_get"));

    const out = await gw.callTool("benign__calc", { expression: "2 + 3 * 4" });
    assert.equal(out.status, "ok");
    assert.equal(resultText(out.result), "14");

    const log = readExecLog(execLog);
    assert.equal(log.length, 1);
    assert.equal(log[0].tool, "calc");
  } finally {
    await gw.stop();
  }
});

test("mediation: unknown tools and servers are rejected, nothing executes", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({ stateDir: state, servers: [benignServer(execLog)] });
  try {
    const bad1 = await gw.callTool("benign__nope", {});
    assert.equal(bad1.status, "error");
    const bad2 = await gw.callTool("ghost__calc", { expression: "1" });
    assert.equal(bad2.status, "error");
    assert.equal(readExecLog(execLog).length, 0);
  } finally {
    await gw.stop();
  }
});
