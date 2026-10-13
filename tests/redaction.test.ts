import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { redactValue, looksSecretValue, REDACTED } from "../src/trace.js";
import { benignServer, makeGateway, readTraces, tmpState } from "./helpers.js";

const PLANTED_KEY_SECRET = "sk-live-PLANTED-SECRET-9f8e7d6c5b";
const PLANTED_VALUE_SECRET = "AKIAIOSFODNN7EXAMPLE";
const PLANTED_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3AAAA";

test("redaction unit: secret keys and secret-shaped values are scrubbed", () => {
  const out = redactValue({
    amount: 25,
    auth_token: PLANTED_KEY_SECRET,
    note: `my aws key is ${PLANTED_VALUE_SECRET} ok`,
    nested: { password: "hunter2", jwt: PLANTED_JWT, plain: "hello" },
    list: ["normal", "Bearer abcdefghijklmnopqrstuvwxyz"],
  }) as Record<string, unknown>;
  assert.equal(out.auth_token, REDACTED);
  assert.equal(out.amount, 25);
  assert.match(String(out.note), /\[REDACTED\]/);
  const nested = out.nested as Record<string, unknown>;
  assert.equal(nested.password, REDACTED);
  assert.equal(nested.jwt, REDACTED);
  assert.equal(nested.plain, "hello");
  assert.deepEqual(out.list, ["normal", REDACTED]);
  assert.ok(looksSecretValue(PLANTED_VALUE_SECRET));
  assert.ok(!looksSecretValue("a perfectly ordinary sentence"));
});

test("tracing: a planted secret never appears in the trace store", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({ stateDir: state, servers: [benignServer(execLog)] });
  try {
    // Approved payment carrying a secret in a secret-named argument.
    const p = await gw.callTool("benign__pay", {
      amount: 10,
      to: "bob",
      auth_token: PLANTED_KEY_SECRET,
    });
    assert.equal(p.status, "approval_required");
    gw.approvalsStore.decide(p.pendingId!, "approved");
    const done = await gw.callTool(
      "benign__pay",
      { amount: 10, to: "bob", auth_token: PLANTED_KEY_SECRET },
      { approvalId: p.pendingId },
    );
    assert.equal(done.status, "ok");

    // Secret-shaped value inside a free-text argument.
    const n = await gw.callTool("benign__add_note", {
      title: "creds",
      body: `aws key ${PLANTED_VALUE_SECRET} and token ${PLANTED_JWT}`,
    });
    assert.equal(n.status, "ok");

    const raw = readFileSync(join(state, "traces.jsonl"), "utf8");
    assert.ok(!raw.includes("PLANTED-SECRET"), "planted key secret leaked into traces");
    assert.ok(!raw.includes(PLANTED_VALUE_SECRET), "planted AWS-shaped secret leaked into traces");
    assert.ok(!raw.includes(PLANTED_JWT), "planted JWT leaked into traces");
    assert.ok(raw.includes(REDACTED), "redaction marker should be present");

    const traces = readTraces(state);
    const paySpan = traces.find(
      (t) => (t.attributes as Record<string, unknown>)["gen_ai.tool.name"] === "benign__pay",
    );
    assert.ok(paySpan, "pay span recorded");
    const attrs = paySpan!.attributes as Record<string, unknown>;
    assert.match(String(attrs["tool.args_hash"]), /^sha256:[0-9a-f]{64}$/);
    assert.equal(typeof paySpan!.duration_ms, "number");
    assert.ok("gen_ai.operation.name" in attrs);
  } finally {
    await gw.stop();
  }
});
