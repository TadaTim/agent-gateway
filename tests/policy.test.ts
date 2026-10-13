import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { benignServer, makeGateway, readExecLog, tmpState } from "./helpers.js";

test("policy: ask flow — unapproved never executes, approved executes exactly once", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({ stateDir: state, servers: [benignServer(execLog)] });
  try {
    const first = await gw.callTool("benign__pay", { amount: 50, to: "landlord" });
    assert.equal(first.status, "approval_required");
    assert.ok(first.pendingId);
    assert.equal(readExecLog(execLog).filter((e) => e.tool === "pay").length, 0);

    // Retry without deciding: still no execution.
    const again = await gw.callTool("benign__pay", { amount: 50, to: "landlord" });
    assert.equal(again.status, "approval_required");
    assert.equal(readExecLog(execLog).filter((e) => e.tool === "pay").length, 0);

    // Approve, then retry with the approval id: executes.
    assert.equal(gw.approvalsStore.decide(first.pendingId!, "approved"), true);
    const done = await gw.callTool(
      "benign__pay",
      { amount: 50, to: "landlord" },
      { approvalId: first.pendingId },
    );
    assert.equal(done.status, "ok");
    assert.equal(readExecLog(execLog).filter((e) => e.tool === "pay").length, 1);

    // Replay with the same (now consumed) approval id: blocked, no second execution.
    const replay = await gw.callTool(
      "benign__pay",
      { amount: 50, to: "landlord" },
      { approvalId: first.pendingId },
    );
    assert.notEqual(replay.status, "ok");
    assert.equal(readExecLog(execLog).filter((e) => e.tool === "pay").length, 1);

    // Approval does not transfer to different arguments.
    const p2 = await gw.callTool("benign__pay", { amount: 60, to: "landlord" });
    assert.equal(p2.status, "approval_required");
    gw.approvalsStore.decide(p2.pendingId!, "approved");
    const wrongArgs = await gw.callTool(
      "benign__pay",
      { amount: 61, to: "landlord" },
      { approvalId: p2.pendingId },
    );
    assert.notEqual(wrongArgs.status, "ok");
  } finally {
    await gw.stop();
  }
});

test("policy: denied approval never executes", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({ stateDir: state, servers: [benignServer(execLog)] });
  try {
    const p = await gw.callTool("benign__pay", { amount: 10, to: "someone" });
    assert.equal(p.status, "approval_required");
    gw.approvalsStore.decide(p.pendingId!, "denied");
    const retry = await gw.callTool(
      "benign__pay",
      { amount: 10, to: "someone" },
      { approvalId: p.pendingId },
    );
    assert.notEqual(retry.status, "ok");
    assert.equal(readExecLog(execLog).filter((e) => e.tool === "pay").length, 0);
  } finally {
    await gw.stop();
  }
});

test("policy: argument constraints — over-limit amounts and path traversal blocked", async () => {
  const state = tmpState();
  const execLog = join(state, "benign-exec.jsonl");
  const gw = await makeGateway({ stateDir: state, servers: [benignServer(execLog)] });
  try {
    // Just over the max: denied by constraint even though the rule action is `ask`.
    const over = await gw.callTool("benign__pay", { amount: 100.01, to: "x" });
    assert.equal(over.status, "blocked_policy");
    // Exactly at the max: constraint passes, policy still requires approval.
    const atMax = await gw.callTool("benign__pay", { amount: 100, to: "x" });
    assert.equal(atMax.status, "approval_required");
    // Non-numeric amount smuggling.
    const smuggled = await gw.callTool("benign__pay", { amount: "50" as unknown as number, to: "x" });
    assert.equal(smuggled.status, "blocked_policy");

    // Path traversal and outside-allowlist reads are blocked before execution.
    for (const p of ["/notes/../etc/passwd", "../etc/passwd", "/etc/passwd", "/notes/../../secret"]) {
      const r = await gw.callTool("benign__read_file", { path: p });
      assert.equal(r.status, "blocked_policy", `path ${p} must be blocked`);
    }
    const okRead = await gw.callTool("benign__read_file", { path: "/notes/a.txt" });
    assert.equal(okRead.status, "ok");

    const log = readExecLog(execLog);
    assert.equal(log.filter((e) => e.tool === "pay").length, 0, "no payment executed");
    assert.equal(log.filter((e) => e.tool === "read_file").length, 1, "only the allowed read executed");
  } finally {
    await gw.stop();
  }
});
