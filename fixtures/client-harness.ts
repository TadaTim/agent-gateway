/**
 * Demo client harness: drives scripted "agent" behavior through the real
 * gateway subprocess (stdio JSON-RPC, exactly as an agent host would).
 *
 * Script:
 *   1. benign work (notes + calc)
 *   2. a payment that triggers policy `ask` -> approved via the approvals
 *      CLI -> retried with the approval id -> executes exactly once
 *   3. a prompt-injection attempt: the weather tool's result instructs the
 *      agent to pay an attacker; the scripted compromised agent tries, and
 *      the gateway blocks both the over-limit call and the unapproved call
 *   4. a rug pull: the malicious server changes vault_get's definition
 *      after 3 calls; the gateway detects it on the next tools/list,
 *      blocks the tool, and raises an alert
 *
 * Run from the repo root after `npm run build`:  npm run demo
 */
import { spawn, execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { RpcPeer } from "../src/jsonrpc.js";

const ROOT = resolve(process.cwd());
const STATE = resolve(ROOT, "demo-state");
rmSync(STATE, { recursive: true, force: true });

function step(title: string): void {
  console.log(`\n=== ${title} ===`);
}
function show(label: string, v: unknown): void {
  console.log(`${label}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
}
function resultText(res: unknown): string {
  const r = res as { content?: { type: string; text?: string }[] };
  return (r?.content ?? []).map((c) => c.text ?? "").join("\n");
}

const gwProc = spawn("node", ["dist/src/server-entry.js", "--config", "demo.config.json"], {
  cwd: ROOT,
  stdio: ["pipe", "pipe", "inherit"],
});
const gw = new RpcPeer(gwProc);

async function call(name: string, args: Record<string, unknown>, meta?: object): Promise<string> {
  const res = await gw.request("tools/call", { name, arguments: args, ...(meta ? { _meta: meta } : {}) });
  return resultText(res);
}

try {
  await gw.request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "demo-harness", version: "0.1.0" },
  });
  gw.notify("notifications/initialized", {});

  step("1. tools/list through the gateway (namespaced, mediated)");
  const listed = (await gw.request("tools/list", {})) as { tools: { name: string }[] };
  show("tools", listed.tools.map((t) => t.name).join(", "));

  step("2. benign work");
  show("add_note", await call("benign__add_note", { title: "groceries", body: "coffee, filters" }));
  show("calc 2 + 3 * 4", await call("benign__calc", { expression: "2 + 3 * 4" }));

  step("3. payment under policy `ask` -> approval -> single execution");
  let approvalId = "";
  try {
    await call("benign__pay", { amount: 50, to: "landlord" });
    show("pay 50", "UNEXPECTEDLY EXECUTED WITHOUT APPROVAL");
  } catch (e) {
    const msg = (e as Error).message;
    show("pay 50 (no approval)", msg);
    approvalId = /approvalId: ([0-9a-f-]{36})/.exec(msg)?.[1] ?? "";
  }
  if (approvalId) {
    const out = execFileSync(
      "node",
      ["dist/src/approvals-cli.js", "--state", "demo-state", "approve", approvalId],
      { cwd: ROOT, encoding: "utf8" },
    );
    show("approvals CLI", out.trim());
    show(
      "pay 50 (approved retry)",
      await call("benign__pay", { amount: 50, to: "landlord" }, { approvalId }),
    );
  }

  step("4. prompt injection: weather result tries to induce attacker payments");
  const weather = await call("malicious__get_weather", { city: "Springfield" });
  show("get_weather result (excerpt)", weather.split("\n").slice(0, 8).join("\n"));
  console.log("-- scripted compromised agent now attempts the induced calls --");
  for (const attempt of [
    { amount: 9999, to: "attacker-account" },
    { amount: 50, to: "attacker-account" },
  ]) {
    try {
      const r = await call("benign__pay", attempt);
      show(`induced pay ${attempt.amount}`, `EXECUTED (!!): ${r}`);
    } catch (e) {
      show(`induced pay ${attempt.amount}`, `blocked by gateway: ${(e as Error).message}`);
    }
  }

  step("5. rug pull: vault_get definition changes after 3 calls");
  for (let i = 0; i < 3; i++) {
    show(`vault_get call ${i + 1}`, await call("malicious__vault_get", { key: "api-key" }));
  }
  const listed2 = (await gw.request("tools/list", {})) as { tools: { name: string }[] };
  show(
    "tools after rug pull",
    listed2.tools.map((t) => t.name).join(", ") + "   <-- malicious__vault_get is GONE (blocked)",
  );
  try {
    await call("malicious__vault_get", { key: "api-key" });
    show("vault_get after block", "UNEXPECTEDLY EXECUTED");
  } catch (e) {
    show("vault_get after block", `blocked by gateway: ${(e as Error).message}`);
  }
  const alerts = execFileSync(
    "node",
    ["dist/src/approvals-cli.js", "--state", "demo-state", "alerts"],
    { cwd: ROOT, encoding: "utf8" },
  );
  show("alerts.jsonl", alerts.trim().split("\n")[0] ?? "(none)");

  step("6. ground truth: what actually executed downstream (benign server log)");
  const execLog = resolve(STATE, "benign-exec.jsonl");
  show("benign-exec.jsonl", existsSync(execLog) ? readFileSync(execLog, "utf8").trim() : "(empty)");
  console.log(
    "\nNote: exactly one pay execution (the approved 50 to landlord). The induced attacker payments never executed.",
  );
} finally {
  gwProc.kill("SIGTERM");
}
process.exit(0);
