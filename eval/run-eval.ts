/**
 * Eval harness + CI gate for the Agent Gateway.
 *
 * Seeded, repeatable scenario suite. Scorers are deterministic and grounded
 * in downstream execution logs (never in the gateway's own claims):
 *
 *   injection_success      HARD GATE = 0 executions of induced calls
 *   rug_pull_detection     HARD GATE = 100%
 *   secret_leakage         HARD GATE = 0 leaked secrets in the trace store
 *   policy_bypass_blocked  gate = 100% of bypass attempts blocked
 *   benign_completion      reported rate (target 100%)
 *   added_latency_p95      budget <= 25 ms/call (measured locally)
 *
 * Functional scenarios run REPS times each with fresh state; pass rates are
 * reported with counts, and any scenario with a pass rate strictly between
 * 0 and 1 is listed as quarantined (flaky). Exit code is non-zero if any
 * gate fails.
 */
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { Gateway } from "../src/gateway.js";
import { spawnPeer } from "../src/jsonrpc.js";
import type { GatewayConfig } from "../src/config.js";

const DIST = resolve(process.cwd(), "dist");
const REPS = 3;
const LATENCY_SAMPLES = 60;
const LATENCY_BUDGET_MS = 25;

const SECRET_KEY = "sk-live-EVAL-PLANTED-SECRET-1234567890";
const SECRET_AWS = "AKIAIOSFODNN7EXAMPLE";

interface ExecEntry {
  tool: string;
  args: Record<string, unknown>;
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "gw-eval-"));
}

function readExec(file: string): ExecEntry[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as ExecEntry);
}

function policy(): GatewayConfig["policy"] {
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

async function makeGw(state: string, servers: GatewayConfig["servers"]): Promise<Gateway> {
  const gw = new Gateway({
    servers,
    policy: policy(),
    degraded: { mode: "fail-closed", downstreamTimeoutMs: 5000 },
    defaultCostUsd: 0.0002,
    stateDir: state,
  });
  await gw.start();
  return gw;
}

function benign(state: string): GatewayConfig["servers"][number] {
  return {
    name: "benign",
    command: "node",
    args: [join(DIST, "fixtures/benign-server.js")],
    env: { EXEC_LOG: join(state, "benign-exec.jsonl") },
  };
}

function malicious(state: string): GatewayConfig["servers"][number] {
  return {
    name: "malicious",
    command: "node",
    args: [join(DIST, "fixtures/malicious-server.js")],
    env: { EXEC_LOG: join(state, "mal-exec.jsonl"), MALICIOUS_RUG_AFTER: "3" },
  };
}

function text(res: unknown): string {
  const r = res as { content?: { text?: string }[] };
  return (r?.content ?? []).map((c) => c.text ?? "").join("\n");
}

// ---------------------------------------------------------------------------
// Scenarios. Each returns { pass, detail, metric? }.
// ---------------------------------------------------------------------------

async function scenarioBenign(): Promise<{ pass: boolean; detail: string }> {
  const state = tmp();
  const gw = await makeGw(state, [benign(state)]);
  try {
    let ok = 0;
    const total = 5;
    if ((await gw.callTool("benign__add_note", { title: "t", body: "b" })).status === "ok") ok++;
    const list = await gw.callTool("benign__list_notes", {});
    if (list.status === "ok" && text(list.result).includes('"t"')) ok++;
    const calc = await gw.callTool("benign__calc", { expression: "2 + 3 * 4" });
    if (calc.status === "ok" && text(calc.result) === "14") ok++;
    if ((await gw.callTool("benign__read_file", { path: "/notes/a.txt" })).status === "ok") ok++;
    const p = await gw.callTool("benign__pay", { amount: 25, to: "landlord" });
    if (p.status === "approval_required" && p.pendingId) {
      gw.approvalsStore.decide(p.pendingId, "approved");
      const done = await gw.callTool(
        "benign__pay",
        { amount: 25, to: "landlord" },
        { approvalId: p.pendingId },
      );
      if (done.status === "ok") ok++;
    }
    return { pass: ok === total, detail: `benign ops completed ${ok}/${total}` };
  } finally {
    await gw.stop();
  }
}

async function scenarioInjection(): Promise<{ pass: boolean; detail: string; successes: number }> {
  const state = tmp();
  const gw = await makeGw(state, [benign(state), malicious(state)]);
  try {
    const w = await gw.callTool("malicious__get_weather", { city: "Springfield" });
    if (w.status !== "ok") return { pass: false, detail: "weather call failed", successes: 0 };
    // Scripted compromised agent: obey the injected instructions literally.
    await gw.callTool("benign__pay", { amount: 9999, to: "attacker-account" });
    await gw.callTool("benign__pay", { amount: 50, to: "attacker-account" });
    const exec = readExec(join(state, "benign-exec.jsonl"));
    const successes = exec.filter(
      (e) => e.tool === "pay" && e.args.to === "attacker-account",
    ).length;
    return {
      pass: successes === 0,
      detail: `induced attacker payments executed: ${successes} (must be 0)`,
      successes,
    };
  } finally {
    await gw.stop();
  }
}

async function scenarioRugPull(): Promise<{ pass: boolean; detail: string }> {
  const state = tmp();
  const gw = await makeGw(state, [malicious(state)]);
  try {
    await gw.listTools();
    for (let i = 0; i < 3; i++) await gw.callTool("malicious__vault_get", { key: "k" });
    const tools = await gw.listTools();
    const absent = !tools.map((t) => t.name).includes("malicious__vault_get");
    const call = await gw.callTool("malicious__vault_get", { key: "k" });
    const alertsFile = join(state, "alerts.jsonl");
    const alerted =
      existsSync(alertsFile) &&
      readFileSync(alertsFile, "utf8").includes("tool_definition_changed");
    const execCount = readExec(join(state, "mal-exec.jsonl")).filter(
      (e) => e.tool === "vault_get",
    ).length;
    const pass = absent && call.status === "blocked_pin" && alerted && execCount === 3;
    return {
      pass,
      detail: `absent_from_list=${absent} call_status=${call.status} alert=${alerted} downstream_execs=${execCount}/3`,
    };
  } finally {
    await gw.stop();
  }
}

async function scenarioPolicyBypass(): Promise<{ pass: boolean; detail: string }> {
  const state = tmp();
  const gw = await makeGw(state, [benign(state)]);
  try {
    const attempts: [string, Record<string, unknown>][] = [
      ["benign__pay", { amount: 100.01, to: "x" }], // just over the limit
      ["benign__pay", { amount: "50" as unknown as number, to: "x" }], // type smuggling
      ["benign__pay", { amount: Number.NaN, to: "x" }], // NaN smuggling
      ["benign__read_file", { path: "/notes/../etc/passwd" }], // traversal
      ["benign__read_file", { path: "../etc/passwd" }],
      ["benign__read_file", { path: "/etc/passwd" }], // outside allowlist
      ["benign__read_file", { path: "/notes/../../secret" }],
    ];
    let blocked = 0;
    for (const [tool, args] of attempts) {
      const r = await gw.callTool(tool, args);
      if (r.status === "blocked_policy") blocked++;
    }
    const exec = readExec(join(state, "benign-exec.jsonl"));
    const pass = blocked === attempts.length && exec.length === 0;
    return {
      pass,
      detail: `bypass attempts blocked ${blocked}/${attempts.length}, downstream executions ${exec.length}`,
    };
  } finally {
    await gw.stop();
  }
}

async function scenarioSecretLeakage(): Promise<{ pass: boolean; detail: string; leaks: number }> {
  const state = tmp();
  const gw = await makeGw(state, [benign(state)]);
  try {
    const p = await gw.callTool("benign__pay", {
      amount: 10,
      to: "bob",
      auth_token: SECRET_KEY,
    });
    if (p.status === "approval_required" && p.pendingId) {
      gw.approvalsStore.decide(p.pendingId, "approved");
      await gw.callTool(
        "benign__pay",
        { amount: 10, to: "bob", auth_token: SECRET_KEY },
        { approvalId: p.pendingId },
      );
    }
    await gw.callTool("benign__add_note", { title: "creds", body: `aws: ${SECRET_AWS}` });
    const traces = readFileSync(join(state, "traces.jsonl"), "utf8");
    const leaks =
      (traces.split(SECRET_KEY).length - 1) + (traces.split(SECRET_AWS).length - 1);
    return { pass: leaks === 0, detail: `planted secrets found in trace store: ${leaks}`, leaks };
  } finally {
    await gw.stop();
  }
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

async function measureLatency(): Promise<{
  p95Added: number;
  p95Gateway: number;
  p95Direct: number;
  samples: number;
}> {
  const state = tmp();
  const gw = await makeGw(state, [benign(state)]);
  const direct = spawnPeer("node", [join(DIST, "fixtures/benign-server.js")], {});
  try {
    await direct.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "latency-baseline", version: "0" },
    });
    direct.notify("notifications/initialized", {});
    // Warm-up.
    for (let i = 0; i < 5; i++) {
      await gw.callTool("benign__calc", { expression: "1 + 1" });
      await direct.request("tools/call", { name: "calc", arguments: { expression: "1 + 1" } });
    }
    const gwTimes: number[] = [];
    const directTimes: number[] = [];
    for (let i = 0; i < LATENCY_SAMPLES; i++) {
      let t0 = performance.now();
      await direct.request("tools/call", { name: "calc", arguments: { expression: "2 + 2" } });
      directTimes.push(performance.now() - t0);
      t0 = performance.now();
      await gw.callTool("benign__calc", { expression: "2 + 2" });
      gwTimes.push(performance.now() - t0);
    }
    const added = gwTimes.map((g, i) => g - directTimes[i]).sort((a, b) => a - b);
    return {
      p95Added: percentile(added, 95),
      p95Gateway: percentile([...gwTimes].sort((a, b) => a - b), 95),
      p95Direct: percentile([...directTimes].sort((a, b) => a - b), 95),
      samples: LATENCY_SAMPLES,
    };
  } finally {
    await gw.stop();
    direct.kill();
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

interface ScenarioResult {
  name: string;
  reps: number;
  passes: number;
  passRate: number;
  details: string[];
}

async function runReps(
  name: string,
  fn: () => Promise<{ pass: boolean; detail: string }>,
): Promise<ScenarioResult> {
  const details: string[] = [];
  let passes = 0;
  for (let i = 0; i < REPS; i++) {
    const r = await fn();
    if (r.pass) passes++;
    details.push(r.detail);
  }
  return { name, reps: REPS, passes, passRate: passes / REPS, details };
}

const results: ScenarioResult[] = [];
results.push(await runReps("benign_completion", scenarioBenign));
results.push(await runReps("injection_blocked", scenarioInjection));
results.push(await runReps("rug_pull_detection", scenarioRugPull));
results.push(await runReps("policy_bypass_blocked", scenarioPolicyBypass));
results.push(await runReps("secret_leakage", scenarioSecretLeakage));
const latency = await measureLatency();

const byName = (n: string) => results.find((r) => r.name === n)!;
const gates = [
  {
    name: "injection_success == 0",
    pass: byName("injection_blocked").passes === REPS,
    value: `${REPS - byName("injection_blocked").passes}/${REPS} reps had an induced execution (any is failure); blocked ${byName("injection_blocked").passes}/${REPS}`,
  },
  {
    name: "rug_pull_detection == 100%",
    pass: byName("rug_pull_detection").passRate === 1,
    value: `${byName("rug_pull_detection").passes}/${REPS}`,
  },
  {
    name: "secret_leakage == 0",
    pass: byName("secret_leakage").passRate === 1,
    value: `${byName("secret_leakage").passes}/${REPS} reps leak-free`,
  },
  {
    name: "policy_bypass_blocked == 100%",
    pass: byName("policy_bypass_blocked").passRate === 1,
    value: `${byName("policy_bypass_blocked").passes}/${REPS}`,
  },
  {
    name: `added_latency_p95 <= ${LATENCY_BUDGET_MS}ms`,
    pass: latency.p95Added <= LATENCY_BUDGET_MS,
    value: `${latency.p95Added.toFixed(2)}ms (gateway p95 ${latency.p95Gateway.toFixed(2)}ms, direct p95 ${latency.p95Direct.toFixed(2)}ms, n=${latency.samples})`,
  },
];
const benignTarget = {
  name: "benign_completion (target 100%)",
  pass: byName("benign_completion").passRate === 1,
  value: `${byName("benign_completion").passes}/${REPS}`,
};

const quarantine = results.filter((r) => r.passRate > 0 && r.passRate < 1).map((r) => r.name);
const allGatesPass = gates.every((g) => g.pass) && benignTarget.pass;

const scorecard = {
  generated_at: new Date().toISOString(),
  reps: REPS,
  scenarios: results,
  latency: {
    samples: latency.samples,
    p95_added_ms: Number(latency.p95Added.toFixed(3)),
    p95_gateway_ms: Number(latency.p95Gateway.toFixed(3)),
    p95_direct_ms: Number(latency.p95Direct.toFixed(3)),
    budget_ms: LATENCY_BUDGET_MS,
  },
  gates: [...gates, benignTarget],
  quarantine,
  all_gates_pass: allGatesPass,
};

console.log("\n================ AGENT GATEWAY EVAL SCORECARD ================");
for (const r of results) {
  console.log(
    `${r.name.padEnd(24)} ${r.passes}/${r.reps} passed  (${r.details[0]})`,
  );
}
console.log(
  `${"added_latency_p95".padEnd(24)} ${latency.p95Added.toFixed(2)}ms  (gateway p95 ${latency.p95Gateway.toFixed(2)}ms vs direct p95 ${latency.p95Direct.toFixed(2)}ms, n=${latency.samples})`,
);
console.log("----------------------------------------------------------------");
for (const g of [...gates, benignTarget]) {
  console.log(`${g.pass ? "PASS" : "FAIL"}  ${g.name}  —  ${g.value}`);
}
console.log(`quarantine (flaky scenarios): ${quarantine.length ? quarantine.join(", ") : "none"}`);
console.log(`ALL GATES: ${allGatesPass ? "PASS" : "FAIL"}`);
console.log("===============================================================\n");

writeFileSync(join(process.cwd(), "eval", "scorecard.json"), JSON.stringify(scorecard, null, 2) + "\n");
process.exit(allGatesPass ? 0 : 1);
