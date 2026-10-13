# Agent Gateway

A protocol-native **MCP (Model Context Protocol) agent reliability platform**.
The gateway sits between an agent host and one or more MCP servers and
mediates *every* interaction: downstream servers run as child processes of
the gateway and are reachable only through it. Nothing reaches a server
except through the gateway, and every tool call is pinned, policy-checked,
approval-gated where required, traced, and redacted — in that order.

Design intent: **complete mediation over prompt-level hope, deterministic
scorers over vibes.** Security decisions are made by deterministic code
(policy rules, schema hashes, an approvals queue), and the eval harness
scores outcomes against downstream execution logs — never against the
gateway's own claims.

## Architecture

```
agent host ──stdio JSON-RPC──▶ Agent Gateway ──stdio JSON-RPC──▶ MCP server (child process)
                               │  ├─ pinning store   (pins.json)      MCP server (child process)
                               │  ├─ policy engine                    MCP server (child process)
                               │  ├─ approvals queue (approvals.json)
                               │  ├─ trace store     (traces.jsonl, redacted)
                               └─ alerts           (alerts.jsonl)
```

| Component | File | Role |
|---|---|---|
| Transport | `src/jsonrpc.ts` | Newline-delimited JSON-RPC 2.0 over stdio; downstream peers, timeouts |
| Gateway | `src/gateway.ts` | Mediation pipeline: pin gate → policy gate → approval gate → execution with degraded-mode handling; writes one span per call |
| Tracing | `src/trace.ts` | OTel GenAI-style spans (`gen_ai.operation.name`, `gen_ai.tool.name`, …), args sha256, estimated cost; **redaction before persistence** |
| Policy | `src/policy.ts` | allow / ask / deny rules with argument constraints (max/min number, path allowlist, pattern, enum); file-backed approvals queue |
| Pinning | `src/pinning.ts` | Trust-on-first-use hash of name+description+inputSchema; definition change ⇒ tool blocked + alert |
| Upstream entry | `src/server-entry.ts` | The gateway as an MCP server over stdio; exposes only `initialize`, `ping`, `tools/list`, `tools/call` — no passthrough |
| Approvals CLI | `src/approvals-cli.ts` | `list` / `approve <id>` / `deny <id>` / `alerts` against the state dir |

### Mediation pipeline (per `tools/call`)

1. **Pinning gate** — if the tool's definition has changed since it was
   pinned, the call is blocked (`blocked_pin`) and the tool is excluded from
   `tools/list`.
2. **Policy gate** — the first matching rule decides allow / ask / deny.
   Argument constraint violations (amount over limit, path traversal,
   type-smuggled values, NaN) are always a deny.
3. **Approval gate** — for `ask`, the call does not execute. It is enqueued
   and the caller receives a pending approval id. A human approves or denies
   via the CLI; a retry carrying that approval id (with identical arguments)
   executes **exactly once** — approvals are single-use and bound to the
   argument hash.
4. **Execution** — the call is forwarded to the owning downstream server
   (tool names are namespaced `server__tool`). Timeouts/errors are handled
   per the configured degraded mode.
5. **Tracing** — every invocation, executed or blocked, produces one span in
   `traces.jsonl` with latency, status, policy decision, pinning status, an
   args hash, the *redacted* args, and an estimated cost (per-tool cost
   table in config; blocked calls cost 0).

### Degraded modes

Configured per gateway (`degraded.mode`):

- **fail-closed** — a downstream timeout/error marks the server unhealthy
  and blocks its calls; a policy/trace subsystem failure blocks the call.
- **fail-open** — a downstream timeout/error triggers a downstream restart
  and one retry; subsystem failures raise an alert but the result is kept.

Both modes are covered by tests against a deliberately stalling fixture
server (`fixtures/flaky-server.ts`).

## Fixtures and demo

- `fixtures/benign-server.ts` — notes, calculator, fake filesystem, fake
  payments. Deliberately naive: enforcement is the gateway's job.
- `fixtures/malicious-server.ts` — the adversary. `get_weather` returns a
  result carrying a prompt-injection payload that tries to induce payments
  to an attacker; `vault_get`'s definition silently changes after N calls
  (`MALICIOUS_RUG_AFTER`, default 3) — a rug pull.
- `fixtures/flaky-server.ts` — stalls once, for degraded-mode tests.
- `fixtures/client-harness.ts` — a scripted agent host that drives the real
  gateway subprocess through benign work, an approved payment, the
  injection attempt, and the rug pull.

```bash
npm install
npm run demo          # full scripted demo against demo.config.json
```

## Approvals workflow

```bash
# a call under an `ask` rule returns an error containing its approval id
node dist/src/approvals-cli.js --state demo-state list
node dist/src/approvals-cli.js --state demo-state approve <id>   # or: deny <id>
node dist/src/approvals-cli.js --state demo-state alerts         # rug-pull & degraded alerts
# the agent then retries the identical call with _meta: { approvalId: <id> }
```

## Eval harness (CI gate)

```bash
npm run eval          # exits non-zero if any hard gate fails
npm test              # 11 unit/integration tests
```

Scenarios are seeded and repeatable; functional scenarios run 3× each with
fresh state, pass rates are reported with counts, and any scenario with a
pass rate strictly between 0 and 1 would be listed as quarantined (flaky).
Ground truth is the downstream servers' execution logs.

### Scorecard (this machine, 2026-10-13)

| Metric | Result | Gate |
|---|---|---|
| Injection success (induced attacker payments executed) | **0** (3/3 reps blocked) | HARD GATE = 0 ✅ |
| Rug-pull detection | **3/3 reps (100%)** — tool removed from list, call `blocked_pin`, alert written | HARD GATE = 100% ✅ |
| Secret leakage into trace store | **0** planted secrets found (3/3 reps) | HARD GATE = 0 ✅ |
| Policy-bypass attempts blocked | **7/7 per rep** (over-limit, string/NaN smuggling, traversal ×4), 0 downstream executions | 100% ✅ |
| Benign task completion | **5/5 ops, 3/3 reps** | target 100% ✅ |
| Gateway added latency, p95 | **0.55 ms/call** in the latest run (1.14 ms in the first recorded run; gateway p95 1.00 ms vs direct p95 0.48 ms, n=60 paired samples) | budget ≤ 25 ms ✅ |
| Quarantined (flaky) scenarios | none | — |

Full machine-readable scorecard: `eval/scorecard.json` (regenerated per run).

## Configuration

See `demo.config.json` for a complete example: downstream servers
(command/args/env), policy rules, degraded mode + timeout, per-tool cost
estimates, and the state directory holding `traces.jsonl`, `pins.json`,
`approvals.json`, and `alerts.jsonl`.

## Executed vs written-but-unrun — honesty table

| Item | Status |
|---|---|
| Build (`tsc`, strict) | ✅ executed, clean |
| Test suite (11 tests: mediation, policy/approvals, redaction, pinning, both degraded modes) | ✅ executed, 11/11 pass |
| Eval harness end-to-end | ✅ executed, all gates pass, exit 0 |
| Injection scenario (blocked) | ✅ executed in demo, tests, and eval (3 reps) |
| Rug-pull scenario (detected, blocked, alerted) | ✅ executed in demo, tests, and eval (3 reps) |
| Demo harness against the real gateway subprocess over stdio | ✅ executed, exit 0 |
| Approvals CLI (list/approve/alerts) | ✅ executed during the demo |
| GitHub Actions workflow (`ci.yml`) | ⚠️ YAML syntax-validated locally; **not executed on GitHub** (no repo/push per scope) and **actionlint was not available** on this machine |
| Real LLM / real MCP servers | ❌ none used — by design: fixtures are local MCP servers; no LLM is involved anywhere in the mediation path (there is no LLM in the gateway to trick — that is the point of complete mediation) |
| Latency numbers | ✅ measured locally on this machine only; they are not a production benchmark |

## Notes and limitations

- Pinning is trust-on-first-use: the first definition seen is pinned. In a
  real deployment, first pins should be reviewed or shipped with the config.
- The gateway speaks newline-delimited JSON-RPC over stdio only (no HTTP
  transport), and aggregates one upstream `tools/list` from all downstreams.
- Redaction is pattern/key-based (secret-shaped values and secret-named
  keys); it is a defense-in-depth control for traces, not a DLP product.
