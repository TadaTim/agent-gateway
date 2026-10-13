/**
 * The Gateway: complete mediation between an agent host and MCP servers.
 *
 * Downstream MCP servers exist only as child processes of the gateway,
 * reachable only through gateway-owned RpcPeers. Every tools/list and
 * tools/call passes through, in order:
 *   1. tool pinning check (rug-pull defense)
 *   2. policy evaluation (allow / ask / deny + argument constraints)
 *   3. approval verification for `ask` calls
 *   4. downstream execution (with degraded-mode handling)
 * and every invocation — executed or blocked — is traced with redaction.
 */
import { join } from "node:path";
import { spawnPeer, RpcPeer, DownstreamTimeoutError, DownstreamExitError } from "./jsonrpc.js";
import {
  TraceStore,
  hashValue,
  redactValue,
  newSpanId,
  newTraceId,
  type SpanRecord,
} from "./trace.js";
import { PolicyEngine, ApprovalsStore } from "./policy.js";
import { PinStore, AlertStore, type ToolDef } from "./pinning.js";
import { PROTOCOL_VERSION, type DownstreamConfig, type GatewayConfig } from "./config.js";

export type CallStatus =
  | "ok"
  | "error"
  | "blocked_policy"
  | "approval_required"
  | "blocked_pin"
  | "blocked_degraded";

export interface CallOutcome {
  status: CallStatus;
  /** Raw MCP tools/call result from downstream (only when status === "ok"). */
  result?: unknown;
  error?: string;
  pendingId?: string;
  latencyMs: number;
}

interface ServerState {
  cfg: DownstreamConfig;
  peer: RpcPeer | null;
  healthy: boolean;
  defs: Map<string, ToolDef>; // local tool name -> def
}

const SEP = "__";

export function fullName(server: string, local: string): string {
  return `${server}${SEP}${local}`;
}

export class Gateway {
  private servers = new Map<string, ServerState>();
  private readonly trace: TraceStore;
  private readonly policy: PolicyEngine;
  private readonly approvals: ApprovalsStore;
  private readonly pins: PinStore;
  private readonly alerts: AlertStore;
  private degradedEvents = 0;

  constructor(private readonly cfg: GatewayConfig) {
    this.trace = new TraceStore(join(cfg.stateDir, "traces.jsonl"));
    this.alerts = new AlertStore(join(cfg.stateDir, "alerts.jsonl"));
    this.pins = new PinStore(join(cfg.stateDir, "pins.json"), this.alerts);
    this.approvals = new ApprovalsStore(join(cfg.stateDir, "approvals.json"));
    this.policy = new PolicyEngine(cfg.policy);
  }

  get approvalsStore(): ApprovalsStore {
    return this.approvals;
  }

  get pinStore(): PinStore {
    return this.pins;
  }

  get degradedEventCount(): number {
    return this.degradedEvents;
  }

  async start(): Promise<void> {
    for (const scfg of this.cfg.servers) {
      const st: ServerState = { cfg: scfg, peer: null, healthy: false, defs: new Map() };
      this.servers.set(scfg.name, st);
      await this.connectServer(st);
    }
    await this.refreshTools();
  }

  async stop(): Promise<void> {
    for (const st of this.servers.values()) {
      st.peer?.kill();
      st.peer = null;
      st.healthy = false;
    }
  }

  private async connectServer(st: ServerState): Promise<void> {
    st.peer?.kill();
    st.peer = spawnPeer(st.cfg.command, st.cfg.args, st.cfg.env ?? {}, st.cfg.cwd);
    await st.peer.request(
      "initialize",
      {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "agent-gateway", version: "0.1.0" },
      },
      this.cfg.degraded.downstreamTimeoutMs,
    );
    st.peer.notify("notifications/initialized", {});
    st.healthy = true;
  }

  /** Fetch fresh tool definitions from every healthy server and re-run pinning. */
  async refreshTools(): Promise<void> {
    for (const st of this.servers.values()) {
      if (!st.peer || !st.healthy) continue;
      try {
        const res = (await st.peer.request(
          "tools/list",
          {},
          this.cfg.degraded.downstreamTimeoutMs,
        )) as { tools: ToolDef[] };
        st.defs.clear();
        for (const tool of res.tools ?? []) {
          st.defs.set(tool.name, tool);
          this.pins.check(fullName(st.cfg.name, tool.name), st.cfg.name, tool);
        }
      } catch {
        // Listing failure marks the server unhealthy; calls to it are then
        // governed by degraded-mode handling.
        st.healthy = false;
      }
    }
  }

  /** Aggregated, namespaced tool list with pin-blocked tools excluded. */
  async listTools(): Promise<ToolDef[]> {
    await this.refreshTools();
    const out: ToolDef[] = [];
    for (const st of this.servers.values()) {
      for (const tool of st.defs.values()) {
        const name = fullName(st.cfg.name, tool.name);
        if (this.pins.isBlocked(name)) continue;
        out.push({ ...tool, name });
      }
    }
    return out;
  }

  async callTool(
    fullToolName: string,
    args: Record<string, unknown> = {},
    meta: { approvalId?: string } = {},
  ): Promise<CallOutcome> {
    const started = Date.now();
    const startIso = new Date(started).toISOString();
    let status: CallStatus = "error";
    let error: string | undefined;
    let pendingId: string | undefined;
    let executed = false;
    let result: unknown;
    let policyAction = "n/a";
    let pinStatus = "n/a";
    let serverName = "";
    const argsHash = hashValue(args);
    const argsRedacted = redactValue(args);

    try {
      const sepIdx = fullToolName.indexOf(SEP);
      serverName = sepIdx >= 0 ? fullToolName.slice(0, sepIdx) : "";
      const localName = sepIdx >= 0 ? fullToolName.slice(sepIdx + SEP.length) : fullToolName;
      const st = this.servers.get(serverName);
      if (!st) {
        status = "error";
        error = `unknown server for tool '${fullToolName}'`;
        return this.finish(started, startIso, fullToolName, serverName, status, {
          error,
          policyAction,
          pinStatus,
          argsHash,
          argsRedacted,
          executed,
        });
      }

      // Ensure we have a current definition (and therefore a pin) for the tool.
      if (!st.defs.has(localName)) await this.refreshTools();
      const def = st.defs.get(localName);
      if (!def) {
        status = "error";
        error = `unknown tool '${fullToolName}'`;
        return this.finish(started, startIso, fullToolName, serverName, status, {
          error,
          policyAction,
          pinStatus,
          argsHash,
          argsRedacted,
          executed,
        });
      }

      // 1. Pinning gate.
      pinStatus = this.pins.isBlocked(fullToolName) ? "changed-blocked" : "ok";
      if (this.pins.isBlocked(fullToolName)) {
        status = "blocked_pin";
        error = `tool '${fullToolName}' is blocked: its definition changed after pinning (possible rug pull)`;
        return this.finish(started, startIso, fullToolName, serverName, status, {
          error,
          policyAction,
          pinStatus,
          argsHash,
          argsRedacted,
          executed,
        });
      }

      // 2. Policy gate (with degraded handling for policy-subsystem errors).
      let decision;
      try {
        decision = this.policy.evaluate(fullToolName, args);
      } catch (err) {
        this.degradedEvents++;
        this.alerts.append({
          type: "policy_subsystem_error",
          tool: fullToolName,
          server: serverName,
          detail: `policy evaluation failed: ${(err as Error).message}`,
          at: new Date().toISOString(),
        });
        if (this.cfg.degraded.mode === "fail-closed") {
          status = "blocked_degraded";
          error = "policy subsystem failed; fail-closed mode blocks the call";
          return this.finish(started, startIso, fullToolName, serverName, status, {
            error,
            policyAction,
            pinStatus,
            argsHash,
            argsRedacted,
            executed,
          });
        }
        decision = { action: "allow" as const, ruleTool: null, violations: [] as string[] };
      }
      policyAction = decision.action;

      if (decision.action === "deny") {
        status = "blocked_policy";
        error =
          decision.violations.length > 0
            ? `policy denied: ${decision.violations.join("; ")}`
            : `policy denied tool '${fullToolName}'`;
        return this.finish(started, startIso, fullToolName, serverName, status, {
          error,
          policyAction,
          pinStatus,
          argsHash,
          argsRedacted,
          executed,
        });
      }

      if (decision.action === "ask") {
        const ok = this.verifyApproval(meta.approvalId, fullToolName, argsHash);
        if (!ok) {
          const rec = this.approvals.enqueue(fullToolName, argsHash, argsRedacted);
          status = "approval_required";
          pendingId = rec.id;
          error = `approval required for '${fullToolName}'; pending approval id ${rec.id}`;
          return this.finish(started, startIso, fullToolName, serverName, status, {
            error,
            pendingId,
            policyAction,
            pinStatus,
            argsHash,
            argsRedacted,
            executed,
          });
        }
      }

      // 3. Downstream availability gate.
      if (!st.healthy || !st.peer) {
        const handled = await this.handleDownstreamFailure(
          st,
          new DownstreamExitError(`server '${serverName}' is unhealthy`),
        );
        if (!handled) {
          status = "blocked_degraded";
          error = `server '${serverName}' unavailable (fail-closed)`;
          return this.finish(started, startIso, fullToolName, serverName, status, {
            error,
            policyAction,
            pinStatus,
            argsHash,
            argsRedacted,
            executed,
          });
        }
      }

      // 4. Execute downstream, with one degraded-mode retry where configured.
      try {
        result = await st.peer!.request(
          "tools/call",
          { name: localName, arguments: args },
          this.cfg.degraded.downstreamTimeoutMs,
        );
        executed = true;
        status = "ok";
      } catch (err) {
        const handled = await this.handleDownstreamFailure(st, err as Error);
        if (handled) {
          try {
            result = await st.peer!.request(
              "tools/call",
              { name: localName, arguments: args },
              this.cfg.degraded.downstreamTimeoutMs,
            );
            executed = true;
            status = "ok";
          } catch (err2) {
            status = "error";
            error = `downstream call failed after retry: ${(err2 as Error).message}`;
          }
        } else {
          status =
            err instanceof DownstreamTimeoutError || err instanceof DownstreamExitError
              ? "blocked_degraded"
              : "error";
          error = `downstream call failed: ${(err as Error).message}`;
        }
      }
      return this.finish(started, startIso, fullToolName, serverName, status, {
        error,
        result,
        pendingId,
        policyAction,
        pinStatus,
        argsHash,
        argsRedacted,
        executed,
      });
    } catch (err) {
      status = "error";
      error = `gateway internal error: ${(err as Error).message}`;
      return this.finish(started, startIso, fullToolName, serverName, status, {
        error,
        policyAction,
        pinStatus,
        argsHash,
        argsRedacted,
        executed,
      });
    }
  }

  /** Returns true when an approved, unconsumed, args-matching approval exists (and consumes it). */
  private verifyApproval(
    approvalId: string | undefined,
    tool: string,
    argsHash: string,
  ): boolean {
    if (!approvalId) return false;
    const rec = this.approvals.get(approvalId);
    if (!rec) return false;
    if (rec.tool !== tool || rec.args_hash !== argsHash) return false;
    if (rec.status !== "approved") return false;
    return this.approvals.consume(approvalId);
  }

  /**
   * Degraded-mode handling for a downstream failure.
   * - fail-closed: mark the server unhealthy, alert, refuse (returns false).
   * - fail-open: alert, restart the downstream process, refresh its tools,
   *   and report recoverable (returns true) so the caller may retry once.
   */
  private async handleDownstreamFailure(st: ServerState, err: Error): Promise<boolean> {
    this.degradedEvents++;
    if (this.cfg.degraded.mode === "fail-closed") {
      st.healthy = false;
      this.alerts.append({
        type: "degraded_mode",
        server: st.cfg.name,
        detail: `fail-closed: downstream failure (${err.message}); server marked unhealthy, calls blocked`,
        at: new Date().toISOString(),
      });
      return false;
    }
    this.alerts.append({
      type: "degraded_mode",
      server: st.cfg.name,
      detail: `fail-open: downstream failure (${err.message}); restarting downstream and retrying once`,
      at: new Date().toISOString(),
    });
    try {
      await this.connectServer(st);
      await this.refreshToolsFor(st);
      return st.healthy;
    } catch {
      st.healthy = false;
      return false;
    }
  }

  private async refreshToolsFor(st: ServerState): Promise<void> {
    if (!st.peer) return;
    const res = (await st.peer.request(
      "tools/list",
      {},
      this.cfg.degraded.downstreamTimeoutMs,
    )) as { tools: ToolDef[] };
    st.defs.clear();
    for (const tool of res.tools ?? []) {
      st.defs.set(tool.name, tool);
      this.pins.check(fullName(st.cfg.name, tool.name), st.cfg.name, tool);
    }
  }

  private finish(
    started: number,
    startIso: string,
    fullToolName: string,
    serverName: string,
    status: CallStatus,
    extra: {
      error?: string;
      result?: unknown;
      pendingId?: string;
      policyAction: string;
      pinStatus: string;
      argsHash: string;
      argsRedacted: unknown;
      executed: boolean;
    },
  ): CallOutcome {
    const ended = Date.now();
    const latencyMs = ended - started;
    const cost = extra.executed
      ? (this.cfg.toolCosts?.[fullToolName] ?? this.cfg.defaultCostUsd ?? 0)
      : 0;
    const span: SpanRecord = {
      trace_id: newTraceId(),
      span_id: newSpanId(),
      parent_span_id: null,
      name: "tools/call",
      start_time: startIso,
      end_time: new Date(ended).toISOString(),
      duration_ms: latencyMs,
      status: status === "ok" ? "ok" : status === "error" ? "error" : "blocked",
      attributes: {
        "gen_ai.system": "mcp",
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": fullToolName,
        "mcp.server": serverName,
        "tool.args_hash": extra.argsHash,
        "tool.args_redacted": extra.argsRedacted,
        "policy.decision": extra.policyAction,
        "pinning.status": extra.pinStatus,
        "gateway.outcome": status,
        "gateway.executed_downstream": extra.executed,
        "cost.usd_estimate": cost,
        ...(extra.error ? { "error.message": extra.error } : {}),
      },
    };
    // Tracing must never leak and should not silently fail: if persistence
    // throws, behavior follows the configured degraded mode.
    try {
      this.trace.append(span);
    } catch (err) {
      this.degradedEvents++;
      if (this.cfg.degraded.mode === "fail-closed" && status === "ok") {
        return {
          status: "blocked_degraded",
          error: `trace persistence failed; fail-closed: ${(err as Error).message}`,
          latencyMs,
        };
      }
      this.alerts.append({
        type: "degraded_mode",
        server: serverName,
        tool: fullToolName,
        detail: `trace persistence failed (fail-open, call result kept): ${(err as Error).message}`,
        at: new Date().toISOString(),
      });
    }
    return {
      status,
      result: extra.result,
      error: extra.error,
      pendingId: extra.pendingId,
      latencyMs,
    };
  }
}
