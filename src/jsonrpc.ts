/**
 * Minimal newline-delimited JSON-RPC 2.0 transport, sufficient for MCP over stdio.
 *
 * - `RpcPeer` wraps a downstream child process: the gateway uses it to talk to
 *   MCP servers it has spawned. Downstream servers are ONLY reachable through
 *   a peer owned by the gateway (complete mediation).
 * - `serveStdio` is the server-side loop used by the fixture servers and by the
 *   gateway's own upstream entry point.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export class DownstreamTimeoutError extends Error {
  constructor(method: string, timeoutMs: number) {
    super(`downstream request '${method}' timed out after ${timeoutMs}ms`);
    this.name = "DownstreamTimeoutError";
  }
}

export class DownstreamExitError extends Error {
  constructor(message = "downstream process exited") {
    super(message);
    this.name = "DownstreamExitError";
  }
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
}

export class RpcPeer {
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private closed = false;

  constructor(public readonly proc: ChildProcess) {
    const rl = createInterface({ input: proc.stdout! });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let msg: JsonRpcResponse;
      try {
        msg = JSON.parse(trimmed) as JsonRpcResponse;
      } catch {
        return; // non-JSON noise on stdout is dropped, never forwarded
      }
      if (typeof msg.id === "number") {
        const p = this.pending.get(msg.id);
        if (!p) return; // late response to a timed-out request: drop
        this.pending.delete(msg.id);
        if (msg.error) {
          p.reject(new Error(`downstream error ${msg.error.code}: ${msg.error.message}`));
        } else {
          p.resolve(msg.result);
        }
      }
      // Notifications from downstream are not forwarded upstream: the gateway
      // exposes a deliberately small, fully mediated surface.
    });
    const onGone = () => {
      if (this.closed) return;
      this.closed = true;
      const err = new DownstreamExitError();
      for (const p of this.pending.values()) p.reject(err);
      this.pending.clear();
    };
    proc.on("exit", onGone);
    proc.on("error", onGone);
  }

  request(method: string, params?: unknown, timeoutMs = 5000): Promise<unknown> {
    if (this.closed) return Promise.reject(new DownstreamExitError());
    const id = this.nextId++;
    const payload: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new DownstreamTimeoutError(method, timeoutMs));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.proc.stdin!.write(JSON.stringify(payload) + "\n", (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(new DownstreamExitError(`stdin write failed: ${err.message}`));
        }
      });
    });
  }

  notify(method: string, params?: unknown): void {
    const payload: JsonRpcRequest = { jsonrpc: "2.0", method, params };
    this.proc.stdin!.write(JSON.stringify(payload) + "\n");
  }

  kill(): void {
    this.closed = true;
    try {
      this.proc.kill("SIGTERM");
    } catch {
      /* already gone */
    }
  }
}

export function spawnPeer(
  command: string,
  args: string[],
  env: Record<string, string> = {},
  cwd?: string,
): RpcPeer {
  const proc = spawn(command, args, {
    stdio: ["pipe", "pipe", "inherit"],
    env: { ...process.env, ...env },
    cwd,
  });
  return new RpcPeer(proc);
}

export type RpcHandler = (method: string, params: any) => Promise<unknown>;

/**
 * Server-side stdio loop. Reads JSON-RPC requests from this process's stdin,
 * dispatches to `handler`, writes responses to stdout. Notifications (no id)
 * are dispatched and their results discarded.
 */
export function serveStdio(handler: RpcHandler): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req: JsonRpcRequest;
    try {
      req = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      return;
    }
    if (req.id === undefined) {
      try {
        await handler(req.method, req.params ?? {});
      } catch {
        /* notifications have no response channel */
      }
      return;
    }
    try {
      const result = await handler(req.method, req.params ?? {});
      const res: JsonRpcResponse = { jsonrpc: "2.0", id: req.id, result };
      process.stdout.write(JSON.stringify(res) + "\n");
    } catch (err) {
      const e = err as Error & { code?: number };
      const res: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: req.id,
        error: { code: typeof e.code === "number" ? e.code : -32000, message: e.message ?? "error" },
      };
      process.stdout.write(JSON.stringify(res) + "\n");
    }
  });
}
