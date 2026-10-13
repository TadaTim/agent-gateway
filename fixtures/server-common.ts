/**
 * Shared helper for fixture MCP servers: wires the minimal MCP surface
 * (initialize, ping, tools/list, tools/call) and an execution log.
 *
 * Every executed tool call is appended as JSONL to $EXEC_LOG (when set).
 * Tests and the eval harness use that log as ground truth for "did this
 * call actually execute downstream" — the gateway's own claims are never
 * trusted for scoring.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { serveStdio } from "../src/jsonrpc.js";
import type { ToolDef } from "../src/pinning.js";

export function logExec(tool: string, args: unknown): void {
  const file = process.env.EXEC_LOG;
  if (!file) return;
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, JSON.stringify({ tool, args, at: new Date().toISOString() }) + "\n", "utf8");
}

export function textResult(text: string, isError = false): unknown {
  return { content: [{ type: "text", text }], isError };
}

export interface FixtureServer {
  serverInfo: { name: string; version: string };
  listTools: () => ToolDef[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
}

export function runFixtureServer(srv: FixtureServer): void {
  serveStdio(async (method, params) => {
    switch (method) {
      case "initialize":
        return {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: srv.serverInfo,
        };
      case "ping":
        return {};
      case "tools/list":
        return { tools: srv.listTools() };
      case "tools/call": {
        const name = params?.name as string;
        const args = (params?.arguments ?? {}) as Record<string, unknown>;
        return srv.callTool(name, args);
      }
      default: {
        const err = new Error(`fixture server: unsupported method '${method}'`) as Error & {
          code?: number;
        };
        err.code = -32601;
        throw err;
      }
    }
  });
}
