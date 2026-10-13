/**
 * Gateway upstream entry point: `node dist/src/server-entry.js --config <file>`.
 *
 * Speaks MCP over stdio to the agent host. The exposed surface is deliberately
 * minimal and fully mediated: initialize, ping, tools/list, tools/call.
 * Anything else is rejected — there is no passthrough.
 */
import { resolve } from "node:path";
import { serveStdio } from "./jsonrpc.js";
import { Gateway } from "./gateway.js";
import { loadConfig, PROTOCOL_VERSION } from "./config.js";

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const configPath = argValue("--config") ?? process.env.AGENT_GATEWAY_CONFIG;
if (!configPath) {
  process.stderr.write("usage: server-entry --config <config.json>\n");
  process.exit(2);
}

const cfg = loadConfig(resolve(configPath));
const gateway = new Gateway(cfg);
await gateway.start();

const shutdown = async (): Promise<void> => {
  await gateway.stop();
  process.exit(0);
};
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

serveStdio(async (method, params) => {
  switch (method) {
    case "initialize":
      return {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "agent-gateway", version: "0.1.0" },
      };
    case "ping":
      return {};
    case "tools/list": {
      const tools = await gateway.listTools();
      return { tools };
    }
    case "tools/call": {
      const name = params?.name as string;
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      const meta = (params?._meta ?? {}) as { approvalId?: string };
      const outcome = await gateway.callTool(name, args, meta);
      if (outcome.status === "ok") return outcome.result;
      const err = new Error(
        `[${outcome.status}] ${outcome.error ?? "call did not execute"}${
          outcome.pendingId ? ` (approvalId: ${outcome.pendingId})` : ""
        }`,
      ) as Error & { code?: number };
      err.code = -32001;
      throw err;
    }
    default: {
      const err = new Error(
        `method '${method}' is not exposed by the gateway (complete mediation: no passthrough)`,
      ) as Error & { code?: number };
      err.code = -32601;
      throw err;
    }
  }
});
