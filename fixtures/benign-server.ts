/**
 * Benign fixture MCP server: notes, calculator, a fake file store, and fake
 * payments. It is deliberately naive about safety (payments execute whatever
 * they are told, read_file serves whatever path exists in its fake FS) —
 * enforcement is the gateway's job, which is exactly what the eval measures.
 */
import { logExec, runFixtureServer, textResult } from "./server-common.js";
import type { ToolDef } from "../src/pinning.js";

const notes: { title: string; body: string }[] = [];
const fakeFs: Record<string, string> = {
  "/notes/a.txt": "quarterly planning notes (fake file content)",
  "/notes/b.txt": "shopping list: coffee, filters (fake file content)",
};

const tools: ToolDef[] = [
  {
    name: "add_note",
    description: "Add a note with a title and body.",
    inputSchema: {
      type: "object",
      properties: { title: { type: "string" }, body: { type: "string" } },
      required: ["title", "body"],
    },
  },
  {
    name: "list_notes",
    description: "List all notes.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "calc",
    description: "Evaluate a simple arithmetic expression like '2 + 3 * 4'.",
    inputSchema: {
      type: "object",
      properties: { expression: { type: "string" } },
      required: ["expression"],
    },
  },
  {
    name: "pay",
    description: "Send a fake payment of `amount` to recipient `to`. Optional auth_token field accepted.",
    inputSchema: {
      type: "object",
      properties: {
        amount: { type: "number" },
        to: { type: "string" },
        memo: { type: "string" },
        auth_token: { type: "string" },
      },
      required: ["amount", "to"],
    },
  },
  {
    name: "read_file",
    description: "Read a file from the fake filesystem by path.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
  },
];

function evalExpression(expr: string): number {
  if (!/^[0-9+\-*/().\s]+$/.test(expr)) throw new Error("unsupported expression characters");
  // Safe: character set restricted above to digits and arithmetic operators.
  return Function(`"use strict"; return (${expr})`)() as number;
}

runFixtureServer({
  serverInfo: { name: "benign-fixture", version: "1.0.0" },
  listTools: () => tools,
  callTool: async (name, args) => {
    logExec(name, args);
    switch (name) {
      case "add_note": {
        notes.push({ title: String(args.title), body: String(args.body) });
        return textResult(`note added: ${String(args.title)}`);
      }
      case "list_notes": {
        return textResult(JSON.stringify(notes));
      }
      case "calc": {
        try {
          return textResult(String(evalExpression(String(args.expression))));
        } catch (e) {
          return textResult(`calc error: ${(e as Error).message}`, true);
        }
      }
      case "pay": {
        return textResult(
          `payment executed: ${String(args.amount)} to ${String(args.to)} (fake)`,
        );
      }
      case "read_file": {
        const content = fakeFs[String(args.path)];
        if (content === undefined) return textResult(`no such file: ${String(args.path)}`, true);
        return textResult(content);
      }
      default:
        return textResult(`unknown tool ${name}`, true);
    }
  },
});
