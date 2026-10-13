/**
 * Approvals CLI: inspect and decide the gateway's pending-approvals queue.
 *
 *   node dist/src/approvals-cli.js --state <dir> list
 *   node dist/src/approvals-cli.js --state <dir> approve <id>
 *   node dist/src/approvals-cli.js --state <dir> deny <id>
 *   node dist/src/approvals-cli.js --state <dir> alerts
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ApprovalsStore } from "./policy.js";

function parseArgs(): { state: string | undefined; positional: string[] } {
  const argv = process.argv.slice(2);
  let state: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--state") state = argv[++i];
    else positional.push(argv[i]);
  }
  return { state, positional };
}

const { state: stateArg, positional } = parseArgs();
const stateDir = resolve(stateArg ?? process.env.AGENT_GATEWAY_STATE ?? "./gateway-state");
const [cmd, id] = positional;

const store = new ApprovalsStore(join(stateDir, "approvals.json"));

switch (cmd) {
  case "list": {
    const records = store.list();
    if (records.length === 0) {
      console.log("(no approval records)");
      break;
    }
    for (const r of records) {
      console.log(
        `${r.id}  ${r.status.padEnd(8)}  ${r.tool}  args=${JSON.stringify(r.args_redacted)}  created=${r.created_at}`,
      );
    }
    break;
  }
  case "approve":
  case "deny": {
    if (!id) {
      console.error(`usage: approvals-cli --state <dir> ${cmd} <id>`);
      process.exit(2);
    }
    const ok = store.decide(id, cmd === "approve" ? "approved" : "denied");
    console.log(ok ? `${cmd === "approve" ? "approved" : "denied"}: ${id}` : `no pending record with id ${id}`);
    process.exit(ok ? 0 : 1);
    break;
  }
  case "alerts": {
    const f = join(stateDir, "alerts.jsonl");
    console.log(existsSync(f) ? readFileSync(f, "utf8") : "(no alerts)");
    break;
  }
  default:
    console.error("usage: approvals-cli --state <dir> <list|approve <id>|deny <id>|alerts>");
    process.exit(2);
}
