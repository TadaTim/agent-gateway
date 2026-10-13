/**
 * Tracing: OpenTelemetry GenAI-style span records persisted as JSONL.
 *
 * Redaction happens BEFORE persistence and before a span is ever written:
 * argument values are passed through `redactValue`, which scrubs anything
 * whose key looks secret-bearing or whose string value matches a known
 * secret shape. A sha256 hash of the canonical (unredacted) arguments is
 * kept for correlation; the raw arguments are never written to disk.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, randomUUID } from "node:crypto";

export const REDACTED = "[REDACTED]";

const SECRET_KEY_RE =
  /(secret|token|password|passwd|pwd|api[-_]?key|apikey|authorization|auth[-_]?token|private[-_]?key|credential|session[-_]?id|cookie)/i;

const SECRET_VALUE_RES: RegExp[] = [
  /sk-[A-Za-z0-9_-]{8,}/, // OpenAI-style keys
  /sk-live-[A-Za-z0-9_-]+/, // Stripe-style live keys
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /ghp_[A-Za-z0-9]{20,}/, // GitHub personal access token
  /github_pat_[A-Za-z0-9_]{20,}/,
  /xox[baprs]-[A-Za-z0-9-]+/, // Slack tokens
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/, // JWT
  /Bearer\s+[A-Za-z0-9._~+/=-]+/i,
];

export function looksSecretValue(s: string): boolean {
  return SECRET_VALUE_RES.some((re) => re.test(s));
}

/** Recursively redact a value. `key` is the object key the value sits under. */
export function redactValue(value: unknown, key = ""): unknown {
  if (typeof value === "string") {
    if (SECRET_KEY_RE.test(key) || looksSecretValue(value)) return REDACTED;
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => redactValue(v, key));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY_RE.test(k)) {
        out[k] = REDACTED;
      } else {
        out[k] = redactValue(v, k);
      }
    }
    return out;
  }
  // numbers / booleans / null: redact if the key itself is secret-bearing
  if (SECRET_KEY_RE.test(key)) return REDACTED;
  return value;
}

/** Canonical JSON: recursively sorted object keys, stable across runs. */
export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringify(v)}`).join(",")}}`;
}

export function hashValue(value: unknown): string {
  return "sha256:" + createHash("sha256").update(canonicalStringify(value)).digest("hex");
}

export interface SpanRecord {
  trace_id: string;
  span_id: string;
  parent_span_id: string | null;
  name: string;
  start_time: string;
  end_time: string;
  duration_ms: number;
  status: "ok" | "error" | "blocked";
  attributes: Record<string, unknown>;
}

export class TraceStore {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
  }

  append(span: SpanRecord): void {
    appendFileSync(this.file, JSON.stringify(span) + "\n", "utf8");
  }
}

export function newTraceId(): string {
  return randomUUID();
}

export function newSpanId(): string {
  return randomUUID();
}
