/**
 * Structured clearance audit events.
 * Fields are an allow-list. Names, dates of birth, raw proofs, and
 * secondFactorHash are not accepted.
 * AUDIT_LOG_PATH appends JSON lines to a local file. Otherwise each event
 * is one JSON line on stdout. /api/metrics reads the in-process summary.
 */

import fs from 'fs';
import path from 'path';

export const CLEARANCE_AUDIT_EVENTS = [
  'challenge_issued',
  'replay_rejected',
  'clone_detected',
  'attestation_failure',
  'proof_failure',
  'clearance_success',
  'clearance_failure',
] as const;

export type ClearanceAuditEventName = (typeof CLEARANCE_AUDIT_EVENTS)[number];

export interface ClearanceAuditRecord {
  event: ClearanceAuditEventName;
  jurisdiction?: 'CH' | 'IT';
  prove_ms?: number;
  verify_ms?: number;
  total_ms?: number;
  reason?: string;
  keyId?: string;
}

interface LatencySummary {
  count: number;
  sum: number;
  min: number;
  max: number;
}

function emptySummary(): LatencySummary {
  return { count: 0, sum: 0, min: 0, max: 0 };
}

const counts: Record<ClearanceAuditEventName, number> = {
  challenge_issued: 0,
  replay_rejected: 0,
  clone_detected: 0,
  attestation_failure: 0,
  proof_failure: 0,
  clearance_success: 0,
  clearance_failure: 0,
};

const latency: Record<'prove_ms' | 'verify_ms' | 'total_ms', LatencySummary> = {
  prove_ms: emptySummary(),
  verify_ms: emptySummary(),
  total_ms: emptySummary(),
};

const REASON_PATTERN = /^[a-z0-9_]+$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function boundedMs(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 600_000) return undefined;
  return value;
}

function observe(summary: LatencySummary, value: number | undefined): void {
  if (value === undefined) return;
  if (summary.count === 0) {
    summary.min = value;
    summary.max = value;
  } else {
    summary.min = Math.min(summary.min, value);
    summary.max = Math.max(summary.max, value);
  }
  summary.count += 1;
  summary.sum += value;
}

function sanitize(record: ClearanceAuditRecord): ClearanceAuditRecord {
  const line: ClearanceAuditRecord = { event: record.event };
  if (record.jurisdiction === 'CH' || record.jurisdiction === 'IT') line.jurisdiction = record.jurisdiction;
  const prove_ms = boundedMs(record.prove_ms);
  const verify_ms = boundedMs(record.verify_ms);
  const total_ms = boundedMs(record.total_ms);
  if (prove_ms !== undefined) line.prove_ms = prove_ms;
  if (verify_ms !== undefined) line.verify_ms = verify_ms;
  if (total_ms !== undefined) line.total_ms = total_ms;
  if (typeof record.reason === 'string' && REASON_PATTERN.test(record.reason)) line.reason = record.reason;
  if (typeof record.keyId === 'string' && KEY_ID_PATTERN.test(record.keyId)) line.keyId = record.keyId;
  return line;
}

export function recordClearanceAudit(record: ClearanceAuditRecord): void {
  const line = sanitize(record);
  counts[line.event] += 1;
  observe(latency.prove_ms, line.prove_ms);
  observe(latency.verify_ms, line.verify_ms);
  observe(latency.total_ms, line.total_ms);

  const encoded = JSON.stringify(line);
  const file = process.env.AUDIT_LOG_PATH;
  if (file && file.trim()) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.appendFileSync(file, `${encoded}\n`, { mode: 0o600 });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[ClearanceAudit] Failed to append ${file}: ${message}`);
    }
    return;
  }
  console.log(encoded);
}

export function clearanceMetricsSnapshot(): {
  events: Record<ClearanceAuditEventName, number>;
  latency: Record<'prove_ms' | 'verify_ms' | 'total_ms', LatencySummary>;
} {
  return {
    events: { ...counts },
    latency: {
      prove_ms: { ...latency.prove_ms },
      verify_ms: { ...latency.verify_ms },
      total_ms: { ...latency.total_ms },
    },
  };
}
