import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import {
  firestoreClearCollection,
  firestoreListDocuments,
  firestoreUpsertDocument,
  isFirestoreEnabled,
} from './firestoreRest.ts';

export interface AccessLog {
  id: string;
  timestamp: string;
  userId: string;
  email: string;
  name: string;
  picture?: string;
  authMethod: 'google_identity_services' | 'google_jwt_verified' | 'credential_verification' | 'guest_audit' | 'eidas_saml';
  action: 'LOGIN_SUCCESS' | 'SESSION_VALIDATE' | 'LOGOUT' | 'APP_ACCESS' | 'COMPLIANCE_RUN' | 'LOGIN_FAILURE';
  ipAddress: string;
  userAgent: string;
  status: 'SUCCESS' | 'DENIED' | 'FLAGGED';
  metadata?: Record<string, any>;
}

export interface AccessStats {
  totalAccesses: number;
  uniqueUsers: number;
  totalLogins: number;
  lastAccessTime: string | null;
  recentLogins: AccessLog[];
  dailyActivity: { date: string; count: number }[];
}

let resolvedAccessLogFile: string | null = null;

/** Default file is data/access_logs.json. ACCESS_LOG_PATH isolates a test process. */
function accessLogFile(): string {
  if (resolvedAccessLogFile) return resolvedAccessLogFile;
  const override = process.env.ACCESS_LOG_PATH?.trim();
  resolvedAccessLogFile = override && override.length > 0
    ? override
    : path.join(process.cwd(), 'data', 'access_logs.json');
  return resolvedAccessLogFile;
}

// In-memory cache for ultra-fast reading with asynchronous atomic persistence
let memoryLogs: AccessLog[] = [];
let isInitialized = false;
let isWriting = false;
let hasPendingWrite = false;

async function loadLogsFromFirestore(): Promise<AccessLog[] | null> {
  if (!isFirestoreEnabled()) return null;
  try {
    const docs = await firestoreListDocuments('access_logs', 1000);
    const parsed: AccessLog[] = [];
    for (const doc of docs) {
      const f = doc.fields;
      if (!f) continue;
      let metadata: Record<string, any> | undefined;
      if (f.metadata?.stringValue) {
        try {
          metadata = JSON.parse(f.metadata.stringValue);
        } catch {}
      }
      parsed.push({
        id: f.id?.stringValue || doc.name.split('/').pop() || crypto.randomUUID(),
        timestamp: f.timestamp?.timestampValue || f.timestamp?.stringValue || new Date().toISOString(),
        userId: f.userId?.stringValue || 'unknown',
        email: f.email?.stringValue || 'unknown',
        name: f.name?.stringValue || 'Unknown',
        picture: f.picture?.stringValue || undefined,
        authMethod: (f.authMethod?.stringValue as AccessLog['authMethod']) || 'google_jwt_verified',
        action: (f.action?.stringValue as AccessLog['action']) || 'APP_ACCESS',
        ipAddress: f.ipAddress?.stringValue || '0.0.0.0',
        userAgent: f.userAgent?.stringValue || '',
        status: (f.status?.stringValue as AccessLog['status']) || 'SUCCESS',
        metadata,
      });
    }
    parsed.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return parsed;
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.warn(`[AccessLogDb] Cloud Firestore read skipped: ${errMsg}`);
    return null;
  }
}

async function ensureDbInitialized() {
  if (isInitialized) return;
  const dbFile = accessLogFile();
  try {
    await fs.mkdir(path.dirname(dbFile), { recursive: true });

    const remoteLogs = await loadLogsFromFirestore();
    if (remoteLogs && remoteLogs.length > 0) {
      memoryLogs = remoteLogs.slice(0, 10000);
      await persistLogs();
      return;
    }

    try {
      const fileData = await fs.readFile(dbFile, 'utf-8');
      memoryLogs = JSON.parse(fileData);
      if (!Array.isArray(memoryLogs)) {
        memoryLogs = [];
      }
    } catch {
      // File doesn't exist yet, seed initial access record
      const seedLog: AccessLog = {
        id: crypto.randomUUID(),
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        userId: "108392183928172648102",
        email: "auditor.compliance@oecd-bilanx.org",
        name: "European Commission Auditor",
        picture: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80",
        authMethod: "google_jwt_verified",
        action: "LOGIN_SUCCESS",
        ipAddress: "192.168.1.104",
        userAgent: "Mozilla/5.0 (European Verification Gateway)",
        status: "SUCCESS",
        metadata: { complianceScope: "eIDAS_Article_24", sessionType: "Verified" }
      };
      memoryLogs = [seedLog];
      await persistLogs();
      persistToFirestore(seedLog).catch(() => {});
    }
  } catch (err) {
    console.error("[AccessLogDb] Initialization error:", err);
    memoryLogs = [];
  } finally {
    isInitialized = true;
  }
}

async function persistLogs(): Promise<void> {
  if (isWriting) {
    hasPendingWrite = true;
    return;
  }

  isWriting = true;
  hasPendingWrite = false;

  try {
    const dbFile = accessLogFile();
    await fs.mkdir(path.dirname(dbFile), { recursive: true });
    const payload = JSON.stringify(memoryLogs, null, 2);
    const tempFile = path.join(path.dirname(dbFile), `.access_logs.${Date.now()}_${crypto.randomBytes(8).toString('hex')}.tmp`);

    try {
      await fs.writeFile(tempFile, payload, 'utf-8');
      await fs.rename(tempFile, dbFile);
    } catch (renameErr) {
      // Clean up temp file if rename failed
      try {
        await fs.unlink(tempFile);
      } catch {
        // Ignore unlink error
      }
      // Fallback to direct write to avoid ENOENT/filesystem locking issues
      await fs.writeFile(dbFile, payload, 'utf-8');
    }
  } catch (err) {
    console.error("[AccessLogDb] Failed to write access log database to disk:", err);
  } finally {
    isWriting = false;
    if (hasPendingWrite) {
      hasPendingWrite = false;
      // Schedule another persist in the next tick to ensure queued state is written
      setImmediate(() => {
        persistLogs().catch(err => console.error("[AccessLogDb] Queue persist error:", err));
      });
    }
  }
}

let writeDebounceTimer: NodeJS.Timeout | null = null;

function schedulePersistLogs() {
  if (writeDebounceTimer) {
    return;
  }
  writeDebounceTimer = setTimeout(() => {
    writeDebounceTimer = null;
    persistLogs().catch(err => console.error("[AccessLogDb] Persist error:", err));
  }, 50);
}

async function persistToFirestore(log: AccessLog): Promise<void> {
  if (!isFirestoreEnabled()) {
    return;
  }

  try {
    const fields: Record<string, any> = {
      id: { stringValue: log.id },
      timestamp: { timestampValue: log.timestamp },
      userId: { stringValue: log.userId },
      email: { stringValue: log.email },
      name: { stringValue: log.name },
      authMethod: { stringValue: log.authMethod },
      action: { stringValue: log.action },
      ipAddress: { stringValue: log.ipAddress },
      userAgent: { stringValue: log.userAgent || '' },
      status: { stringValue: log.status }
    };

    if (log.picture) {
      fields.picture = { stringValue: log.picture };
    }
    if (log.metadata) {
      fields.metadata = { stringValue: JSON.stringify(log.metadata) };
    }

    await firestoreUpsertDocument('access_logs', log.id, fields);
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.warn(`[AccessLogDb] Cloud Firestore async persist skipped: ${errMsg}`);
  }
}

export async function recordAccessLog(
  entry: Omit<AccessLog, 'id' | 'timestamp'>
): Promise<AccessLog> {
  await ensureDbInitialized();

  const newLog: AccessLog = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry
  };

  // Add to front of array for chronological descending order
  memoryLogs.unshift(newLog);

  // Keep a clean cap of 10,000 access events to avoid unbounded file expansion
  if (memoryLogs.length > 10000) {
    memoryLogs = memoryLogs.slice(0, 10000);
  }

  // 1. Asynchronously save to persistent local JSON database (batched via debounce)
  schedulePersistLogs();

  // 2. Asynchronously save to Google Cloud Firestore (in Cloud Run / Production)
  persistToFirestore(newLog).catch(() => {});

  // 3. Emit structured audit log to stdout for Google Cloud Logging ingestion
  if (process.env.NODE_ENV === 'production' || process.env.K_SERVICE) {
    console.log(JSON.stringify({
      severity: newLog.status === 'DENIED' ? 'WARNING' : 'INFO',
      message: `[AccessLog] ${newLog.action} (${newLog.authMethod}) - User: ${newLog.email || newLog.userId} - Status: ${newLog.status}`,
      eidasAudit: {
        id: newLog.id,
        timestamp: newLog.timestamp,
        userId: newLog.userId,
        email: newLog.email,
        authMethod: newLog.authMethod,
        action: newLog.action,
        status: newLog.status,
        ipAddress: newLog.ipAddress,
        metadata: newLog.metadata
      }
    }));
  }

  return newLog;
}

export async function getAccessLogs(params?: {
  limit?: number;
  offset?: number;
  search?: string;
  action?: string;
  userId?: string;
}): Promise<{ logs: AccessLog[]; total: number }> {
  await ensureDbInitialized();

  let filtered = [...memoryLogs];

  if (params?.search) {
    const q = params.search.toLowerCase().trim();
    filtered = filtered.filter(
      log =>
        log.email.toLowerCase().includes(q) ||
        log.name.toLowerCase().includes(q) ||
        log.userId.toLowerCase().includes(q) ||
        log.ipAddress.toLowerCase().includes(q) ||
        log.action.toLowerCase().includes(q)
    );
  }

  if (params?.action && params.action !== 'ALL') {
    filtered = filtered.filter(log => log.action === params.action);
  }

  if (params?.userId) {
    filtered = filtered.filter(log => log.userId === params.userId);
  }

  const total = filtered.length;
  const offset = params?.offset || 0;
  const limit = params?.limit || 50;

  const paginatedLogs = filtered.slice(offset, offset + limit);

  return {
    logs: paginatedLogs,
    total
  };
}

export async function getAccessStats(): Promise<AccessStats> {
  await ensureDbInitialized();

  const totalAccesses = memoryLogs.length;
  const uniqueUsers = new Set(memoryLogs.map(l => l.email || l.userId)).size;
  const totalLogins = memoryLogs.filter(l => l.action === 'LOGIN_SUCCESS').length;
  const lastAccessTime = memoryLogs[0]?.timestamp || null;
  const recentLogins = memoryLogs
    .filter(l => l.action === 'LOGIN_SUCCESS')
    .slice(0, 10);

  // Daily activity bucketed by YYYY-MM-DD
  const dateMap = new Map<string, number>();
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().split('T')[0];
    dateMap.set(key, 0);
  }

  for (const log of memoryLogs) {
    const day = log.timestamp.split('T')[0];
    if (dateMap.has(day)) {
      dateMap.set(day, (dateMap.get(day) || 0) + 1);
    }
  }

  const dailyActivity = Array.from(dateMap.entries()).map(([date, count]) => ({
    date,
    count
  }));

  return {
    totalAccesses,
    uniqueUsers,
    totalLogins,
    lastAccessTime,
    recentLogins,
    dailyActivity
  };
}

export async function clearAccessLogs(): Promise<void> {
  await ensureDbInitialized();
  memoryLogs = [];
  await persistLogs();
  if (isFirestoreEnabled()) {
    await firestoreClearCollection('access_logs').catch((err) => {
      console.warn('[AccessLogDb] Cloud Firestore clear skipped:', err instanceof Error ? err.message : String(err));
    });
  }
}

export async function exportAccessLogsCsv(): Promise<string> {
  await ensureDbInitialized();
  const headers = ['ID', 'Timestamp', 'User ID', 'Email', 'Name', 'Action', 'Status', 'IP Address', 'User Agent', 'Auth Method'];
  const rows = memoryLogs.map(l => [
    `"${l.id}"`,
    `"${l.timestamp}"`,
    `"${l.userId}"`,
    `"${l.email}"`,
    `"${l.name}"`,
    `"${l.action}"`,
    `"${l.status}"`,
    `"${l.ipAddress}"`,
    `"${(l.userAgent || '').replace(/"/g, '""')}"`,
    `"${l.authMethod}"`
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}
