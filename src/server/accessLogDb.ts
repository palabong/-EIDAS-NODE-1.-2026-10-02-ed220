import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { GoogleAuth } from 'google-auth-library';

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

async function ensureDbInitialized() {
  if (isInitialized) return;
  const dbFile = accessLogFile();
  try {
    await fs.mkdir(path.dirname(dbFile), { recursive: true });
    try {
      const fileData = await fs.readFile(dbFile, 'utf-8');
      memoryLogs = JSON.parse(fileData);
      if (!Array.isArray(memoryLogs)) {
        memoryLogs = [];
      }
    } catch {
      // File doesn't exist yet, seed initial access record
      memoryLogs = [
        {
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
        }
      ];
      await persistLogs();
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

const GCP_PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT || '';
const FIRESTORE_DATABASE_ID = process.env.FIRESTORE_DATABASE_ID || '(default)';
let gcpAuthClient: GoogleAuth | null = null;

async function persistToFirestore(log: AccessLog): Promise<void> {
  // Only attempt Firestore persistence if in cloud environment or explicitly enabled with a configured project
  if (!GCP_PROJECT_ID || (!process.env.K_SERVICE && !process.env.FIRESTORE_DATABASE_ID && process.env.USE_FIRESTORE !== 'true')) {
    return;
  }

  try {
    if (!gcpAuthClient) {
      gcpAuthClient = new GoogleAuth({
        scopes: ['https://www.googleapis.com/auth/datastore']
      });
    }

    const client = await gcpAuthClient.getClient();
    const tokenResponse = await client.getAccessToken();
    const token = tokenResponse.token;
    if (!token) return;

    // Convert fields to Firestore REST API document format
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

    if (log.metadata) {
      fields.metadata = { stringValue: JSON.stringify(log.metadata) };
    }

    const url = `https://firestore.googleapis.com/v1/projects/${GCP_PROJECT_ID}/databases/${FIRESTORE_DATABASE_ID}/documents/access_logs?documentId=${log.id}`;

    await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ fields })
    });
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
