import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldCheck, 
  Database, 
  Download, 
  RefreshCw, 
  Search, 
  Filter, 
  Trash2, 
  X, 
  CheckCircle2, 
  AlertTriangle,
  AlertCircle,
  User, 
  Globe, 
  Clock, 
  ExternalLink,
  Activity,
  Users,
  KeyRound
} from 'lucide-react';

interface AccessLog {
  id: string;
  timestamp: string;
  userId: string;
  email: string;
  name: string;
  picture?: string;
  authMethod: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  status: 'SUCCESS' | 'DENIED' | 'FLAGGED';
  metadata?: Record<string, any>;
}

interface AccessStats {
  totalAccesses: number;
  uniqueUsers: number;
  totalLogins: number;
  lastAccessTime: string | null;
  recentLogins: AccessLog[];
  dailyActivity: { date: string; count: number }[];
}

interface AccessLogAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AccessLogAuditModal({ isOpen, onClose }: AccessLogAuditModalProps) {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [stats, setStats] = useState<AccessStats | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [isClearing, setIsClearing] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (actionFilter !== 'ALL') params.set('action', actionFilter);
      params.set('limit', '100');

      // Helper function with automatic retry and strict Content-Type validation
      // Prevents HTML warmup/proxy fallback payloads from throwing syntax errors on JSON parsing
      const fetchJsonSafely = async (url: string, retries = 2, delayMs = 600): Promise<any> => {
        for (let attempt = 0; attempt <= retries; attempt++) {
          try {
            const userSession = localStorage.getItem('bilanx_verified_google_user');
            const token = userSession ? JSON.parse(userSession).sessionToken : null;
            
            const res = await fetch(url, {
              headers: { 
                Accept: 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {})
              }
            });
            const contentType = res.headers.get('content-type') || '';
            if (!contentType.includes('application/json')) {
              // Might be transient proxy warmup page
              if (attempt < retries) {
                await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
                continue;
              }
              throw new Error(`Expected JSON but server returned ${contentType || 'non-JSON response'}`);
            }
            if (!res.ok) {
              const errBody = await res.json().catch(() => null);
              throw new Error(errBody?.error || `Request failed (HTTP ${res.status})`);
            }
            return await res.json();
          } catch (err: any) {
            if (attempt < retries) {
              await new Promise(r => setTimeout(r, delayMs * (attempt + 1)));
              continue;
            }
            throw err;
          }
        }
      };

      const [logsData, statsData] = await Promise.all([
        fetchJsonSafely(`/api/access-logs?${params.toString()}`),
        fetchJsonSafely('/api/access-logs/stats')
      ]);

      if (logsData && Array.isArray(logsData.logs)) {
        setLogs(logsData.logs);
        setTotalCount(logsData.total || 0);
      }

      if (statsData) {
        setStats(statsData);
      }
    } catch (err: any) {
      console.warn("[AccessLogAuditModal] Notice loading access logs:", err?.message || err);
      setErrorMsg("Unable to synchronize access logs right now. The server may be warming up.");
    } finally {
      setLoading(false);
    }
  }, [search, actionFilter]);

  useEffect(() => {
    if (isOpen) {
      fetchLogs();
    }
  }, [isOpen, fetchLogs]);

  const handleClearLogs = async () => {
    if (!window.confirm("Are you sure you want to clear the local Access Logs database? This cannot be undone.")) {
      return;
    }
    setIsClearing(true);
    try {
      const userSession = localStorage.getItem('bilanx_verified_google_user');
      const token = userSession ? JSON.parse(userSession).sessionToken : null;
      
      const res = await fetch('/api/access-logs/clear', { 
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : undefined
      });
      if (res.ok) {
        setFeedbackMsg("Access log database successfully cleared.");
        setTimeout(() => setFeedbackMsg(null), 3500);
        await fetchLogs();
      }
    } catch (e) {
      console.error("Failed to clear database:", e);
    } finally {
      setIsClearing(false);
    }
  };

  const handleExportCsv = () => {
    const userSession = localStorage.getItem('bilanx_verified_google_user');
    const token = userSession ? JSON.parse(userSession).sessionToken : '';
    window.location.href = `/api/access-logs/export?token=${token}`;
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs font-sans animate-fade-in">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden text-slate-100">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Database size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-tight">Access Audit Database</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded uppercase font-semibold">
                  Live Persistent Log
                </span>
              </div>
              <p className="text-xs text-slate-400">Recording every authenticated Google verification and system access event in real time</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportCsv}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Download CSV database dump"
            >
              <Download size={14} />
              <span>Export CSV</span>
            </button>
            <button
              onClick={fetchLogs}
              disabled={loading}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
              title="Refresh access records"
            >
              <RefreshCw size={16} className={loading ? "animate-spin text-blue-400" : ""} />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer ml-1"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Aggregate Statistics Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 px-6 py-4 border-b border-slate-800/80 bg-slate-950/40 shrink-0">
            <div className="bg-slate-800/50 border border-slate-700/60 p-3 rounded-lg flex items-center gap-3">
              <div className="p-2 rounded bg-blue-500/10 text-blue-400 shrink-0">
                <Activity size={18} />
              </div>
              <div>
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Total Access Events</div>
                <div className="text-xl font-bold text-white font-mono">{stats.totalAccesses}</div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 p-3 rounded-lg flex items-center gap-3">
              <div className="p-2 rounded bg-emerald-500/10 text-emerald-400 shrink-0">
                <Users size={18} />
              </div>
              <div>
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Unique Identities</div>
                <div className="text-xl font-bold text-emerald-400 font-mono">{stats.uniqueUsers}</div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 p-3 rounded-lg flex items-center gap-3">
              <div className="p-2 rounded bg-purple-500/10 text-purple-400 shrink-0">
                <KeyRound size={18} />
              </div>
              <div>
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Verified Logins</div>
                <div className="text-xl font-bold text-purple-300 font-mono">{stats.totalLogins}</div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 p-3 rounded-lg flex items-center gap-3">
              <div className="p-2 rounded bg-amber-500/10 text-amber-400 shrink-0">
                <Clock size={18} />
              </div>
              <div>
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Last Recorded Access</div>
                <div className="text-xs font-semibold text-slate-200 truncate max-w-[140px]">
                  {stats.lastAccessTime ? new Date(stats.lastAccessTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'None'}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Filter Controls & Search */}
        <div className="px-6 py-3 border-b border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 shrink-0">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={14} />
            <input
              type="text"
              placeholder="Search by email, name, Google UID, IP address, action..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg pl-9 pr-3 py-2 focus:outline-hidden focus:border-blue-500 transition-colors"
            />
            {search && (
              <button 
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 text-xs"
              >
                ✕
              </button>
            )}
          </div>

          <div className="flex items-center gap-2 overflow-x-auto pb-1 sm:pb-0">
            <span className="text-[11px] text-slate-400 font-medium flex items-center gap-1 shrink-0">
              <Filter size={12} /> Filter:
            </span>
            {['ALL', 'LOGIN_SUCCESS', 'COMPLIANCE_RUN', 'LOGOUT', 'LOGIN_FAILURE'].map((act) => (
              <button
                key={act}
                onClick={() => setActionFilter(act)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-colors whitespace-nowrap cursor-pointer ${
                  actionFilter === act
                    ? 'bg-blue-600 text-white font-bold'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200 border border-slate-700'
                }`}
              >
                {act === 'ALL' ? 'All Events' : act.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        {/* Error message banner */}
        {errorMsg && (
          <div className="px-6 py-2.5 bg-rose-950/60 border-b border-rose-800/80 text-xs text-rose-300 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <AlertCircle size={15} className="text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => fetchLogs()}
              className="px-2.5 py-1 bg-rose-900/60 hover:bg-rose-800 border border-rose-700/60 rounded text-[11px] font-semibold text-rose-200 transition-colors cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {/* Feedback message banner */}
        {feedbackMsg && (
          <div className="px-6 py-2 bg-emerald-950/60 border-b border-emerald-800 text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 size={14} />
            <span>{feedbackMsg}</span>
          </div>
        )}

        {/* Database Records Table */}
        <div className="flex-1 overflow-y-auto min-h-[300px] divide-y divide-slate-800/60">
          {loading && logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-400">
              <RefreshCw className="animate-spin text-blue-400" size={24} />
              <p className="text-xs font-mono">Querying Access Log Records...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-2 text-slate-400 text-center px-4">
              <Database size={32} className="text-slate-600" />
              <p className="text-sm font-semibold text-slate-300">No access records match your filter</p>
              <p className="text-xs text-slate-500">Sign in with Google or perform compliance checks to generate real-time audit records.</p>
            </div>
          ) : (
            <table className="w-full text-left text-xs text-slate-300 border-collapse">
              <thead className="bg-slate-950/70 text-[10px] font-mono uppercase text-slate-400 sticky top-0 z-10 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4">Verified Identity</th>
                  <th className="py-2.5 px-4">Action / Event</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">IP Address</th>
                  <th className="py-2.5 px-4">Client Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                    
                    {/* Timestamp */}
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString([], { 
                        month: 'short', 
                        day: 'numeric', 
                        hour: '2-digit', 
                        minute: '2-digit', 
                        second: '2-digit' 
                      })}
                    </td>

                    {/* Verified User */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2.5">
                        {log.picture ? (
                          <img 
                            src={log.picture} 
                            alt={log.name} 
                            className="w-7 h-7 rounded-full border border-slate-700 object-cover shrink-0" 
                            referrerPolicy="no-referrer"
                          />
                        ) : (
                          <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 shrink-0">
                            <User size={14} />
                          </div>
                        )}
                        <div className="min-w-0">
                          <div className="font-medium text-white truncate max-w-[180px]">{log.name}</div>
                          <div className="text-[10px] text-slate-400 font-mono truncate max-w-[180px]">{log.email}</div>
                          <div className="text-[9px] text-slate-500 font-mono truncate max-w-[180px]">UID: {log.userId.slice(0, 12)}...</div>
                        </div>
                      </div>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider ${
                        log.action === 'LOGIN_SUCCESS' 
                          ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                          : log.action === 'COMPLIANCE_RUN'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : log.action === 'LOGOUT'
                          ? 'bg-slate-700/60 text-slate-300 border border-slate-600'
                          : 'bg-red-500/20 text-red-300 border border-red-500/30'
                      }`}>
                        {log.action}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      {log.status === 'SUCCESS' ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                          <CheckCircle2 size={12} />
                          <span>Verified</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                          <AlertTriangle size={12} />
                          <span>{log.status}</span>
                        </span>
                      )}
                    </td>

                    {/* IP Address */}
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {log.ipAddress}
                    </td>

                    {/* User Agent */}
                    <td className="py-3 px-4 text-[10px] text-slate-400 max-w-[200px] truncate" title={log.userAgent}>
                      {log.userAgent}
                    </td>

                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between text-xs text-slate-400 shrink-0">
          <div className="font-mono text-[11px]">
            Showing <strong className="text-white">{logs.length}</strong> of <strong className="text-white">{totalCount}</strong> database access records
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleClearLogs}
              disabled={isClearing}
              className="text-red-400 hover:text-red-300 text-[11px] flex items-center gap-1 transition-colors cursor-pointer px-2 py-1 hover:bg-red-950/40 rounded"
            >
              <Trash2 size={12} />
              <span>{isClearing ? 'Clearing...' : 'Clear Log History'}</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
