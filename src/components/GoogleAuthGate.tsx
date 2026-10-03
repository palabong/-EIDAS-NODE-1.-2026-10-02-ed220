import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldCheck, 
  AlertCircle, 
  Database, 
  Fingerprint
} from 'lucide-react';
import { VerifiedGoogleUser } from '../hooks/useGoogleAuth';

interface GoogleAuthGateProps {
  onLoginSuccess: (user: VerifiedGoogleUser) => void;
  isVerifying: boolean;
  authError: string | null;
  onClearError: () => void;
  onInstantVerify: (email?: string, name?: string) => Promise<VerifiedGoogleUser>;
  onOpenAuditLogs: () => void;
}

export function GoogleAuthGate({
  onLoginSuccess,
  isVerifying,
  authError,
  onClearError,
  onOpenAuditLogs
}: GoogleAuthGateProps) {
  const [gsiLoaded, setGsiLoaded] = useState(false);
  const buttonContainerRef = useRef<HTMLDivElement>(null);

  // Initialize official Google Identity Services client
  useEffect(() => {
    const clientId = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID || 'your_client_id.apps.googleusercontent.com';
    
    const initGoogleButton = () => {
      if (typeof window !== 'undefined' && window.google?.accounts?.id && buttonContainerRef.current) {
        try {
          window.google.accounts.id.initialize({
            client_id: clientId,
            callback: async (response: { credential: string }) => {
              try {
                const res = await fetch('/api/auth/verify-google', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                  body: JSON.stringify({ credential: response.credential }),
                });
                const contentType = res.headers.get('content-type') || '';
                if (contentType.includes('application/json')) {
                  const data = await res.json();
                  if (data.success && data.user) {
                    const verifiedUser = {
                      ...data.user,
                      sessionToken: data.sessionToken
                    };
                    localStorage.setItem('bilanx_verified_google_user', JSON.stringify(verifiedUser));
                    onLoginSuccess(verifiedUser);
                  }
                }
              } catch (err) {
                console.error("Google Sign-In callback error:", err);
              }
            },
          });

          buttonContainerRef.current.innerHTML = '';
          window.google.accounts.id.renderButton(
            buttonContainerRef.current,
            {
              type: 'standard',
              theme: 'filled_blue',
              size: 'large',
              text: 'signin_with',
              shape: 'rectangular',
              logo_alignment: 'left',
              width: 320
            }
          );
          setGsiLoaded(true);
          return true;
        } catch (err) {
          console.warn("Could not render official Google button:", err);
        }
      }
      return false;
    };

    if (!initGoogleButton()) {
      const interval = setInterval(() => {
        if (initGoogleButton()) {
          clearInterval(interval);
        }
      }, 300);
      return () => clearInterval(interval);
    }
  }, [onLoginSuccess]);

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 sm:p-6 font-sans relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-10 right-10 w-80 h-80 bg-indigo-600/5 rounded-full blur-2xl pointer-events-none"></div>

      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative z-10">
        
        {/* Header Badge */}
        <div className="p-8 pb-6 text-center">
          <div className="w-16 h-16 bg-blue-500/10 border border-blue-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-blue-400 shadow-inner">
            <ShieldCheck size={32} />
          </div>

          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-950/70 border border-blue-800/60 text-blue-300 text-[11px] font-mono mb-3">
            <Fingerprint size={12} />
            <span>Google OAuth 2.0 Credential Verification</span>
          </div>

          <h1 className="text-2xl font-bold text-white tracking-tight">Credentials Hub</h1>
          <p className="text-slate-400 text-xs mt-1.5 leading-relaxed">
            Sign in with your Google account via official OAuth 2.0 to access the eIDAS 2.0 node & compliance dashboard.
          </p>
        </div>

        {/* Error Notification */}
        {authError && (
          <div className="mx-8 mb-4 p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2.5 text-xs text-red-200">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1 leading-snug">{authError}</div>
            <button onClick={onClearError} className="text-red-400 hover:text-red-100 font-bold px-1">✕</button>
          </div>
        )}

        {/* Auth Body — Solely Official Google OAuth Button */}
        <div className="px-8 pb-8 flex flex-col gap-6 items-center">

          {/* Official Google Identity Button Container */}
          <div className="w-full flex justify-center py-2 min-h-[50px] items-center">
            <div ref={buttonContainerRef} className="flex justify-center"></div>
            {!gsiLoaded && (
              <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin"></div>
                <span>Loading Google OAuth Client...</span>
              </div>
            )}
          </div>

          {/* Audit Trail Transparency Card */}
          <div className="w-full p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-xl text-left">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-mono font-bold text-slate-300 flex items-center gap-1.5">
                <Database size={13} className="text-emerald-400" />
                Local Access Log Database
              </span>
              <button
                onClick={onOpenAuditLogs}
                className="text-[10px] font-mono text-blue-400 hover:text-blue-300 underline cursor-pointer"
              >
                View Audit Records
              </button>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              OAuth 2.0 authentication executes a cryptographic verification sequence and writes an immutable record into the local access log database.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="bg-slate-950 px-6 py-3.5 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>eIDAS 2.0 Node Sandbox</span>
          <button 
            onClick={onOpenAuditLogs}
            className="text-slate-400 hover:text-white transition-colors cursor-pointer flex items-center gap-1"
          >
            <span>Audit Logs</span>
          </button>
        </div>

      </div>
    </div>
  );
}
