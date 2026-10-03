/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Layers, 
  Terminal, 
  Key, 
  FileText,
  User,
  Sliders,
  Sparkles,
  Search,
  Lock,
  Unlock,
  AlertCircle,
  Zap,
  ArrowLeftRight
} from 'lucide-react';
import { UserProfile, PortfolioItem, ThemeConfig, ScreeningTicket, DKProduct, DKWallet, ZKALogEntry, EidasAssertion, UhdRfidAssertion } from './types';
import { DEFAULT_PROFILE, DEFAULT_THEME, DEFAULT_PORTFOLIO, DEFAULT_SCREENING_TICKETS, DEFAULT_DK_PRODUCTS, DEFAULT_DK_WALLETS, DEFAULT_ZKA_LOGS } from './data';

import DocumentationMode from './components/DocumentationMode';
import UnifiedLabDemo from './sandbox/UnifiedLabDemo';

import { BilanxStressTest } from './sandbox/BilanxStressTest';
import { useGoogleAuth, VerifiedGoogleUser } from './hooks/useGoogleAuth';
import { GoogleAuthGate } from './components/GoogleAuthGate';
import { AccessLogAuditModal } from './components/AccessLogAuditModal';
import EidasNodeLab from './components/EidasNodeLab';

export default function App() {
  const { 
    user,
    setUser, 
    loading, 
    isVerifying, 
    authError, 
    clearAuthError, 
    loginWithGoogleCredential, 
    logout 
  } = useGoogleAuth();

  const [showAuditModal, setShowAuditModal] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center font-sans">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin"></div>
          <div className="font-mono text-xs text-slate-400 uppercase tracking-widest">Verifying Google Identity Credentials...</div>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <>
        <GoogleAuthGate
          onLoginSuccess={(verifiedUser) => setUser(verifiedUser)}
          isVerifying={isVerifying}
          authError={authError}
          onClearError={clearAuthError}
          onInstantVerify={loginWithGoogleCredential}
          onOpenAuditLogs={() => setShowAuditModal(true)}
        />
        <AccessLogAuditModal
          isOpen={showAuditModal}
          onClose={() => setShowAuditModal(false)}
        />
      </>
    );
  }

  return (
    <>
      <BilanxApp 
        user={user} 
        logout={logout} 
        onOpenAuditLogs={() => setShowAuditModal(true)} 
      />
      <AccessLogAuditModal
        isOpen={showAuditModal}
        onClose={() => setShowAuditModal(false)}
      />
    </>
  );
}

function BilanxApp({ 
  user, 
  logout, 
  onOpenAuditLogs 
}: { 
  user: VerifiedGoogleUser; 
  logout: () => void; 
  onOpenAuditLogs: () => void; 
}) {

  // Application Data States (hydrated from localStorage if available)
  const [profile, setProfile] = useState<UserProfile>(() => {
    const saved = localStorage.getItem('credentials_hub_profile');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_PROFILE;
  });

  const [eidasAssertions, setEidasAssertions] = useState<EidasAssertion[]>(() => {
    const saved = localStorage.getItem('credentials_hub_eidas_assertions');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.length > 0) return parsed;
      } catch (_) {}
    }
    return [
      {
        id: "EIDAS-2026-06-23-01",
        timestamp: "2026-06-23T10:15:30.000Z",
        issuer: "http://S-PEPS.gov.xx",
        subjectId: "SUBJ-BEL-BRU-9824A",
        transactionId: "TXN-BRU-1120X",
        loa: "high",
        attributes: {
          ageOver18: true,
          productAuthentic: true
        },
        signature: "SIG-881294-001"
      },
      {
        id: "EIDAS-2026-06-23-02",
        timestamp: "2026-06-23T11:42:15.000Z",
        issuer: "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
        subjectId: "SUBJ-EU-5541B",
        transactionId: "TXN-CEF-9904Y",
        loa: "low",
        attributes: {
          ageOver18: true,
          productAuthentic: true
        },
        signature: "SIG-324095-002"
      },
      {
        id: "EIDAS-2026-06-23-03",
        timestamp: "2026-06-23T13:05:00.000Z",
        issuer: "http://S-PEPS.gov.xx",
        subjectId: "SUBJ-BEL-ANW-4402C",
        transactionId: "TXN-BRU-5512Z",
        loa: "substantial",
        attributes: {
          ageOver18: true,
          productAuthentic: true
        },
        signature: "SIG-740921-003"
      }
    ];
  });

  const [uhdRfidAssertions, setUhdRfidAssertions] = useState<UhdRfidAssertion[]>(() => {
    const saved = localStorage.getItem('credentials_hub_uhd_rfid_assertions');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.length > 0) return parsed;
      } catch (_) {}
    }
    return [
      {
        id: "RFID-SAML-2026-06-23-01",
        timestamp: "2026-06-23T10:15:30.000Z",
        hardwareUid: "UID-9904-AUTH-951",
        productName: "Audentes Mint Tobacco Pods (Pack of 4)",
        category: "Tobacco",
        status: "authentic",
        hmacSha256: "bf89d7fa13cde6a54101bc89a742cd90981b2fcd1054a896d74b96791a82bc1b",
        tagsRead: 12,
        rssi: -32,
        collisions: 1,
        issuer: "http://consortium-rfid-svs.int",
        exciseRecovered: 3.85,
        signature: "SIG-ECDSA-AUDNT-9904A"
      },
      {
        id: "RFID-SAML-2026-06-23-02",
        timestamp: "2026-06-23T11:42:15.000Z",
        hardwareUid: "UID-8812-AUTH-324",
        productName: "Veritas Premium Aged Cognac v2",
        category: "Alcohol",
        status: "authentic",
        hmacSha256: "2d3e5f4c8b9a1e0f6d8c7b9a5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d",
        tagsRead: 8,
        rssi: -28,
        collisions: 0,
        issuer: "http://consortium-rfid-svs.int",
        exciseRecovered: 3.85,
        signature: "SIG-ECDSA-VERT-8812C"
      },
      {
        id: "RFID-SAML-2026-06-23-03",
        timestamp: "2026-06-23T13:05:00.000Z",
        hardwareUid: "UID-1102-FAKE-881",
        productName: "Lumina Grapefruit Ice Disposable (Counterfeit Serial)",
        category: "Vaporizer",
        status: "counterfeit",
        hmacSha256: "8812739fa8e20cf3a209bc923dd8842bc01a9dfca891efcf004297bcda084e12",
        tagsRead: 24,
        rssi: -48,
        collisions: 5,
        issuer: "http://consortium-rfid-svs.int",
        exciseRecovered: 0,
        signature: "SIG-UNKNOWN-OR-REVOKED"
      },
      {
        id: "RFID-SAML-2026-06-23-04",
        timestamp: "2026-06-23T15:20:10.000Z",
        hardwareUid: "UID-3221-RECALLED-60",
        productName: "Chronos CBD Isolate Vaporizer Pen",
        category: "Cannabinoids",
        status: "recalled",
        hmacSha256: "fe382a938c01d9f0a2cf8b92d04a7c8b201a9bfe8902c3d049f7e8a9bc01a2f4",
        tagsRead: 15,
        rssi: -35,
        collisions: 2,
        issuer: "http://consortium-rfid-svs.int",
        exciseRecovered: 0,
        signature: "SIG-ECDSA-CHRONOS-3221A"
      }
    ];
  });

  const [portfolio, setPortfolio] = useState<PortfolioItem[]>(() => {
    const saved = localStorage.getItem('credentials_hub_portfolio');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_PORTFOLIO;
  });

  const [tickets, setTickets] = useState<ScreeningTicket[]>(() => {
    const saved = localStorage.getItem('credentials_hub_tickets');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_SCREENING_TICKETS;
  });

  // Dual-Key Sovereign Validation System (DK-SVS) states
  const [dkProducts, setDkProducts] = useState<DKProduct[]>(() => {
    const saved = localStorage.getItem('credentials_hub_dk_products');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_DK_PRODUCTS;
  });

  const [dkWallets, setDkWallets] = useState<DKWallet[]>(() => {
    const saved = localStorage.getItem('credentials_hub_dk_wallets');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_DK_WALLETS;
  });

  const [zkaLogs, setZkaLogs] = useState<ZKALogEntry[]>(() => {
    const saved = localStorage.getItem('credentials_hub_zka_logs');
    if (saved) {
      try { return JSON.parse(saved); } catch (_) {}
    }
    return DEFAULT_ZKA_LOGS;
  });

  // Real-time Accumulated Compliance Rebate daily ledger carrot
  const [accumulatedRebate, setAccumulatedRebate] = useState<number>(() => {
    const saved = localStorage.getItem('credentials_hub_accumulated_rebate');
    return saved ? parseFloat(saved) : 84.50; // default realistic baseline
  });

  // Current Theme parameters. Defaults to "Vibrant Palette" aesthetic (slate dark base, cyan + indigo highlights)
  const [theme, setTheme] = useState<ThemeConfig>(DEFAULT_THEME);
  
  // Navigation active Mode: 'showcase' | 'documentation' | 'stresstest' | 'eidas_node'
  const [activeMode, setActiveMode] = useState<'showcase' | 'documentation' | 'stresstest' | 'eidas_node'>('eidas_node');

  // Simple Security clearance level bypass (to demonstrate high-tech security credentials)
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(true);
  const [licenseKey, setLicenseKey] = useState<string>(profile.licenseNumber);
  const [showLicensePrompt, setShowLicensePrompt] = useState<boolean>(false);

  // Synchronize localStorage
  useEffect(() => {
    localStorage.setItem('credentials_hub_profile', JSON.stringify(profile));
  }, [profile]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_eidas_assertions', JSON.stringify(eidasAssertions));
  }, [eidasAssertions]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_uhd_rfid_assertions', JSON.stringify(uhdRfidAssertions));
  }, [uhdRfidAssertions]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_portfolio', JSON.stringify(portfolio));
  }, [portfolio]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_tickets', JSON.stringify(tickets));
  }, [tickets]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_dk_products', JSON.stringify(dkProducts));
  }, [dkProducts]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_dk_wallets', JSON.stringify(dkWallets));
  }, [dkWallets]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_zka_logs', JSON.stringify(zkaLogs));
  }, [zkaLogs]);

  useEffect(() => {
    localStorage.setItem('credentials_hub_accumulated_rebate', accumulatedRebate.toString());
  }, [accumulatedRebate]);

  // Profile Save handler
  const handleUpdateProfile = (newProfile: UserProfile) => {
    setProfile(newProfile);
  };

  // Portfolio items update handler
  const handleUpdatePortfolio = (newPortfolio: PortfolioItem[]) => {
    setPortfolio(newPortfolio);
  };

  // Add individual portfolio item
  const handleAddPortfolioItem = (newItem: PortfolioItem) => {
    setPortfolio(prev => [newItem, ...prev]);
  };

  // Updates specific screening ticket evaluations when the manual officer audits them
  const handleUpdateTicketStatus = (id: string, status: 'passed' | 'failed' | 'requires_manual_audit', notes?: string) => {
    setTickets(prev => prev.map(ticket => {
      if (ticket.id === id) {
        return { 
          ...ticket, 
          status, 
          evaluationNotes: notes,
          scannedResultScore: status === 'passed' ? 99.8 : (status === 'failed' ? 15.0 : 61.2) // update compliance rates dynamically
        };
      }
      return ticket;
    }));
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col font-sans overflow-x-hidden selection:bg-[#0B3B60] selection:text-white">
      
      {/* 🏛️ EU STATE CUSTOMS & EXCISE GATEWAY HEADER */}
      <header className="flex flex-col md:flex-row justify-between items-center px-6 md:px-10 py-5 border-b border-slate-200 bg-white gap-4 z-40 sticky top-0 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-[#0B3B60] border border-blue-900 rounded flex items-center justify-center shadow-xs">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <div className="flex flex-col">
            <span className="text-lg md:text-xl font-black tracking-tight text-[#0B3B60] uppercase leading-none">
              BILANX.<span className="text-blue-500">EXPERT</span>
            </span>
            <span className="text-[9px] font-bold tracking-widest text-slate-500 uppercase mt-1">DK-SVS Lab Sandbox</span>
          </div>
        </div>

        {/* Dynamic Mode Navigation Tabs with Institutional Slate Underlines */}
        <nav className="flex items-center gap-3 md:gap-6 text-xs font-bold uppercase tracking-widest text-slate-500 overflow-x-auto py-1">
          <button 
            id="nav-eidas-node"
            onClick={() => setActiveMode('eidas_node')}
            className={`cursor-pointer transition-all pb-1.5 flex items-center gap-1.5 whitespace-nowrap ${
              activeMode === 'eidas_node' 
                ? 'text-blue-600 border-b-2 border-blue-600 font-black' 
                : 'hover:text-slate-800'
            }`}
          >
            <ShieldCheck size={14} /> eIDAS 2.0 SAML Lab
          </button>

          <button 
            id="nav-stresstest"
            onClick={() => setActiveMode('stresstest')}
            className={`cursor-pointer transition-all pb-1.5 flex items-center gap-1.5 whitespace-nowrap ${
              activeMode === 'stresstest' 
                ? 'text-blue-600 border-b-2 border-blue-600 font-black' 
                : 'hover:text-slate-800'
            }`}
          >
            <Terminal size={14} /> Lab Demo (Real Path)
          </button>

          <button 
            id="nav-showcase"
            onClick={() => setActiveMode('showcase')}
            className={`cursor-pointer transition-all pb-1.5 flex items-center gap-1.5 whitespace-nowrap ${
              activeMode === 'showcase' 
                ? 'text-[#0B3B60] border-b-2 border-[#0B3B60] font-black' 
                : 'hover:text-slate-800'
            }`}
          >
            <Zap size={14} /> Advanced / Dossier
          </button>
          
          
          <button 
            id="nav-docs"
            onClick={() => setActiveMode('documentation')}
            className={`cursor-pointer transition-all pb-1.5 flex items-center gap-1.5 whitespace-nowrap ${
              activeMode === 'documentation' 
                ? 'text-[#0B3B60] border-b-2 border-[#0B3B60] font-black' 
                : 'hover:text-slate-800'
            }`}
          >
            <FileText size={14} /> Directives
          </button>
        </nav>

        {/* Quick Switch Button Group: [Lab Demo] <-> [Advanced] */}
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200 shadow-xs" title="Switch dashboard mode">
            <button
              id="btn-quick-switch-stress"
              onClick={() => setActiveMode('stresstest')}
              className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeMode === 'stresstest'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/70'
              }`}
            >
              <Terminal size={13} />
              <span>Lab Demo</span>
            </button>
            <button
              id="btn-quick-switch-pos"
              onClick={() => setActiveMode('showcase')}
              className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeMode === 'showcase'
                  ? 'bg-[#0B3B60] text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/70'
              }`}
            >
              <Zap size={13} />
              <span>Advanced</span>
            </button>
          </div>

          {/* Verification Badging */}
          <div className="text-right hidden xl:block">
            <span className="text-[9px] font-bold text-slate-400 block uppercase leading-none">Assigned Store</span>
            <span className="text-xs font-extrabold text-slate-700">{profile.company}</span>
          </div>
          
          <button 
            onClick={() => setShowLicensePrompt(!showLicensePrompt)}
            className="px-4 py-2 bg-[#0B3B60] hover:bg-[#062844] text-white border border-[#0B3B60] rounded font-bold text-xs uppercase tracking-wider transition-all inline-flex items-center gap-1.5 cursor-pointer shadow-xs"
          >
            {isAuthenticated ? <Unlock size={12} className="text-white opacity-80" /> : <Lock size={12} className="text-red-400" />}
            {isAuthenticated ? "SECURE ACTIVE" : "GATEWAY LOCKED"}
          </button>

          <div className="h-8 w-[1px] bg-slate-200 hidden sm:block"></div>

          {/* Access Logs & Audit Database Modal Trigger */}
          <button
            onClick={onOpenAuditLogs}
            className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 rounded font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
            title="Open Local Access Log Database"
          >
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="font-mono text-[11px]">Audit DB</span>
          </button>

          {/* Verified Google Account Profile */}
          <div className="flex items-center gap-2.5 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg">
            {user.picture ? (
              <img 
                src={user.picture} 
                alt={user.name} 
                className="w-6 h-6 rounded-full border border-slate-300 object-cover shrink-0" 
                referrerPolicy="no-referrer"
              />
            ) : (
              <div className="w-6 h-6 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-bold shrink-0">
                {user.name.charAt(0)}
              </div>
            )}
            <div className="text-left hidden md:block">
              <div className="text-[11px] font-bold text-slate-800 leading-tight flex items-center gap-1">
                <span>{user.name}</span>
                <span className="text-[9px] px-1 py-0.2 bg-blue-100 text-blue-800 rounded font-mono font-semibold">Verified</span>
              </div>
              <div className="text-[9px] font-mono text-slate-500 leading-tight truncate max-w-[130px]">{user.email}</div>
            </div>
            <button
              onClick={logout}
              className="ml-1 text-[10px] text-slate-400 hover:text-red-600 font-mono underline cursor-pointer"
              title="Sign out of verified session"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* SECURE LICENSE PROMPT CARD */}
      {showLicensePrompt && (
        <div className="bg-[#EBF3FA] border-b border-[#0B3B60]/20 py-4 px-6 md:px-10 flex flex-col md:flex-row justify-between items-center gap-4 z-30 relative">
          <div className="flex items-center gap-3">
            <AlertCircle className="text-[#0B3B60] shrink-0" size={18} />
            <p className="text-xs text-slate-700 font-sans font-medium">
              Enter your State Customs Certificate key to authorize terminal scanning configurations. Verification metrics are recorded securely.
            </p>
          </div>
          <div className="flex gap-2 w-full md:w-auto">
            <input 
              type="text" 
              placeholder="EU-ID-XXXX-XX"
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value)}
              className="px-3 py-1.5 bg-white border border-slate-300 rounded text-xs font-mono text-slate-800 w-full md:w-44 focus:outline-hidden focus:border-[#0B3B60]"
            />
            <button 
              onClick={() => {
                if (licenseKey) {
                  setProfile(prev => ({ ...prev, licenseNumber: licenseKey }));
                  setIsAuthenticated(true);
                  setShowLicensePrompt(false);
                }
              }}
              className="px-4 py-1.5 bg-[#0B3B60] hover:bg-[#062844] border border-[#0B3B60] text-white rounded font-bold text-xs uppercase tracking-wider transition-all cursor-pointer shadow-xs"
            >
              Verify Credentials
            </button>
          </div>
        </div>
      )}

      {/* 🏛️ MAIN INSTITUTIONAL WORKSPACE */}
      <main className="flex-1 px-4 md:px-10 py-8 max-w-7xl mx-auto w-full">
        {activeMode === 'eidas_node' && (
          <EidasNodeLab />
        )}

        {activeMode === 'stresstest' && (
          <UnifiedLabDemo 
            dkProducts={dkProducts}
            dkWallets={dkWallets}
            onRebate={(delta) => setAccumulatedRebate(prev => prev + delta)}
          />
        )}

        {activeMode === 'showcase' && (
          <BilanxStressTest onSwitchToRetailPos={() => setActiveMode('stresstest')} />
        )}



        {activeMode === 'documentation' && (
          <DocumentationMode />
        )}
      </main>

      {/* 🏁 INSTITUTIONAL REGULATORY FOOTER */}
      <footer className="border-t border-slate-200 flex flex-col lg:flex-row items-center px-6 md:px-10 py-6 gap-6 justify-between bg-white text-xs shrink-0 mt-12 shadow-inner relative">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-slate-100 text-slate-700 border border-slate-300 px-3 py-1 text-[10px] uppercase font-bold rounded shadow-xs tracking-wider z-10 text-center">
          Sandbox: Direct Access Active. Zero PII Recorded.
        </div>
        <div className="flex flex-col sm:flex-row items-center gap-4 lg:gap-10">
          <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest text-center sm:text-left">
            STATE AUDIT DIRECTIVES:
          </div>
          <div className="flex flex-wrap gap-4 md:gap-8 text-[11px] font-mono font-bold text-slate-700 uppercase tracking-tighter justify-center">
            <span>✓ E-Services Gateway</span>
            <span>✓ Excise Duty Compliance</span>
            <span>✓ eIDAS Verification Integration</span>
            <span>✓ Zero PII Record Keeping</span>
          </div>
        </div>
        
        <div className="flex flex-col sm:flex-row items-center gap-4 text-center sm:text-right">
          <span className="text-[10px] text-slate-500 italic font-mono">
            Directive Framework: COM(2026) 438 / Customs Compliance Hub
          </span>
          <div className="h-4 w-[1px] bg-slate-300 hidden sm:block"></div>
          <span className="text-xs font-bold text-[#0B3B60] tracking-wider flex items-center gap-1.5 justify-center sm:justify-end uppercase font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-[#0B3B60]"></span>
            SYSTEM DISCIPLINED: SECURE STATE NODE
          </span>
        </div>
      </footer>

    </div>
  );
}
