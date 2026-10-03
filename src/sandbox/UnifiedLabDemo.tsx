import React, { useState, useEffect } from 'react';
import { runDualKeyAgeGate } from './lib/e2e/runDualKeyAgeGate';
import { Terminal, Zap, CheckCircle, XCircle, ShoppingBag, User, ShieldCheck, Activity, Fingerprint } from 'lucide-react';
import type { DKProduct, DKWallet } from '../types';

interface UnifiedLabDemoProps {
  dkProducts: DKProduct[];
  dkWallets: DKWallet[];
  onRebate?: (delta: number) => void;
}

type E2EAgeGateResult = {
  dualKeyOk: boolean;
  ageGateOk: boolean;
  proofBytes: Uint8Array;
  proofByteLength: number;
  timings: {
    dualKey_ms: number;
    server_dual_key_verify_ms?: number;
    prove_ms: number;
    verify_ms: number;
    total_ms: number;
  };
  error?: string;
};

export default function UnifiedLabDemo({ dkProducts, dkWallets, onRebate }: UnifiedLabDemoProps) {
  const defaultProduct = dkProducts.find(p => p.status === 'authentic') || dkProducts[0];
  const defaultWallet = dkWallets[0];

  const [selectedProductId, setSelectedProductId] = useState<string>(defaultProduct?.id || '');
  const [selectedWalletId, setSelectedWalletId] = useState<string>(defaultWallet?.id || '');

  const [age, setAge] = useState<number>(defaultWallet?.ageGroup === 'Under 18' ? 17 : 18);
  const [threshold] = useState<number>(18);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<{ i: number; n: number } | null>(null);
  const [results, setResults] = useState<E2EAgeGateResult[]>([]);
  const [stressCount, setStressCount] = useState<number>(30);

  const selectedProduct = dkProducts.find(p => p.id === selectedProductId) || null;
  const selectedWallet = dkWallets.find(w => w.id === selectedWalletId) || null;

  const handleWalletSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const wId = e.target.value;
    setSelectedWalletId(wId);
    const wallet = dkWallets.find(w => w.id === wId);
    if (wallet) {
      setAge(wallet.ageGroup === 'Under 18' ? 17 : 18);
    }
  };

  const runSingle = async () => {
    setRunning(true);
    setResults([]);
    try {
      const result = await runDualKeyAgeGate({ age, threshold });
      setResults([result]);
      
      if (result.dualKeyOk && result.ageGateOk && onRebate) {
        onRebate(0.15);
      }
    } catch (err: any) {
      setResults([{
        dualKeyOk: false,
        ageGateOk: false,
        proofBytes: new Uint8Array(),
        proofByteLength: 0,
        timings: { dualKey_ms: 0, prove_ms: 0, verify_ms: 0, total_ms: 0 },
        error: err.message || String(err)
      }]);
    } finally {
      setRunning(false);
    }
  };

  const runStress = async () => {
    setRunning(true);
    setResults([]);
    setProgress({ i: 0, n: stressCount });
    const currentResults: E2EAgeGateResult[] = [];
    try {
      for (let i = 0; i < stressCount; i++) {
        setProgress({ i: i + 1, n: stressCount });
        const result = await runDualKeyAgeGate({ age, threshold });
        currentResults.push(result);
        setResults([...currentResults]); // Update UI sequentially
      }
    } catch (err: any) {
      currentResults.push({
        dualKeyOk: false,
        ageGateOk: false,
        proofBytes: new Uint8Array(),
        proofByteLength: 0,
        timings: { dualKey_ms: 0, prove_ms: 0, verify_ms: 0, total_ms: 0 },
        error: err.message || String(err)
      });
      setResults([...currentResults]);
    } finally {
      setRunning(false);
      setProgress(null);
    }
  };

  const clearResults = () => setResults([]);

  const computeStats = () => {
    if (results.length === 0) return null;
    const successCount = results.filter(r => r.dualKeyOk && r.ageGateOk).length;
    const failCount = results.length - successCount;
    const totalMsArr = results.map(r => r.timings.total_ms).sort((a, b) => a - b);
    const meanTotal = totalMsArr.reduce((a, b) => a + b, 0) / totalMsArr.length;
    const p50Total = totalMsArr[Math.floor(totalMsArr.length * 0.5)] || 0;
    const p95Total = totalMsArr[Math.floor(totalMsArr.length * 0.95)] || 0;

    return { successCount, failCount, meanTotal, p50Total, p95Total };
  };

  const stats = computeStats();
  const latestResult = results.length > 0 ? results[results.length - 1] : null;

  return (
    <div className="flex-1 bg-slate-950 text-slate-200 overflow-y-auto">
      {/* Zone A: Header */}
      <div className="bg-slate-900 border-b border-slate-800 p-6 shadow-sm">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <Terminal className="text-blue-400" /> DK-SVS POS Age-Gate (Lab — Real Path)
            </h2>
            <p className="text-slate-400 mt-1">
              Powered by <code className="text-[11px] font-mono bg-slate-800 px-1.5 py-0.5 rounded text-blue-300 border border-slate-700">runDualKeyAgeGate</code> (E2E cryptographic path, no mocks)
            </p>
          </div>
          <div className="text-xs text-slate-400 bg-slate-800/80 px-4 py-2.5 rounded-lg border border-slate-700/50 max-w-md shadow-inner">
            Need Key-1 mock vs real compare or Technical Dossier? Use top nav: <strong className="text-slate-200 font-semibold">Advanced / Dossier</strong>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto p-6 space-y-6">
        
        {/* POS Ticket Layout */}
        <div className="grid md:grid-cols-2 gap-6">
          
          {/* Left Column: Product */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <ShoppingBag size={18} className="text-slate-400"/> Scanned Item
              </h3>
              {selectedProduct && (
                <span className={`text-[10px] px-2 py-1 rounded border uppercase tracking-widest font-bold ${
                  selectedProduct.status === 'authentic' ? 'bg-emerald-950/60 text-emerald-400 border-emerald-900/50' : 
                  selectedProduct.status === 'counterfeit' ? 'bg-red-950/60 text-red-400 border-red-900/50' :
                  'bg-orange-950/60 text-orange-400 border-orange-900/50'
                }`}>
                  {selectedProduct.status}
                </span>
              )}
            </div>
            <div className="mb-4">
              <select
                value={selectedProductId}
                onChange={(e) => setSelectedProductId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-sans text-sm focus:border-blue-500 outline-none transition-colors"
              >
                <option value="" disabled>Select a product...</option>
                {dkProducts.map(p => (
                  <option key={p.id} value={p.id}>{p.name} ({p.category}) - {p.uid}</option>
                ))}
              </select>
            </div>
            {selectedProduct ? (
              <div className="flex flex-col mt-auto gap-4">
                <div className="flex justify-between items-center">
                  <div>
                    <div className="text-lg font-bold text-white">{selectedProduct.name}</div>
                    <div className="text-sm text-slate-400">{selectedProduct.category}</div>
                    <div className="text-xs text-slate-500 font-mono mt-1">UID: {selectedProduct.uid}</div>
                  </div>
                  <div className="text-2xl font-light text-white tracking-tight">€{selectedProduct.price.toFixed(2)}</div>
                </div>
                
                {selectedProduct.status !== 'authentic' && (
                  <div className="bg-orange-950/40 border border-orange-900/50 rounded-lg p-3 text-xs text-orange-200">
                    <div className="font-bold text-orange-400 uppercase tracking-wider mb-1">
                      Stock Policy Block: {selectedProduct.status}
                    </div>
                    <p>
                      This is a stock / policy gate, not the age-gate proof. Dual-Key + B2 age-gate may still be run below for lab testing purposes.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-sm text-slate-500 italic mt-auto">Select a product from catalog</div>
            )}
          </div>

          {/* Right Column: Customer Wallet */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col">
            <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <User size={18} className="text-slate-400"/> Customer Wallet
              </h3>
              <span className="text-[10px] text-slate-500 uppercase tracking-wider">Simulated inputs</span>
            </div>
            
            <div className="mb-4">
              <select
                value={selectedWalletId}
                onChange={handleWalletSelect}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-sans text-sm focus:border-blue-500 outline-none transition-colors mb-4"
              >
                <option value="" disabled>Select a customer wallet...</option>
                {dkWallets.map(w => (
                  <option key={w.id} value={w.id}>{w.id} - {w.country} ({w.holderClass}) [{w.ageGroup}]</option>
                ))}
              </select>

              {selectedWallet ? (
                <div className="mb-4">
                  <div className="text-lg font-bold text-white">{selectedWallet.id}</div>
                  <div className="text-sm text-slate-400">{selectedWallet.holderClass}</div>
                  <div className="text-xs text-slate-500 font-mono mt-1">Age Group: {selectedWallet.ageGroup}</div>
                  <div className="text-xs text-blue-400 font-mono mt-2 bg-blue-950/30 p-2 rounded border border-blue-900/50 inline-block">
                    Age used for proof: {age}
                  </div>
                </div>
              ) : (
                <div className="text-sm text-slate-500 italic mb-4">Select a customer wallet</div>
              )}

              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2 pl-4 border-l border-slate-800">
                  <label className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Custom Age Override:</label>
                  <input 
                    type="number" 
                    value={age} 
                    onChange={(e) => setAge(parseInt(e.target.value) || 0)} 
                    className="w-16 bg-slate-950 border border-slate-700 rounded p-1.5 text-white font-mono text-center text-sm focus:border-blue-500 outline-none transition-colors" 
                  />
                </div>
              </div>
            </div>
            
            {/* Honest Threshold Hint */}
            <div className="mt-auto bg-slate-950/50 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2"><ShieldCheck size={14} className="text-blue-400"/> B2 Facade Policy (Fixed)</span>
              <span className="font-mono bg-slate-900 border border-slate-800 px-2.5 py-1 rounded text-slate-300 font-medium">Threshold: {threshold}</span>
            </div>
          </div>

        </div>

        {/* Zone C: Primary Action */}
        <div className="flex flex-col gap-2">
          <button 
            onClick={runSingle}
            disabled={running || !selectedProductId || !selectedWalletId}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-lg shadow-blue-900/20 p-5 flex flex-col items-center justify-center transition-all disabled:opacity-50 disabled:cursor-not-allowed group relative overflow-hidden min-h-[90px]"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-blue-400 opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative flex items-center gap-3 text-lg tracking-wide">
              <Fingerprint size={24} className={running ? 'animate-pulse text-blue-200' : 'text-blue-200'} />
              {running ? 'Validating via Dual-Key...' : 'Validate at POS'}
            </div>
          </button>
          {(!selectedProductId || !selectedWalletId) && (
            <div className="text-center text-sm text-slate-400 font-medium">Select product and wallet to validate</div>
          )}
        </div>

        {/* Zone D: Decision Banner (Latest Result) */}
        <div>
          {latestResult ? (
            <div className={`rounded-xl p-5 border shadow-lg flex flex-col ${latestResult.dualKeyOk && latestResult.ageGateOk ? 'bg-green-950/20 border-green-900/40 shadow-green-900/10' : 'bg-red-950/20 border-red-900/40 shadow-red-900/10'}`}>
              
              <div className="flex flex-col md:flex-row gap-4 mb-6">
                <div className={`flex-1 text-center p-4 rounded-lg border ${latestResult.dualKeyOk && latestResult.ageGateOk ? 'bg-green-950/40 border-green-800/50' : 'bg-red-950/40 border-red-800/50'}`}>
                  <div className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">Crypto Age-Gate</div>
                  {latestResult.dualKeyOk && latestResult.ageGateOk ? (
                    <div className="inline-flex items-center gap-2 text-xl font-black text-green-400 uppercase tracking-widest">
                      <CheckCircle size={22} /> APPROVED
                    </div>
                  ) : (
                    <div className="inline-flex items-center gap-2 text-xl font-black text-red-400 uppercase tracking-widest">
                      <XCircle size={22} /> REJECTED
                    </div>
                  )}
                  {latestResult.error && (
                    <div className="text-red-300 text-xs mt-3 font-mono bg-red-950/50 border border-red-900/50 p-2 rounded-lg break-words text-left">
                      {latestResult.error}
                    </div>
                  )}
                </div>

                <div className={`flex-1 text-center p-4 rounded-lg border ${!selectedProduct || selectedProduct.status === 'authentic' ? 'bg-emerald-950/20 border-emerald-900/30' : 'bg-orange-950/40 border-orange-800/50'}`}>
                  <div className="text-xs text-slate-400 uppercase tracking-widest font-semibold mb-2">Stock Policy</div>
                  {!selectedProduct || selectedProduct.status === 'authentic' ? (
                    <div className="inline-flex items-center gap-2 text-xl font-black text-emerald-400 uppercase tracking-widest">
                      <CheckCircle size={22} /> OK
                    </div>
                  ) : (
                    <div className="inline-flex items-center gap-2 text-xl font-black text-orange-400 uppercase tracking-widest">
                      <XCircle size={22} /> BLOCK ({selectedProduct.status})
                    </div>
                  )}
                </div>
              </div>
              
              <div className="text-center mb-6 text-sm text-slate-300 font-medium">
                {selectedProduct && selectedWallet && (
                  <>Ticket: {selectedProduct.name} &middot; {selectedWallet.id} &middot; age {age}</>
                )}
              </div>
              
              {/* Prominent Main Metrics */}
              {!latestResult.error && (
                <div className="grid md:grid-cols-2 gap-3 mb-5">
                  <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-center">
                    <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-1 font-semibold">Total Latency</div>
                    <div className="text-xl font-mono text-white tracking-tight">{latestResult.timings.total_ms.toFixed(1)} <span className="text-xs text-slate-500">ms</span></div>
                  </div>
                  <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-center">
                    <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-1 font-semibold">Proof Size</div>
                    <div className="text-xl font-mono text-white tracking-tight">{latestResult.proofByteLength} <span className="text-xs text-slate-500">B</span></div>
                  </div>
                </div>
              )}

              {/* Scope 2 Honest Lab Breakdown */}
              <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3.5 text-xs font-mono text-slate-400 space-y-2 mt-auto shadow-inner">
                <div className="flex justify-between border-b border-slate-800/80 pb-2 mb-2 font-sans font-bold text-slate-300 uppercase tracking-wider text-[10px]">
                  Lab Metrics Breakdown
                </div>
                {!latestResult.error ? (
                  <>
                    <div className="flex justify-between items-center"><span>Dual-Key:</span> <span className="text-slate-200">{latestResult.timings.dualKey_ms.toFixed(1)} ms</span></div>
                    <div className="flex justify-between items-center"><span>Server Dual-Key verify:</span> <span className="text-slate-200">{latestResult.timings.server_dual_key_verify_ms !== undefined ? `${latestResult.timings.server_dual_key_verify_ms.toFixed(1)} ms` : 'n/a'}</span></div>
                    <div className="flex justify-between items-center"><span>Prove (B2):</span> <span className="text-slate-200">{latestResult.timings.prove_ms.toFixed(1)} ms</span></div>
                    <div className="flex justify-between items-center"><span>Verify (B2):</span> <span className="text-slate-200">{latestResult.timings.verify_ms.toFixed(1)} ms</span></div>
                  </>
                ) : (
                  <div className="text-center text-slate-600 py-3 font-sans italic">Metrics unavailable (Error)</div>
                )}
              </div>

            </div>
          ) : (
            <div className="rounded-xl p-8 border border-slate-800 border-dashed flex flex-col items-center justify-center text-slate-500 bg-slate-900/30">
              <ShieldCheck size={36} className="mb-4 text-slate-700" />
              <div className="text-sm font-semibold tracking-wide">Awaiting POS Validation</div>
              <div className="text-xs mt-1 max-w-[200px] text-center text-slate-500">Ready to initiate cryptographic age-gate check.</div>
            </div>
          )}
        </div>

        {/* Zone E: Lab Stress (Secondary) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg mt-8">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2">
              <Activity className="text-purple-400" size={18} />
              <h3 className="text-white font-semibold">Lab Batch Stress</h3>
              <span className="ml-2 text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded uppercase tracking-widest border border-slate-700">Real Path</span>
            </div>
            
            <div className="flex items-center gap-3">
              <select 
                value={stressCount} 
                onChange={(e) => setStressCount(parseInt(e.target.value))}
                className="bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono text-sm focus:border-purple-500 outline-none transition-colors"
              >
                <option value={5}>5 runs</option>
                <option value={10}>10 runs</option>
                <option value={30}>30 runs</option>
              </select>
              <button 
                onClick={runStress} 
                disabled={running}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm font-bold rounded-lg shadow shadow-purple-900/20 disabled:opacity-50 flex items-center gap-2 min-w-[140px] justify-center transition-colors"
              >
                <Zap size={14} /> {progress ? `${progress.i} / ${progress.n}` : `Run Batch`}
              </button>
              <button 
                onClick={clearResults} 
                disabled={running || results.length === 0}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-bold rounded-lg shadow border border-slate-700 disabled:opacity-50 transition-colors"
              >
                Clear List
              </button>
            </div>
          </div>

          {/* Stress Results List */}
          {results.length > 1 && stats ? (
            <div className="space-y-5">
              {/* Batch Aggregates */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 p-4 bg-slate-950 rounded-lg border border-slate-800/80 font-mono text-sm">
                <div className="text-center md:text-left"><div className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold mb-1">Success</div><div className="text-green-400 font-bold text-lg">{stats.successCount}</div></div>
                <div className="text-center md:text-left"><div className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold mb-1">Failed</div><div className="text-red-400 font-bold text-lg">{stats.failCount}</div></div>
                <div className="text-center md:text-left"><div className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold mb-1">Mean Latency</div><div className="text-blue-300 text-base">{stats.meanTotal.toFixed(1)} <span className="text-xs text-slate-500">ms</span></div></div>
                <div className="text-center md:text-left"><div className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold mb-1">p50 Latency</div><div className="text-blue-300 text-base">{stats.p50Total.toFixed(1)} <span className="text-xs text-slate-500">ms</span></div></div>
                <div className="text-center md:text-left"><div className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold mb-1">p95 Latency</div><div className="text-blue-300 text-base">{stats.p95Total.toFixed(1)} <span className="text-xs text-slate-500">ms</span></div></div>
              </div>
              
              {/* Batch Detail List */}
              <div className="space-y-2 max-h-[350px] overflow-y-auto pr-2 custom-scrollbar">
                {results.map((r, idx) => (
                  <div key={idx} className="flex flex-col md:flex-row md:items-center justify-between p-3 bg-slate-900/50 border border-slate-800/80 rounded-lg font-mono text-xs gap-3">
                    <div className="flex items-center gap-4">
                      <span className="text-slate-600 font-semibold w-6">{idx+1}.</span>
                      <span className={`px-2.5 py-1 rounded-md tracking-wider font-bold text-[10px] ${r.dualKeyOk && r.ageGateOk ? 'bg-green-950 text-green-400 border border-green-900/50' : 'bg-red-950 text-red-400 border border-red-900/50'}`}>
                        {r.dualKeyOk && r.ageGateOk ? 'APPROVED' : 'REJECTED'}
                      </span>
                      {r.error && <span className="text-red-400/80 text-[10px] truncate max-w-[200px] font-sans italic">{r.error}</span>}
                    </div>
                    {!r.error && (
                      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-slate-500">
                        <span className="flex items-center gap-1.5"><span className="text-[10px] uppercase tracking-wider font-sans">Tot:</span> <span className="text-slate-300 font-medium">{r.timings.total_ms.toFixed(1)}</span>ms</span>
                        <span className="flex items-center gap-1.5"><span className="text-[10px] uppercase tracking-wider font-sans">Prv:</span> <span className="text-slate-300 font-medium">{r.timings.prove_ms.toFixed(1)}</span>ms</span>
                        <span className="flex items-center gap-1.5"><span className="text-[10px] uppercase tracking-wider font-sans">Vrf:</span> <span className="text-slate-300 font-medium">{r.timings.verify_ms.toFixed(1)}</span>ms</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            results.length <= 1 && (
              <div className="flex flex-col items-center justify-center text-slate-500 py-8 bg-slate-900/30 rounded-lg border border-slate-800 border-dashed">
                <Activity size={32} className="mb-3 opacity-20" />
                <span className="text-sm">Run a batch stress test to view aggregate metrics.</span>
              </div>
            )
          )}
        </div>

      </div>
    </div>
  );
}
