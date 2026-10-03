import React, { useState } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Zap, 
  Clock, 
  CheckCircle2, 
  XCircle,
  Play,
  RotateCcw,
  Square,
  Columns,
  BarChart2
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useDualKeyValidation, HandshakeState, DualKeyValidationResult } from './hooks/useDualKeyValidation';

// Utility for rendering badges
const StatusBadge = ({ label, success }: { label: string; success?: boolean }) => {
  if (success === undefined) return <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">{label}: N/A</span>;
  return success ? (
    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 border border-green-200">
      <CheckCircle2 className="w-3 h-3 mr-1" />
      {label}: Valid
    </span>
  ) : (
    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">
      <XCircle className="w-3 h-3 mr-1" />
      {label}: Invalid
    </span>
  );
};

const StateBadge = ({ state }: { state: HandshakeState }) => {
  const styles: Record<string, string> = {
    'IDLE': 'bg-gray-100 text-gray-800',
    'INITIATING': 'bg-blue-100 text-blue-800 animate-pulse',
    'AWAITING_CHALLENGE': 'bg-purple-100 text-purple-800 animate-pulse',
    'VERIFYING_SIGNATURES': 'bg-amber-100 text-amber-800 animate-pulse',
    'COMPLETED': 'bg-green-100 text-green-800',
    'FAILED': 'bg-red-100 text-red-800',
  };
  
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold tracking-wide ${styles[state] || styles.IDLE}`}>
      {state}
    </span>
  );
}

export function SandboxCryptoComparison() {
  const [executionMode, setExecutionMode] = useState<'SINGLE' | 'PARALLEL'>('SINGLE');
  const [activeSingleTarget, setActiveSingleTarget] = useState<'MOCK' | 'REAL'>('MOCK');
  
  const [institutionId, setInstitutionId] = useState('INST-8472-BX');
  const [secondFactorId, setSecondFactorId] = useState('RFID-9932-AX');
  
  // By maintaining two separate instances, each preserves its own historical state automatically.
  const mockValidation = useDualKeyValidation({ useRealCrypto: false });
  const realValidation = useDualKeyValidation({ useRealCrypto: true });

  const isMockRunning = mockValidation.state !== 'IDLE' && mockValidation.state !== 'COMPLETED' && mockValidation.state !== 'FAILED';
  const isRealRunning = realValidation.state !== 'IDLE' && realValidation.state !== 'COMPLETED' && realValidation.state !== 'FAILED';
  
  const isRunning = executionMode === 'SINGLE' 
    ? (activeSingleTarget === 'MOCK' ? isMockRunning : isRealRunning)
    : (isMockRunning || isRealRunning);

  const handleRun = () => {
    if (executionMode === 'PARALLEL') {
      mockValidation.runDualKeyHandshake({ institutionId, secondFactorId });
      realValidation.runDualKeyHandshake({ institutionId, secondFactorId });
    } else {
      if (activeSingleTarget === 'MOCK') {
        mockValidation.runDualKeyHandshake({ institutionId, secondFactorId });
      } else {
        realValidation.runDualKeyHandshake({ institutionId, secondFactorId });
      }
    }
  };

  const handleReset = () => {
    if (executionMode === 'PARALLEL') {
      mockValidation.reset();
      realValidation.reset();
    } else {
      if (activeSingleTarget === 'MOCK') mockValidation.reset();
      else realValidation.reset();
    }
  };

  const renderColumn = (
    title: string, 
    description: string, 
    isActive: boolean, 
    data: { state: HandshakeState, result: DualKeyValidationResult | null },
    icon: React.ReactNode
  ) => {
    const { state, result } = data;
    
    return (
      <div className={`relative flex flex-col p-6 rounded-2xl border-2 transition-all duration-300 ${isActive ? 'border-blue-500 bg-white shadow-xl' : 'border-gray-200 bg-gray-50/50 grayscale-[0.2]'}`}>
        {!isActive && (
          <div className="absolute inset-0 bg-gray-50/40 rounded-2xl z-10 pointer-events-none" />
        )}
        
        <div className="flex items-center space-x-3 mb-2">
          <div className={`p-2 rounded-lg ${isActive ? 'bg-blue-100 text-blue-600' : 'bg-gray-200 text-gray-500'}`}>
            {icon}
          </div>
          <div>
            <h3 className="text-lg font-bold text-gray-900">{title}</h3>
            <p className="text-sm text-gray-500">{description}</p>
          </div>
        </div>

        <div className="mt-6 flex items-center justify-between">
          <span className="text-sm font-semibold text-gray-500 tracking-wide uppercase">Current State</span>
          <StateBadge state={state} />
        </div>

        <div className="mt-6 flex-1">
          <div className="bg-gray-50 rounded-xl border border-gray-200 p-4 min-h-[320px] flex flex-col shadow-inner">
            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Handshake Results</h4>
            
            {result ? (
              <div className="space-y-5 flex-1 flex flex-col">
                <div className="grid grid-cols-2 gap-3">
                  <StatusBadge label="Inst. Sig" success={result.institutionalSignatureValid} />
                  <StatusBadge label="User Sig" success={result.userSignatureValid} />
                  <div className="col-span-2 flex justify-center mt-1">
                    <StatusBadge label="Cryptographic Binding" success={result.bindingValid} />
                  </div>
                </div>
                
                <div className="flex items-center justify-between py-3 border-y border-gray-200 bg-white px-3 rounded-lg shadow-sm">
                  <div className="flex items-center text-sm font-medium text-gray-600">
                    <Clock className="w-4 h-4 mr-2 text-blue-500" />
                    Latency
                  </div>
                  <span className="font-mono font-bold text-gray-900">{result.latencyMs} ms</span>
                </div>
                
                <div className="flex-1 mt-2 flex flex-col">
                  <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 block">Execution Logs</span>
                  <div className="bg-[#1e1e1e] text-[#4af626] font-mono text-[11px] p-3 rounded-lg overflow-y-auto h-[160px] leading-relaxed shadow-inner">
                    {result.logs?.map((log, i) => (
                      <div key={i} className="mb-1">{`> ${log}`}</div>
                    ))}
                    {(!result.logs || result.logs.length === 0) && (
                      <div className="opacity-50 italic">No logs available.</div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
                <ShieldAlert className="w-12 h-12 mb-3 opacity-20" />
                <p className="text-sm font-medium">No result available.</p>
                <p className="text-xs text-gray-400 mt-1">Run handshake to view data.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderLatencyComparison = () => {
    const mockMs = mockValidation.result?.latencyMs;
    const realMs = realValidation.result?.latencyMs;
    
    if (mockMs === undefined && realMs === undefined) return null;

    const chartData = [
      { name: 'Mock', latency: mockMs || 0, color: '#9ca3af' }, // gray-400
      { name: 'Real', latency: realMs || 0, color: '#3b82f6' }  // blue-500
    ];

    let ratioText = '';
    if (mockMs !== undefined && realMs !== undefined && mockMs > 0 && realMs > 0) {
      if (mockMs > realMs) {
        const ratio = (mockMs / realMs).toFixed(1);
        ratioText = `Real crypto is ~${ratio}x faster`;
      } else if (realMs > mockMs) {
        const ratio = (realMs / mockMs).toFixed(1);
        ratioText = `Mock is ~${ratio}x faster`;
      } else {
        ratioText = `Both took the same time`;
      }
    }

    return (
      <div className="bg-white p-6 rounded-2xl shadow-md border border-gray-200 mt-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-100 text-purple-600 rounded-lg">
              <BarChart2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-gray-900">Performance Comparison</h3>
              <p className="text-sm text-gray-500">Latency difference between implementations</p>
            </div>
          </div>
          {ratioText && (
            <span className="text-sm font-semibold text-green-700 bg-green-50 px-3 py-1 rounded-full border border-green-200">
              {ratioText}
            </span>
          )}
        </div>

        <div className="h-48 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" unit=" ms" />
              <YAxis dataKey="name" type="category" width={60} tick={{ fontSize: 14, fontWeight: 500 }} />
              <Tooltip 
                formatter={(value: number) => [`${value} ms`, 'Latency']}
                cursor={{ fill: '#f3f4f6' }}
                contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' }}
              />
              <Bar dataKey="latency" radius={[0, 4, 4, 0]} barSize={40}>
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-8 font-sans">
      
      {/* Header */}
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center p-3 bg-blue-50 text-blue-600 rounded-full mb-2">
          <ShieldCheck className="w-8 h-8" />
        </div>
        <h2 className="text-3xl font-extrabold text-gray-900 tracking-tight">DK-SVS Dual-Key Handshake Comparison</h2>
        <p className="text-lg text-gray-500 max-w-2xl mx-auto">
          Compare the high-fidelity mock simulation against the real ECDSA P-256 Web Crypto implementation.
        </p>
      </div>

      {/* Controls */}
      <div className="bg-white p-6 rounded-2xl shadow-md border border-gray-200">
        
        {/* Execution Mode Selector */}
        <div className="flex justify-center mb-6">
          <div className="inline-flex bg-gray-100 p-1.5 rounded-xl">
            <button
              onClick={() => setExecutionMode('SINGLE')}
              className={`flex items-center px-5 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                executionMode === 'SINGLE' ? 'bg-white text-gray-900 shadow-sm ring-1 ring-gray-200' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200/50'
              }`}
            >
              <Square className="w-4 h-4 mr-2" />
              Single Mode
            </button>
            <button
              onClick={() => setExecutionMode('PARALLEL')}
              className={`flex items-center px-5 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                executionMode === 'PARALLEL' ? 'bg-white text-gray-900 shadow-sm ring-1 ring-gray-200' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200/50'
              }`}
            >
              <Columns className="w-4 h-4 mr-2" />
              Parallel Comparison
            </button>
          </div>
        </div>

        {/* Target Selector (only visible in Single Mode) */}
        {executionMode === 'SINGLE' && (
          <div className="flex justify-center mb-8">
            <div className="inline-flex bg-gray-50 p-1 rounded-xl border border-gray-200">
              <button
                onClick={() => setActiveSingleTarget('MOCK')}
                className={`flex items-center px-6 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  activeSingleTarget === 'MOCK' ? 'bg-white text-gray-900 shadow-sm ring-1 ring-gray-200' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Cpu className={`w-4 h-4 mr-2 ${activeSingleTarget === 'MOCK' ? 'text-gray-900' : 'text-gray-400'}`} />
                High-Fidelity Mock
              </button>
              <button
                onClick={() => setActiveSingleTarget('REAL')}
                className={`flex items-center px-6 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  activeSingleTarget === 'REAL' ? 'bg-white text-blue-700 shadow-sm ring-1 ring-gray-200' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Zap className={`w-4 h-4 mr-2 ${activeSingleTarget === 'REAL' ? 'text-blue-600' : 'text-gray-400'}`} />
                Real Web Crypto
              </button>
            </div>
          </div>
        )}

        {/* Inputs & Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-3xl mx-auto mb-8">
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-gray-700">Institution ID</label>
            <input 
              type="text" 
              value={institutionId}
              onChange={(e) => setInstitutionId(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors font-mono text-sm shadow-sm"
              placeholder="e.g. INST-8472-BX"
            />
          </div>
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-gray-700">Second Factor ID (RFID/Token)</label>
            <input 
              type="text" 
              value={secondFactorId}
              onChange={(e) => setSecondFactorId(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors font-mono text-sm shadow-sm"
              placeholder="e.g. RFID-9932-AX"
            />
          </div>
        </div>

        <div className="flex justify-center space-x-4">
          <button 
            onClick={handleRun}
            disabled={isRunning}
            className={`flex items-center px-8 py-3 bg-gray-900 hover:bg-gray-800 text-white rounded-xl font-bold shadow-md transition-all ${
              isRunning ? 'opacity-50 cursor-not-allowed' : 'active:scale-95'
            }`}
          >
            <Play className={`w-5 h-5 mr-2 ${isRunning ? 'animate-pulse' : ''}`} />
            {executionMode === 'PARALLEL' 
              ? (isRunning ? 'Running Both...' : 'Run Both (Parallel)') 
              : (isRunning ? 'Running Handshake...' : 'Run Dual-Key Handshake')}
          </button>
          <button 
            onClick={handleReset}
            title={executionMode === 'PARALLEL' ? 'Reset Both' : 'Reset Active Mode'}
            className="flex items-center px-4 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl font-semibold transition-all shadow-sm active:scale-95"
          >
            <RotateCcw className="w-5 h-5" />
            {executionMode === 'PARALLEL' && <span className="ml-2 font-semibold">Reset Both</span>}
          </button>
        </div>
      </div>

      {/* Comparison Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {renderColumn(
          'Mock Simulation',
          'Simulated delays & state transitions',
          executionMode === 'PARALLEL' || activeSingleTarget === 'MOCK',
          { state: mockValidation.state, result: mockValidation.result },
          <Cpu className="w-6 h-6" />
        )}
        
        {renderColumn(
          'Real Web Crypto',
          'ECDSA P-256 with strong binding',
          executionMode === 'PARALLEL' || activeSingleTarget === 'REAL',
          { state: realValidation.state, result: realValidation.result },
          <Shield className="w-6 h-6" />
        )}
      </div>

      {/* Latency Comparison Chart */}
      {renderLatencyComparison()}
    </div>
  );
}

