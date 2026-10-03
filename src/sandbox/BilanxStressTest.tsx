import { useState, useEffect } from 'react';
import { useFormStatus } from 'react-dom';
import { Terminal, ArrowRight } from 'lucide-react';
// Imported exclusively from the isolated sandbox location.
// (Using relative path to avoid compilation errors without custom path aliases,
// representing the @sandbox/mocks/useBilanxDualKeyValidation.mock alias).
import { useBilanxDualKeyValidation } from './mocks/useBilanxDualKeyValidation.mock';
import { SandboxCryptoComparison } from './SandboxCryptoComparison';
import { SandboxDocumentation } from './SandboxDocumentation';
import { SandboxStats } from './SandboxStats';
import { RecentlyProcessedItems } from './RecentlyProcessedItems';
import { LiveItemFeed } from './LiveItemFeed';
import { SandboxTabNavigation, TabType } from './SandboxTabNavigation';
import { SandboxDossier } from './SandboxDossier';
import { DualKeyResultProvider } from './context/DualKeyResultContext';

interface BilanxStressTestProps {
  onSwitchToRetailPos?: () => void;
}

/**
 * A dedicated button for batch stress testing.
 * Uses React 19's `useFormStatus` to automatically show pending state
 * when the form action is executing the stress test payload.
 */
function StressTestButton({ count }: { count: number }) {
  const { pending } = useFormStatus();
  return (
    <button 
      type="submit"
      name="count"
      value={count}
      disabled={pending}
      className="px-4 py-2 bg-blue-600 text-white font-medium rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
    >
      {pending ? 'Running...' : `Stress Test ${count} items`}
    </button>
  );
}

export function BilanxStressTest({ onSwitchToRetailPos }: BilanxStressTestProps = {}) {
  const [activeTab, setActiveTab] = useState<TabType>('dossier');
  const { items, pendingIds, validateItem, runStressTest, resetDataset, stats } = useBilanxDualKeyValidation();

  // --- Pagination Logic ---
  // Using state to track current page. Batching 50 items per page.
  const [currentPage, setCurrentPage] = useState(1);
  const [showDocumentation, setShowDocumentation] = useState(false);
  const itemsPerPage = 50;
  
  // Calculate total pages based on items length
  const totalPages = Math.ceil(items.length / itemsPerPage);
  // Slice the items array to only show the current page's items
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const displayItems = items.slice(startIndex, endIndex);

  const goToPage = (page: number) => {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)));
  };

  // --- Recently Processed Items Logic ---
  const [lastBatchIds, setLastBatchIds] = useState<Set<string>>(new Set());

  // Capture IDs as they become pending (i.e. start processing)
  useEffect(() => {
    if (pendingIds.size > 0) {
      setLastBatchIds(prev => {
        let hasNew = false;
        pendingIds.forEach(id => {
          if (!prev.has(id)) hasNew = true;
        });
        
        if (!hasNew) return prev;
        const next = new Set(prev);
        pendingIds.forEach(id => next.add(id));
        return next;
      });
    }
  }, [pendingIds]);

  const handleRunStressTest = (payload: FormData) => {
    // Clear the previous batch tracking before starting a new one
    setLastBatchIds(new Set());
    runStressTest(payload);
  };

  const handleReset = () => {
    setLastBatchIds(new Set());
    resetDataset();
    setCurrentPage(1);
  };

  // ------------------------

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'validated': return 'text-green-700 bg-green-50 border-green-200';
      case 'failed': return 'text-red-700 bg-red-50 border-red-200';
      case 'in_progress': 
      case 'dual_key_in_progress': return 'text-indigo-700 bg-indigo-50 border-indigo-200';
      case 'eidas_in_progress': return 'text-purple-700 bg-purple-50 border-purple-200';
      default: return 'text-gray-700 bg-gray-50 border-gray-200';
    }
  };

  const getStatusLabel = (status: string) => {
    if (status === 'eidas_in_progress') return 'eIDAS in Progress';
    if (status === 'dual_key_in_progress' || status === 'in_progress') return 'Dual-Key in Progress';
    if (status === 'validated') return 'Validated';
    if (status === 'failed') return 'Failed';
    return 'Pending';
  };

  // --- Phase Indicator Logic ---
  // Helper to determine the current active phase and its visual styling
  const getPhaseInfo = (status: string, phase?: string) => {
    if (phase === 'eidas' || status === 'eidas_in_progress') {
      return { label: 'Phase: eIDAS', classes: 'text-purple-800 bg-purple-100 border-purple-200' };
    }
    if (phase === 'dual_key' || status === 'dual_key_in_progress' || status === 'in_progress') {
      return { label: 'Phase: Dual-Key', classes: 'text-indigo-800 bg-indigo-100 border-indigo-200' };
    }
    return { label: 'Phase: N/A', classes: 'text-slate-500 bg-slate-100 border-slate-200' };
  };

  return (
    <DualKeyResultProvider>
      <div className="max-w-6xl mx-auto p-6 font-sans">
      <header className="mb-6 border-b pb-4">
        <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">
              BILANX DK-SVS — Frontend Sandbox
            </h1>
            <p className="text-slate-500 mt-1">
              Isolated environment for stress testing and validation of the Sovereign Dual-Key Handshake.
            </p>
          </div>
          <div className="flex items-center gap-2.5 flex-shrink-0">
            {onSwitchToRetailPos && (
              <button
                id="btn-stress-to-retail-pos"
                onClick={onSwitchToRetailPos}
                className="px-3.5 py-1.5 text-sm font-bold bg-[#0B3B60] hover:bg-[#062844] text-white rounded-md transition-all shadow-xs flex items-center gap-2 cursor-pointer border border-[#0B3B60]"
                title="Switch to Retail POS dashboard"
              >
                <Terminal size={15} />
                <span>Switch to Retail POS</span>
                <ArrowRight size={14} className="opacity-70" />
              </button>
            )}
            <button
              onClick={() => setShowDocumentation(!showDocumentation)}
              className="px-3 py-1.5 text-sm font-medium border border-slate-300 rounded text-slate-700 hover:bg-slate-50 transition-colors"
            >
              {showDocumentation ? 'Hide Documentation' : 'Show Documentation'}
            </button>
          </div>
        </div>
        
        {/* Tab Navigation */}
        <SandboxTabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
      </header>

      {/* Sandbox Documentation Section */}
      {activeTab === 'batch' && (
        <SandboxDocumentation showDocumentation={showDocumentation} />
      )}

      {/* Batch Stress Test Tab Content */}
      {activeTab === 'batch' && (
        <div>
          {/* Live Stats Overview */}
          <SandboxStats stats={stats} />

          {/* Controls */}
          <div className="flex items-center gap-4 mb-8 p-4 bg-white border rounded-lg shadow-sm">
            {/* Using a native form with the useActionState handler passed directly to action */}
            <form action={handleRunStressTest} className="flex gap-4 items-center">
              <StressTestButton count={50} />
              <StressTestButton count={100} />
              <StressTestButton count={200} />
            </form>
            <div className="w-px h-8 bg-gray-200 mx-2"></div>
            <button 
              onClick={handleReset}
              className="px-4 py-2 bg-slate-100 text-slate-700 font-medium rounded hover:bg-slate-200 transition-colors"
            >
              Reset Dataset
            </button>
          </div>

          {/* Recently Processed Items */}
          <RecentlyProcessedItems 
            items={items}
            lastBatchIds={lastBatchIds}
            pendingIds={pendingIds}
            getStatusColor={getStatusColor}
            getStatusLabel={getStatusLabel}
            getPhaseInfo={getPhaseInfo}
          />

          <LiveItemFeed 
            displayItems={displayItems}
            currentPage={currentPage}
            totalPages={totalPages}
            goToPage={goToPage}
            pendingIds={pendingIds}
            validateItem={validateItem}
            getPhaseInfo={getPhaseInfo}
            getStatusColor={getStatusColor}
            getStatusLabel={getStatusLabel}
          />
        </div>
      )}

      {/* Validation Lab Tab Content */}
      {activeTab === 'validation' && (
        <div>
          <SandboxCryptoComparison />
        </div>
      )}

      {/* Sovereign Technical Position Paper Tab Content */}
      {activeTab === 'dossier' && (
        <div>
          <SandboxDossier />
        </div>
      )}

    </div>
    </DualKeyResultProvider>
  );
}
