import { FC } from 'react';
import { BilanxMockItem } from './mocks/bilanxMockData.mock';

interface LiveItemFeedProps {
  displayItems: BilanxMockItem[];
  currentPage: number;
  totalPages: number;
  goToPage: (page: number) => void;
  pendingIds: Set<string>;
  validateItem: (id: string) => void;
  getPhaseInfo: (status: string, phase?: string) => { label: string; classes: string };
  getStatusColor: (status: string) => string;
  getStatusLabel: (status: string) => string;
}

export const LiveItemFeed: FC<LiveItemFeedProps> = ({
  displayItems,
  currentPage,
  totalPages,
  goToPage,
  pendingIds,
  validateItem,
  getPhaseInfo,
  getStatusColor,
  getStatusLabel,
}) => {
  return (
    <section className="border rounded-lg bg-white overflow-hidden shadow-sm">
      <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex flex-col sm:flex-row justify-between items-center gap-3">
        <div className="flex items-center gap-2">
          <h2 className="font-semibold text-slate-700">Live Item Feed</h2>
          <span className="text-xs text-slate-500 bg-slate-200 px-2 py-1 rounded">Page {currentPage} of {totalPages}</span>
        </div>
        
        {/* Pagination Controls */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => goToPage(1)}
            disabled={currentPage === 1}
            className="px-2 py-1 text-sm border rounded text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            First
          </button>
          <button
            onClick={() => goToPage(currentPage - 1)}
            disabled={currentPage === 1}
            className="px-2 py-1 text-sm border rounded text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Previous
          </button>
          <span className="px-3 text-sm font-medium text-slate-600 border-x border-slate-200">
            {currentPage} / {totalPages}
          </span>
          <button
            onClick={() => goToPage(currentPage + 1)}
            disabled={currentPage === totalPages}
            className="px-2 py-1 text-sm border rounded text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
          <button
            onClick={() => goToPage(totalPages)}
            disabled={currentPage === totalPages}
            className="px-2 py-1 text-sm border rounded text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Last
          </button>
        </div>
      </div>
      
      <div className="divide-y max-h-[500px] overflow-y-auto">
        {displayItems.map((item) => {
          const isPending = pendingIds.has(item.id);
          const isActionable = item.validationStatus === 'pending' || item.validationStatus === 'failed';
          
          return (
            <div key={item.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between hover:bg-slate-50 transition-colors gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-medium text-slate-900">{item.nome}</span>
                  
                  {/* Phase Indicator */}
                  {item.validationStatus !== 'pending' && (
                    <span className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded border uppercase ${getPhaseInfo(item.validationStatus, item.currentPhase).classes}`}>
                      {getPhaseInfo(item.validationStatus, item.currentPhase).label}
                    </span>
                  )}

                  {/* Status Badge */}
                  <span className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded border uppercase ${getStatusColor(item.validationStatus)}`}>
                    {getStatusLabel(item.validationStatus)}
                  </span>
                </div>
                
                {item.eidasDetails && (
                  <div className="text-xs mt-1 text-slate-500">
                    {item.eidasDetails.errorMessage && (
                      <span className="text-red-500 block font-medium">eIDAS Error: {item.eidasDetails.errorMessage} ({item.eidasDetails.errorCode})</span>
                    )}
                    {item.eidasDetails.attributesDisclosed && item.eidasDetails.attributesDisclosed.length > 0 && (
                      <span className="text-green-600 block font-medium flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        eIDAS Minimal Disclosure: {item.eidasDetails.attributesDisclosed.join(', ')}
                      </span>
                    )}
                  </div>
                )}
                
                <div className="text-sm text-slate-500 font-mono flex items-center gap-4 mt-1">
                  <span>{item.categoria}</span>
                  <span className="flex items-center gap-1">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    {item.simulatedLatencyMs}ms
                  </span>
                  <span className="text-slate-400">{item.id}</span>
                </div>
              </div>
              
              <button
                onClick={() => validateItem(item.id)}
                disabled={!isActionable || isPending}
                className={`
                  px-5 py-2 text-sm font-medium border rounded transition-colors
                  ${isActionable && !isPending 
                    ? 'border-gray-300 text-gray-700 hover:bg-gray-100' 
                    : 'border-transparent bg-gray-100 text-gray-400 cursor-not-allowed'}
                `}
              >
                {isPending ? 'Validating...' : 'Validate'}
              </button>
            </div>
          );
        })}
      </div>
    </section>
  );
};
