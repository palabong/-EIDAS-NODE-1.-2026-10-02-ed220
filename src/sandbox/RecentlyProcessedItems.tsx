import { FC } from 'react';
import { BilanxMockItem } from './mocks/bilanxMockData.mock';

interface RecentlyProcessedItemsProps {
  items: BilanxMockItem[];
  lastBatchIds: Set<string>;
  pendingIds: Set<string>;
  getStatusColor: (status: string) => string;
  getStatusLabel: (status: string) => string;
  getPhaseInfo: (status: string, phase?: string) => { label: string; classes: string };
}

export const RecentlyProcessedItems: FC<RecentlyProcessedItemsProps> = ({
  items,
  lastBatchIds,
  pendingIds,
  getStatusColor,
  getStatusLabel,
  getPhaseInfo,
}) => {
  if (lastBatchIds.size === 0) return null;

  return (
    <section className="mb-8 border rounded-lg bg-white overflow-hidden shadow-sm border-blue-200">
      <div className="bg-blue-50 px-4 py-3 border-b border-blue-200 flex flex-col sm:flex-row justify-between items-center gap-3">
        <h2 className="font-semibold text-blue-800">Recently Processed Items (Last Batch)</h2>
        <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded">
          {lastBatchIds.size} items
        </span>
      </div>
      
      <div className="divide-y max-h-[300px] overflow-y-auto">
        {items
          .filter(item => lastBatchIds.has(item.id))
          .slice(0, 30) // limit to max 30 for display
          .map(item => {
            const isPending = pendingIds.has(item.id);
            const isActionable = item.validationStatus === 'pending' || item.validationStatus === 'failed';
            
            return (
              <div key={item.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between hover:bg-blue-50/50 transition-colors gap-4">
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
              </div>
            );
          })}
      </div>
      {lastBatchIds.size > 30 && (
        <div className="bg-slate-50 px-4 py-2 text-center text-sm text-slate-500 border-t border-blue-100">
          Showing first 30 of {lastBatchIds.size} processed items. See Live Item Feed for all.
        </div>
      )}
    </section>
  );
};
