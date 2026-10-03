import { FC } from 'react';

export type TabType = 'batch' | 'validation' | 'dossier';

interface SandboxTabNavigationProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
}

export const SandboxTabNavigation: FC<SandboxTabNavigationProps> = ({ activeTab, onTabChange }) => {
  return (
    <div className="flex items-center gap-6 mt-6 border-b border-slate-200">
      <button
        type="button"
        onClick={() => onTabChange('batch')}
        className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
          activeTab === 'batch' 
            ? 'border-blue-600 text-blue-600' 
            : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
        }`}
      >
        Batch Stress Test
      </button>
      <button
        type="button"
        onClick={() => onTabChange('validation')}
        className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
          activeTab === 'validation' 
            ? 'border-blue-600 text-blue-600' 
            : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
        }`}
      >
        Validation Lab
      </button>
      <button
        type="button"
        onClick={() => onTabChange('dossier')}
        className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
          activeTab === 'dossier' 
            ? 'border-blue-600 text-blue-600' 
            : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
        }`}
      >
        Sovereign Technical Position Paper
      </button>
    </div>
  );
};
