import { FC } from 'react';

export interface SandboxStatsProps {
  stats: {
    total: number;
    pending: number;
    validated: number;
    failed: number;
    avgLatency: number;
  };
}

export const SandboxStats: FC<SandboxStatsProps> = ({ stats }) => {
  return (
    <section className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
      <div className="p-4 bg-slate-50 rounded-lg border border-slate-100">
        <div className="text-sm text-slate-500 font-medium">Total Items</div>
        <div className="text-3xl font-semibold text-slate-900">{stats.total}</div>
      </div>
      <div className="p-4 bg-blue-50 rounded-lg border border-blue-100">
        <div className="text-sm text-blue-600 font-medium">Pending</div>
        <div className="text-3xl font-semibold text-blue-700">{stats.pending}</div>
      </div>
      <div className="p-4 bg-green-50 rounded-lg border border-green-100">
        <div className="text-sm text-green-600 font-medium">Validated</div>
        <div className="text-3xl font-semibold text-green-700">{stats.validated}</div>
      </div>
      <div className="p-4 bg-red-50 rounded-lg border border-red-100">
        <div className="text-sm text-red-600 font-medium">Failed</div>
        <div className="text-3xl font-semibold text-red-700">{stats.failed}</div>
      </div>
      <div className="p-4 bg-purple-50 rounded-lg border border-purple-100">
        <div className="text-sm text-purple-600 font-medium">Avg Latency</div>
        <div className="text-3xl font-semibold text-purple-700">{stats.avgLatency}ms</div>
      </div>
    </section>
  );
};
