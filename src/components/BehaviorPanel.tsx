import React from 'react';
import { motion } from 'motion/react';
import { UserX } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { apiClient } from '../lib/apiClient';

const demoBehavior = {
  anomalies: [
    { user: 'demo-admin', action: 'IAM policy update', score: 81, time: new Date().toISOString() },
    { user: 'demo-analyst', action: 'Security group change', score: 66, time: new Date().toISOString() },
  ],
};

export function BehaviorPanel({ itemVariants }: any) {
  const { data, loading, error, warning, retry } = useApi<{ anomalies: Array<{ user: string; action: string; score: number; time: string }> }>(
    () => apiClient.get('/api/dashboard/behavior'),
    [],
    {
      fallbackData: demoBehavior,
      fallbackWarning: 'Using demo behavior feed while backend is unreachable.',
    }
  );
  const anomalies = data?.anomalies || [];

  return (
    <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl h-full">
      <h3 className="text-sm font-medium text-slate-400 mb-6 flex items-center gap-2">
        <UserX className="w-4 h-4 text-purple-500" /> User Behavior Anomalies
      </h3>

      {warning && <div className="mb-4 rounded-lg border border-amber-500/25 bg-amber-500/10 text-amber-300 px-3 py-2 text-xs">{warning}</div>}
      
      {loading && <div className="h-44 shimmer-skeleton rounded-xl" />}

      {!loading && error && (
        <div className="text-center py-8">
          <p className="text-rose-300 text-sm mb-3">Failed to load behavior anomalies.</p>
          <button className="px-3 py-1.5 rounded-lg border border-rose-500/30 text-rose-300" onClick={() => void retry()}>Retry</button>
        </div>
      )}

      {!loading && !error && anomalies.length === 0 && (
        <div className="text-center py-8 text-slate-500 text-sm">No recent behavior anomalies.</div>
      )}

      {!loading && !error && anomalies.length > 0 && <div className="space-y-4">
        {anomalies.map((anom, i) => (
          <div key={i} className="p-4 bg-white/5 rounded-xl border border-white/5 hover:bg-white/10 transition-colors shadow-lg">
            <div className="flex justify-between items-start mb-2">
              <span className="text-sm font-medium text-slate-200">{anom.user}</span>
              <span className={`text-xs px-2 py-1 rounded font-mono ${anom.score > 80 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/20' : 'bg-amber-500/20 text-amber-400 border border-amber-500/20'}`}>
                Score: {anom.score}
              </span>
            </div>
            <div className="flex justify-between items-end">
              <span className="text-xs text-slate-400">{anom.action}</span>
              <span className="text-[10px] text-slate-500 font-mono">{anom.time ? new Date(anom.time).toLocaleTimeString() : '--:--'}</span>
            </div>
          </div>
        ))}
      </div>}
    </motion.div>
  );
}
