import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { BrainCircuit, Activity, ShieldAlert, Zap, Server, Database, Network } from 'lucide-react';
import { cn } from './Layout';
import { useApi } from '../hooks/useApi';
import { apiClient } from '../lib/apiClient';

const demoIntel = {
  modelConfidence: 91,
  inferenceLatencyMs: 15,
  anomaliesBlocked: 7,
  liveStream: [
    { time: '10:14:12', resource: 's3://demo-public', behaviorScore: 82, riskScore: 88, action: 'BLOCK' },
    { time: '10:16:05', resource: 'sg-demo-123', behaviorScore: 61, riskScore: 70, action: 'ALERT' },
  ],
};

export function AIThreatIntel() {
  const [isScanning, setIsScanning] = useState(true);
  const { data, loading, error, warning, retry } = useApi<{
    modelConfidence: number;
    inferenceLatencyMs: number;
    anomaliesBlocked: number;
    liveStream: Array<{ time: string; resource: string; behaviorScore: number; riskScore: number; action: string }>;
  }>(
    () => apiClient.get('/api/dashboard/ai-intel'),
    [],
    {
      fallbackData: demoIntel,
      fallbackWarning: 'Backend unavailable. Using demo AI telemetry stream.',
    }
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setIsScanning(prev => !prev);
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  const container = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.1 } }
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <motion.div variants={container} initial="hidden" animate="show" className="space-y-8">
      {warning && <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 text-amber-300 px-4 py-2 text-xs">{warning}</div>}
      {loading && <div className="h-32 bg-[#111] rounded-2xl border border-white/5 animate-pulse" />}
      {!loading && error && (
        <div className="bg-[#111] border border-rose-500/20 rounded-2xl p-6 text-center">
          <p className="text-rose-300 mb-3">Failed to load AI telemetry.</p>
          <button className="px-3 py-1.5 rounded-lg border border-rose-500/30 text-rose-300" onClick={() => void retry()}>Retry</button>
        </div>
      )}

      {!loading && !error && data && <>
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div variants={item} className="bg-[#111] border border-white/5 rounded-2xl p-6 flex items-center gap-6">
          <div className="w-14 h-14 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20">
            <BrainCircuit className="w-7 h-7 text-emerald-400" />
          </div>
          <div>
            <div className="text-slate-400 text-sm mb-1">Model Confidence</div>
            <div className="text-3xl font-light text-white">{data.modelConfidence}%</div>
          </div>
        </motion.div>
        <motion.div variants={item} className="bg-[#111] border border-white/5 rounded-2xl p-6 flex items-center gap-6">
          <div className="w-14 h-14 rounded-full bg-blue-500/10 flex items-center justify-center border border-blue-500/20">
            <Zap className="w-7 h-7 text-blue-400" />
          </div>
          <div>
            <div className="text-slate-400 text-sm mb-1">Inference Latency</div>
            <div className="text-3xl font-light text-white">{data.inferenceLatencyMs}<span className="text-lg text-slate-500 ml-1">ms</span></div>
          </div>
        </motion.div>
        <motion.div variants={item} className="bg-[#111] border border-white/5 rounded-2xl p-6 flex items-center gap-6">
          <div className="w-14 h-14 rounded-full bg-purple-500/10 flex items-center justify-center border border-purple-500/20">
            <Activity className="w-7 h-7 text-purple-400" />
          </div>
          <div>
            <div className="text-slate-400 text-sm mb-1">Active Threats (Blocked)</div>
            <div className="text-3xl font-light text-white">{data.anomaliesBlocked}</div>
          </div>
        </motion.div>
      </div>

      {/* Live Inference Feed */}
      <motion.div variants={item} className="bg-[#111] border border-white/5 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <Network className="w-5 h-5 text-emerald-400" />
            <h3 className="text-lg font-medium text-white">Live ML Inference Stream</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              {isScanning && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
            <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Analyzing</span>
          </div>
        </div>
        
        <div className="p-0">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/5 text-xs uppercase tracking-wider text-slate-500 font-mono bg-black/20">
                <th className="p-4 font-medium">Timestamp</th>
                <th className="p-4 font-medium">Resource</th>
                <th className="p-4 font-medium">Behavior Score</th>
                <th className="p-4 font-medium">Risk Score</th>
                <th className="p-4 font-medium">ML Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono text-sm">
              {data.liveStream.length === 0 && (
                <tr>
                  <td className="p-6 text-slate-500 text-center" colSpan={5}>No live inference events yet.</td>
                </tr>
              )}
              {data.liveStream.map((row, i) => {
                const color = row.riskScore >= 80 ? 'text-rose-400' : row.riskScore >= 45 ? 'text-amber-400' : 'text-slate-400';
                return (
                <motion.tr 
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.1 + 0.5 }}
                  className="hover:bg-white/[0.02] transition-colors"
                >
                  <td className="p-4 text-slate-500">{row.time}</td>
                  <td className="p-4 text-slate-300">{row.resource}</td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                        <div className={cn("h-full rounded-full", row.behaviorScore > 80 ? "bg-rose-500" : row.behaviorScore > 40 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${row.behaviorScore}%` }} />
                      </div>
                      <span className="text-slate-400 text-xs">{row.behaviorScore}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className={cn(row.riskScore >= 80 ? "text-rose-400" : row.riskScore >= 45 ? "text-amber-400" : "text-emerald-400")}>{row.riskScore}</span>
                  </td>
                  <td className={cn("p-4 font-bold", color)}>{row.action}</td>
                </motion.tr>
              )})}
            </tbody>
          </table>
        </div>
      </motion.div>
      </>}
    </motion.div>
  );
}
