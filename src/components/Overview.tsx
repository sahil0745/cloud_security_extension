import React, { useEffect, useState, Suspense } from 'react';
import { ShieldAlert, CheckCircle, Activity, ShieldCheck, Loader2 } from 'lucide-react';
import { motion } from 'motion/react';
import { apiClient } from '../lib/apiClient';

// Lazy load heavy components for performance
const ChartsPanel = React.lazy(() => import('./ChartsPanel').then(m => ({ default: m.ChartsPanel })));
const AttackPathGraph = React.lazy(() => import('./AttackPathGraph').then(m => ({ default: m.AttackPathGraph })));
const BehaviorPanel = React.lazy(() => import('./BehaviorPanel').then(m => ({ default: m.BehaviorPanel })));
const VulnerabilityList = React.lazy(() => import('./VulnerabilityList').then(m => ({ default: m.VulnerabilityList })));

const SkeletonCard = () => (
  <div className="ds-card p-6 rounded-2xl">
    <div className="h-4 shimmer-skeleton w-1/3 mb-4"></div>
    <div className="h-10 shimmer-skeleton w-1/2 mb-3"></div>
    <div className="h-4 shimmer-skeleton w-2/3"></div>
  </div>
);

export function Overview() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [posture, setPosture] = useState({
    score: 0,
    trend: "+0%",
    scannedResources: 0,
    openVulnerabilities: 0,
    remediatedToday: 0,
    systemStatus: 'Stable',
    lastScanTime: null as string | null,
  });

  const fetchRealTimeData = async () => {
    try {
      setError(null);
      setWarning(null);
      const data = await apiClient.get<typeof posture>('/api/dashboard/overview');
      setPosture(data);
    } catch {
      setPosture({
        score: 61,
        trend: '+2%',
        scannedResources: 480,
        openVulnerabilities: 6,
        remediatedToday: 2,
        systemStatus: 'Monitoring',
        lastScanTime: new Date().toISOString(),
      });
      setWarning('Backend unavailable. Showing demo posture snapshot.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchRealTimeData();
    // Real-time polling
    const interval = setInterval(() => {
      void fetchRealTimeData();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.1 } } };
  const item = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } } };
  const lastScanLabel = posture.lastScanTime ? new Date(posture.lastScanTime).toLocaleString() : 'Never';

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
           <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
        </div>
        <div className="h-64 ds-card rounded-2xl flex items-center justify-center">
            <Loader2 className="w-8 h-8 text-white/20 animate-spin" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div className="h-64 bg-[#111] rounded-2xl border border-rose-500/20 flex flex-col items-center justify-center gap-3 anim-fade-in">
          <div className="text-rose-300">{error}</div>
          <button onClick={() => { setLoading(true); void fetchRealTimeData(); }} className="px-4 py-2 rounded-lg border border-rose-500/30 text-rose-300 hover:bg-rose-500/10">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <motion.div variants={container} initial="hidden" animate="show" className="space-y-6">
      {warning && (
        <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 text-amber-300 px-4 py-2 text-xs">
          {warning}
        </div>
      )}
      
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-xl md:text-2xl text-white tracking-tight">Security Posture Overview</h2>
          <p className="text-slate-400 text-sm mt-1">Live risk telemetry, anomaly intelligence, and remediation readiness.</p>
        </div>
      </div>

      {/* 1. OVERVIEW PANEL (Top KPIs) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div variants={item} className="bg-[#111] p-6 rounded-2xl border border-white/5 relative overflow-hidden group shadow-2xl backdrop-blur-xl">
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="flex items-center justify-between mb-4 relative z-10">
            <h3 className="text-slate-400 font-medium text-sm">Risk Score</h3>
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-4xl font-light text-white relative z-10">{posture.score}<span className="text-xl text-slate-500">/100</span></div>
          <div className="text-sm text-emerald-400 mt-3 font-mono relative z-10 tracking-widest bg-emerald-500/10 inline-block px-2 rounded-full">{posture.trend} <span className="text-slate-500">this week</span></div>
        </motion.div>

        <motion.div variants={item} className="bg-[#111] p-6 rounded-2xl border border-white/5 relative overflow-hidden group shadow-2xl backdrop-blur-xl">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="flex items-center justify-between mb-4 relative z-10">
            <h3 className="text-slate-400 font-medium text-sm">System Status</h3>
            <Activity className="w-5 h-5 text-blue-400" />
          </div>
          <div className="text-3xl font-light text-white relative z-10 mt-2 flex items-center gap-3">
             <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-blue-500"></span>
            </span> {posture.systemStatus}
          </div>
          <div className="text-xs text-slate-500 mt-3 font-mono relative z-10 flex items-center gap-2">
             {posture.scannedResources} assets secured globally
          </div>
        </motion.div>

        <motion.div variants={item} className="bg-[#111] p-6 rounded-2xl border border-white/5 relative overflow-hidden group shadow-2xl backdrop-blur-xl">
          <div className="absolute inset-0 bg-gradient-to-br from-rose-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="flex items-center justify-between mb-4 relative z-10">
            <h3 className="text-slate-400 font-medium text-sm">Total Vulnerabilities</h3>
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
          <div className="text-4xl font-light text-white relative z-10">{posture.openVulnerabilities}</div>
          <div className="text-sm text-rose-400 mt-3 font-mono relative z-10">{posture.openVulnerabilities > 0 ? 'Action Required' : 'No Active Issues'}</div>
        </motion.div>

        <motion.div variants={item} className="bg-[#111] p-6 rounded-2xl border border-white/5 relative overflow-hidden group shadow-2xl backdrop-blur-xl">
          <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="flex items-center justify-between mb-4 relative z-10">
            <h3 className="text-slate-400 font-medium text-sm">Last Scan Time</h3>
            <CheckCircle className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-mono font-light text-white relative z-10 mt-4">{lastScanLabel}</div>
          <div className="text-[10px] uppercase tracking-widest text-indigo-400 mt-3 font-mono relative z-10">{posture.remediatedToday} Auto-Fixes Applied</div>
        </motion.div>
      </div>

      <Suspense fallback={<div className="h-[250px] bg-[#111] animate-pulse rounded-2xl border border-white/5" />}>
        {/* 2. CHARTS PANEL (Attacks, Trends, Heatmap) */}
        <ChartsPanel itemVariants={item} />
      </Suspense>

      <Suspense fallback={<div className="h-[300px] bg-[#111] animate-pulse rounded-2xl border border-white/5" />}>
        {/* 3. EXPLOITATION PATH GRAPH */}
        <AttackPathGraph itemVariants={item} />
      </Suspense>

      {/* 4. BEHAVIOR & VULNERABILITY LIST */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6 pb-20">
        <div className="md:col-span-2">
          <Suspense fallback={<div className="h-[300px] bg-[#111] animate-pulse rounded-2xl border border-white/5" />}>
            <VulnerabilityList itemVariants={item} />
          </Suspense>
        </div>
        <div className="md:col-span-1">
          <Suspense fallback={<div className="h-[300px] bg-[#111] animate-pulse rounded-2xl border border-white/5" />}>
            <BehaviorPanel itemVariants={item} />
          </Suspense>
        </div>
      </div>
      
    </motion.div>
  );
}
