import React, { useEffect, useState } from 'react';
import { ShieldAlert, CheckCircle, Clock, AlertTriangle, Shield, RefreshCw, ShieldCheck, ChevronDown, ChevronUp } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './Layout';
import { apiClient } from '../lib/apiClient';

interface Alert {
  id: number;
  resource: string;
  type: string;
  severity: string;
  riskScore: number;
  status: string;
  timestamp: string;
  explanation?: string;
  remediation?: string;
}

type Toast = { type: 'success' | 'error' | 'warning'; message: string } | null;

export function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null);
  const [toast, setToast] = useState<Toast>(null);

  const demoAlerts: Alert[] = [
    {
      id: 9001,
      resource: 's3://demo-public-bucket',
      type: 'Public access policy detected',
      severity: 'HIGH',
      riskScore: 78,
      status: 'Open',
      timestamp: new Date().toISOString(),
      explanation: 'Demo mode: backend is currently unreachable.',
      remediation: 'Restrict policy to least privilege and block public ACLs.',
    },
  ];

  useEffect(() => {
    void fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    setWarning(null);
    try {
      const data = await apiClient.get<Alert[]>('/api/alerts');
      setAlerts(Array.isArray(data) ? data : []);
    } catch (err) {
      setAlerts(demoAlerts);
      setWarning('Backend unavailable. Showing demo threat feed.');
    } finally {
      setLoading(false);
    }
  };

  const handleRemediate = (id: number) => {
    void apiClient.post<{ success: boolean }>(`/api/alerts/${id}/remediate`)
      .then((data) => {
        if (data.success) {
          setToast({ type: 'success', message: 'Remediation queued successfully.' });
          void fetchAlerts();
        }
      })
      .catch(() => {
        setError('Remediation request failed. Please retry.');
        setToast({ type: 'error', message: 'Remediation request failed.' });
      });
  };

  useEffect(() => {
    if (!toast) {
      return;
    }
    const timer = window.setTimeout(() => setToast(null), 2200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'high': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'medium': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return <AlertTriangle className="w-4 h-4 text-rose-400" />;
      case 'remediated': return <CheckCircle className="w-4 h-4 text-emerald-400" />;
      case 'pending approval': return <Clock className="w-4 h-4 text-amber-400" />;
      default: return <Shield className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-light text-white">Active Threats</h2>
        <button 
          onClick={fetchAlerts}
          className="flex items-center gap-2 px-4 py-2 bg-[#111] border border-white/10 rounded-lg text-sm font-medium text-slate-300 hover:bg-white/5 transition-colors"
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {warning && (
        <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 text-amber-300 px-4 py-2 text-xs">
          {warning}
        </div>
      )}

      <div className="bg-[#111] rounded-2xl border border-white/5 overflow-hidden ds-card">
        {loading && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-16 text-center"
          >
            <RefreshCw className="w-10 h-10 mx-auto text-slate-500 animate-spin mb-4" />
            <p className="text-slate-300 font-medium">Loading threat intelligence...</p>
            <p className="text-slate-500 text-sm mt-1">Syncing latest misconfiguration events</p>
          </motion.div>
        )}

        {!loading && error && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-16 text-center"
          >
            <AlertTriangle className="w-10 h-10 mx-auto text-rose-400 mb-4" />
            <p className="text-rose-300 font-medium">{error}</p>
            <button
              onClick={() => void fetchAlerts()}
              className="mt-5 px-4 py-2 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-lg hover:bg-rose-500/20 transition-colors"
            >
              Retry
            </button>
          </motion.div>
        )}

        {!loading && !error && alerts.length === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-16 text-center text-slate-500"
          >
            <ShieldCheck className="w-12 h-12 mx-auto text-emerald-500/50 mb-4" />
            <p className="text-lg font-medium text-slate-300">All Clear</p>
            <p className="text-sm mt-1">No active misconfigurations detected.</p>
          </motion.div>
        )}

        {!loading && !error && alerts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-black/20 border-b border-white/5 text-xs uppercase tracking-wider text-slate-500 font-mono">
                <th className="p-5 font-medium w-10"></th>
                <th className="p-5 font-medium">Resource</th>
                <th className="p-5 font-medium">Misconfiguration Type</th>
                <th className="p-5 font-medium">Severity</th>
                <th className="p-5 font-medium">Risk Score</th>
                <th className="p-5 font-medium">Status</th>
                <th className="p-5 font-medium">Detected</th>
                <th className="p-5 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {alerts.map((alert, idx) => (
                <React.Fragment key={alert.id}>
                  <motion.tr 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={cn(
                      "hover:bg-white/[0.02] transition-colors group cursor-pointer",
                      expandedAlert === alert.id && "bg-white/[0.02]"
                    )}
                    onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
                  >
                    <td className="p-5 text-slate-500">
                      {expandedAlert === alert.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </td>
                    <td className="p-5 font-mono text-sm text-slate-300">{alert.resource}</td>
                    <td className="p-5 text-sm text-slate-300">{alert.type}</td>
                    <td className="p-5">
                      <span className={cn("px-2.5 py-1 rounded-full text-xs font-medium border", getSeverityColor(alert.severity))}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="p-5">
                      <div className="flex items-center gap-3">
                        <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                          <div 
                            className={cn("h-full rounded-full", alert.riskScore > 90 ? "bg-rose-500" : alert.riskScore > 70 ? "bg-orange-500" : "bg-amber-500")}
                            style={{ width: `${alert.riskScore}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-slate-400">{alert.riskScore}</span>
                      </div>
                    </td>
                    <td className="p-5">
                      <div className="flex items-center gap-2 text-sm text-slate-400">
                        {getStatusIcon(alert.status)}
                        <span className="capitalize">{alert.status}</span>
                      </div>
                    </td>
                    <td className="p-5 text-sm text-slate-500 font-mono">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="p-5 text-right" onClick={(e) => e.stopPropagation()}>
                      {alert.status === 'Open' ? (
                        <button 
                          onClick={() => handleRemediate(alert.id)}
                          className="px-4 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 text-emerald-400 text-xs font-medium rounded-lg transition-colors"
                        >
                          Auto-Remediate
                        </button>
                      ) : alert.status === 'Pending Approval' ? (
                        <button className="px-4 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-white text-xs font-medium rounded-lg transition-colors">
                          Review
                        </button>
                      ) : (
                        <span className="text-xs font-medium text-slate-500 px-4 py-1.5">Resolved</span>
                      )}
                    </td>
                  </motion.tr>
                  <AnimatePresence>
                    {expandedAlert === alert.id && (
                      <motion.tr
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-black/20"
                      >
                        <td colSpan={8} className="p-0">
                          <div className="p-6 border-l-2 border-rose-500/50 ml-5 my-4 bg-[#111] rounded-r-xl">
                            <h4 className="text-sm font-medium text-white mb-2">Vulnerability Details</h4>
                            <p className="text-sm text-slate-400 mb-4">{alert.explanation || "This resource violates security policies."}</p>
                            
                            <h4 className="text-sm font-medium text-white mb-2">Remediation Steps</h4>
                            <p className="text-sm text-slate-400">{alert.remediation || "Review the configuration and apply least privilege."}</p>
                          </div>
                        </td>
                      </motion.tr>
                    )}
                  </AnimatePresence>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </div>

      {toast && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className={cn(
            'fixed bottom-6 right-6 z-50 text-sm px-4 py-2 rounded-lg border backdrop-blur-lg',
            toast.type === 'success' && 'bg-emerald-500/15 border-emerald-500/30 text-emerald-200',
            toast.type === 'error' && 'bg-rose-500/15 border-rose-500/30 text-rose-200',
            toast.type === 'warning' && 'bg-amber-500/15 border-amber-500/30 text-amber-200'
          )}
        >
          {toast.message}
        </motion.div>
      )}
    </div>
  );
}
