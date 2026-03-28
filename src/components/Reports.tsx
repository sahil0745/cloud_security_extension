import React, { useState } from 'react';
import { motion } from 'motion/react';
import { FileText, Download, Check, X, ShieldAlert, Clock, FileDown } from 'lucide-react';
import { cn } from './Layout';
import { apiClient, ApiError } from '../lib/apiClient';

type ToastState = {
  type: 'success' | 'error';
  message: string;
} | null;

type ReportScope = 'global' | 'tenant' | 'user';

type PreviewState = {
  format: 'csv' | 'pdf';
  data: any;
} | null;

type ReportsProps = {
  role?: 'ADMIN' | 'USER';
};

export function Reports({ role = 'USER' }: ReportsProps) {
  const [approvals, setApprovals] = useState([
    { id: 1, action: 'Delete Resource', resource: 'rds-prod-db', requester: 'john.doe@company.com', time: '10 mins ago', status: 'pending' },
    { id: 2, action: 'Modify IAM Policy', resource: 'AdminAccessRole', requester: 'jane.smith@company.com', time: '1 hour ago', status: 'pending' },
    { id: 3, action: 'Open Firewall Port', resource: 'sg-web-tier', requester: 'dev-team', time: '2 hours ago', status: 'approved' },
  ]);

  const handleApproval = (id: number, approved: boolean) => {
    setApprovals(approvals.map(app => app.id === id ? { ...app, status: approved ? 'approved' : 'rejected' } : app));
  };

  const [exporting, setExporting] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastState>(null);
  const [severity, setSeverity] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [complianceMode, setComplianceMode] = useState(false);
  const [complianceStandard, setComplianceStandard] = useState<'SOC2' | 'ISO'>('SOC2');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [scheduleFrequency, setScheduleFrequency] = useState<'daily' | 'weekly'>('weekly');
  const [working, setWorking] = useState<string | null>(null);
  const [scope, setScope] = useState<ReportScope>(role === 'ADMIN' ? 'global' : 'user');
  const [tenantId, setTenantId] = useState('');
  const [previewState, setPreviewState] = useState<PreviewState>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const buildReportQuery = () => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (startTime) params.set('start_time', new Date(startTime).toISOString());
    if (endTime) params.set('end_time', new Date(endTime).toISOString());
    if (complianceMode) {
      params.set('compliance_mode', 'true');
      params.set('compliance_standard', complianceStandard);
    }
    params.set('scope', scope);
    if (scope === 'tenant' && tenantId.trim()) {
      params.set('tenant_id', tenantId.trim());
    }
    return params.toString();
  };

  const runExportDownload = async (format: 'csv' | 'pdf') => {
    setExporting(format);
    try {
      const fileName = `cloudsec-report-${new Date().toISOString().slice(0, 10)}.${format}`;
      const query = buildReportQuery();
      const signedPath = query
        ? `/api/export?format=${format}&use_signed_url=true&${query}`
        : `/api/export?format=${format}&use_signed_url=true`;
      const directPath = query
        ? `/api/export?format=${format}&${query}`
        : `/api/export?format=${format}`;

      try {
        const signed = await apiClient.get<{ download_url?: string }>(signedPath);
        if (!signed?.download_url) {
          throw new Error('signed url missing');
        }
        await apiClient.download(signed.download_url, fileName);
      } catch {
        // Fallback to direct streamed export if signed artifact flow is unavailable.
        await apiClient.download(directPath, fileName);
      }

      setToast({ type: 'success', message: `${format.toUpperCase()} report downloaded successfully.` });
    } catch (e: any) {
      const detail = e instanceof ApiError && typeof e.payload === 'object' && e.payload && 'detail' in (e.payload as any)
        ? String((e.payload as any).detail)
        : null;
      setToast({ type: 'error', message: detail || `Failed to download ${format.toUpperCase()} report.` });
    }
    setExporting(null);
    window.setTimeout(() => setToast(null), 2800);
  };

  const handleOpenPreview = async (format: 'csv' | 'pdf') => {
    setPreviewLoading(true);
    try {
      const query = buildReportQuery();
      const path = query ? `/api/generate-report?${query}` : '/api/generate-report';
      const data = await apiClient.get<any>(path);
      setPreviewState({ format, data });
    } catch {
      setToast({ type: 'error', message: 'Failed to load report preview.' });
      window.setTimeout(() => setToast(null), 2800);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleConfirmPreviewDownload = async () => {
    if (!previewState) return;
    const format = previewState.format;
    setPreviewState(null);
    await runExportDownload(format);
  };

  const handleSchedule = async () => {
    setWorking('schedule');
    try {
      await apiClient.post('/api/report-schedules', {
        frequency: scheduleFrequency,
        report_format: 'pdf',
        recipient_email: recipientEmail || null,
        severity: severity || null,
        compliance_mode: complianceMode,
        compliance_standard: complianceStandard,
        scope,
        tenant_id: scope === 'tenant' ? (tenantId.trim() || null) : null,
      });
      setToast({ type: 'success', message: `Scheduled ${scheduleFrequency} report successfully.` });
    } catch {
      setToast({ type: 'error', message: 'Failed to schedule report.' });
    } finally {
      setWorking(null);
      window.setTimeout(() => setToast(null), 2800);
    }
  };

  const handleSendEmail = async () => {
    if (!recipientEmail) {
      setToast({ type: 'error', message: 'Recipient email is required.' });
      window.setTimeout(() => setToast(null), 2800);
      return;
    }
    setWorking('email');
    try {
      await apiClient.post('/api/report-email', {
        recipient_email: recipientEmail,
        report_format: 'pdf',
        severity: severity || null,
        start_time: startTime ? new Date(startTime).toISOString() : null,
        end_time: endTime ? new Date(endTime).toISOString() : null,
        compliance_mode: complianceMode,
        compliance_standard: complianceStandard,
        scope,
        tenant_id: scope === 'tenant' ? (tenantId.trim() || null) : null,
      });
      setToast({ type: 'success', message: 'Report email queued successfully.' });
    } catch {
      setToast({ type: 'error', message: 'Failed to send report email.' });
    } finally {
      setWorking(null);
      window.setTimeout(() => setToast(null), 2800);
    }
  };

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Governance & Approvals */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-[#111] rounded-2xl border border-white/5 overflow-hidden flex flex-col">
          <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              <h3 className="text-lg font-medium text-white">Governance & Approvals</h3>
            </div>
            <span className="bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-medium px-2.5 py-1 rounded-full">
              {approvals.filter(a => a.status === 'pending').length} Pending
            </span>
          </div>
          <div className="p-0 flex-1 overflow-y-auto">
            <ul className="divide-y divide-white/5">
              {approvals.map((req) => (
                <li key={req.id} className="p-6 hover:bg-white/[0.02] transition-colors">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="text-sm font-medium text-slate-200">{req.action}</h4>
                      <p className="text-sm text-slate-500 mt-1">Resource: <code className="bg-white/5 px-1.5 py-0.5 rounded text-rose-400 font-mono text-xs">{req.resource}</code></p>
                      <div className="flex items-center gap-4 mt-3 text-xs text-slate-500 font-mono">
                        <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> {req.time}</span>
                        <span>By: {req.requester}</span>
                      </div>
                    </div>
                    {req.status === 'pending' ? (
                      <div className="flex gap-2">
                        <button 
                          onClick={() => handleApproval(req.id, true)}
                          className="p-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 rounded-lg transition-colors"
                          title="Approve"
                        >
                          <Check className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => handleApproval(req.id, false)}
                          className="p-2 bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 rounded-lg transition-colors"
                          title="Reject"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <span className={cn(
                        "text-xs font-medium px-2.5 py-1 rounded-full uppercase tracking-wider border",
                        req.status === 'approved' ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                      )}>
                        {req.status}
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </motion.div>

        {/* Reporting System */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-[#111] rounded-2xl border border-white/5 overflow-hidden flex flex-col">
          <div className="p-6 border-b border-white/5 flex items-center gap-3 bg-white/[0.02]">
            <FileText className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-medium text-white">Compliance & Reporting</h3>
          </div>
          <div className="p-6 space-y-6">
            <p className="text-sm text-slate-400">
              Generate comprehensive security reports including detected vulnerabilities, configuration drift history, remediation actions, and overall security posture.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4 rounded-xl border border-white/5 bg-white/[0.01]">
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              >
                <option value="">All severities</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
              <select
                value={complianceStandard}
                onChange={(e) => setComplianceStandard(e.target.value as 'SOC2' | 'ISO')}
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              >
                <option value="SOC2">SOC2</option>
                <option value="ISO">ISO</option>
              </select>
              <input
                type="datetime-local"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              />
              <input
                type="datetime-local"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              />
              <input
                type="email"
                value={recipientEmail}
                onChange={(e) => setRecipientEmail(e.target.value)}
                placeholder="admin@company.com"
                className="md:col-span-2 bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              />
              <select
                value={scope}
                onChange={(e) => setScope(e.target.value as ReportScope)}
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200"
              >
                {role === 'ADMIN' && <option value="global">Global Scope</option>}
                {role === 'ADMIN' && <option value="tenant">Tenant Scope</option>}
                <option value="user">My User Scope</option>
              </select>
              <input
                type="text"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={scope !== 'tenant'}
                placeholder="tenant-alpha"
                className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-200 disabled:opacity-50"
              />
              <label className="md:col-span-2 flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={complianceMode} onChange={(e) => setComplianceMode(e.target.checked)} />
                Compliance mode (SOC2 / ISO)
              </label>
            </div>
            
            <div className="space-y-4">
              <div className="p-5 border border-white/5 rounded-xl flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between hover:border-white/10 bg-white/[0.01] transition-colors">
                <div>
                  <h4 className="font-medium text-slate-200">Weekly Security Summary</h4>
                  <p className="text-xs text-slate-500 mt-1">Includes all alerts and auto-remediations.</p>
                </div>
                <div className="flex w-full flex-wrap gap-2 sm:w-auto sm:justify-end">
                  <button onClick={() => runExportDownload('csv')} disabled={exporting !== null || previewLoading} className="flex min-w-[132px] items-center justify-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-xs font-medium rounded-lg transition-colors disabled:opacity-50">
                    <FileDown className="w-3.5 h-3.5" /> {exporting === 'csv' ? 'Building...' : previewLoading ? 'Loading...' : 'Download CSV'}
                  </button>
                  <button onClick={() => runExportDownload('pdf')} disabled={exporting !== null || previewLoading} className="flex min-w-[132px] items-center justify-center gap-1.5 px-3 py-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 text-blue-400 text-xs font-medium rounded-lg transition-colors disabled:opacity-50">
                    <Download className="w-3.5 h-3.5" /> {exporting === 'pdf' ? 'Building...' : previewLoading ? 'Loading...' : 'Download PDF'}
                  </button>
                </div>
              </div>

              <div className="p-5 border border-white/5 rounded-xl flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between hover:border-white/10 bg-white/[0.01] transition-colors">
                <div>
                  <h4 className="font-medium text-slate-200">Compliance Audit Log</h4>
                  <p className="text-xs text-slate-500 mt-1">Full history of configuration changes.</p>
                  <span className="text-[10px] uppercase font-mono tracking-widest bg-emerald-500/10 text-emerald-400 px-2 rounded-full mt-2 inline-block border border-emerald-500/20">SOC2 Ready</span>
                </div>
                <div className="flex w-full flex-wrap gap-2 sm:w-auto sm:justify-end">
                  <button onClick={() => runExportDownload('csv')} disabled={exporting !== null || previewLoading} className="flex min-w-[132px] items-center justify-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 text-xs font-medium rounded-lg transition-colors disabled:opacity-50">
                    <FileDown className="w-3.5 h-3.5" /> {exporting === 'csv' ? 'Building...' : previewLoading ? 'Loading...' : 'Download CSV'}
                  </button>
                  <button onClick={() => runExportDownload('pdf')} disabled={exporting !== null || previewLoading} className="flex min-w-[132px] items-center justify-center gap-1.5 px-3 py-1.5 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 text-blue-400 text-xs font-medium rounded-lg transition-colors disabled:opacity-50">
                    <Download className="w-3.5 h-3.5" /> {exporting === 'pdf' ? 'Building...' : previewLoading ? 'Loading...' : 'Download PDF'}
                  </button>
                </div>
              </div>

              <div className="p-5 border border-white/5 rounded-xl hover:border-white/10 bg-white/[0.01] transition-colors space-y-3">
                <h4 className="font-medium text-slate-200">Automated Delivery</h4>
                <p className="text-xs text-slate-500">Schedule daily/weekly reports and send reports to admin email.</p>
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={scheduleFrequency}
                    onChange={(e) => setScheduleFrequency(e.target.value as 'daily' | 'weekly')}
                    className="bg-[#0c1424] border border-white/10 rounded-lg px-3 py-1.5 text-xs text-slate-200"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                  <button
                    onClick={handleSchedule}
                    disabled={working !== null}
                    className="px-3 py-1.5 rounded-lg text-xs border border-amber-500/20 text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 disabled:opacity-50"
                  >
                    {working === 'schedule' ? 'Scheduling...' : 'Schedule Report'}
                  </button>
                  <button
                    onClick={handleSendEmail}
                    disabled={working !== null}
                    className="px-3 py-1.5 rounded-lg text-xs border border-emerald-500/20 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-50"
                  >
                    {working === 'email' ? 'Sending...' : 'Email Report'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

      </div>

      {toast && (
        <motion.div
          initial={{ opacity: 0, y: 16, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 12, scale: 0.98 }}
          className={cn(
            'fixed bottom-6 right-6 px-4 py-3 rounded-xl border shadow-2xl backdrop-blur-xl z-50 text-sm font-medium',
            toast.type === 'success'
              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
          )}
        >
          {toast.message}
        </motion.div>
      )}

      {previewState && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            className="w-full max-w-2xl rounded-2xl border border-white/10 bg-[#0b111d] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
              <h4 className="text-base font-semibold text-slate-100">Report Preview ({previewState.format.toUpperCase()})</h4>
              <button onClick={() => setPreviewState(null)} className="rounded-md p-1 text-slate-400 hover:bg-white/10 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-4 px-5 py-4 text-sm text-slate-300">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                  <p className="text-xs text-slate-500">Risk Score</p>
                  <p className="mt-1 text-lg font-semibold text-amber-300">{previewState.data?.risk_overview?.score ?? 'n/a'}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                  <p className="text-xs text-slate-500">Risk Level</p>
                  <p className="mt-1 text-lg font-semibold text-rose-300">{previewState.data?.risk_overview?.level ?? 'n/a'}</p>
                </div>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                <p className="text-xs text-slate-500">AI Executive Summary</p>
                <p className="mt-1 line-clamp-4 text-slate-200">{previewState.data?.ai_summary || 'No AI summary available for this snapshot.'}</p>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                <p className="text-xs text-slate-500">Summary Counts</p>
                <p className="mt-1 text-slate-200">
                  Vulnerabilities: {previewState.data?.vulnerabilities?.length ?? 0} | Config Changes: {previewState.data?.config_changes?.length ?? 0} | Remediations: {previewState.data?.remediation_actions?.length ?? 0}
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-white/10 px-5 py-4">
              <button
                onClick={() => setPreviewState(null)}
                className="rounded-lg border border-white/15 px-3 py-1.5 text-xs text-slate-300 hover:bg-white/5"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmPreviewDownload}
                className="rounded-lg border border-blue-500/30 bg-blue-500/15 px-3 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-500/25"
              >
                Confirm & Download
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
}
