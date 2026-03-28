import React, { useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Server, Database, CloudFog, AlertTriangle, RefreshCw, ShieldCheck } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { apiClient } from '../lib/apiClient';

type AttackPathNode = {
  id: string;
  label: string;
  type: string;
  severity: string;
  risk: number;
  x: number;
  y: number;
  description: string;
};

type AttackPathEdge = {
  id: string;
  from: string;
  to: string;
  risk: number;
  confidence: number;
  vector: string;
  recommendation: string;
  animated: boolean;
};

type AttackPathPayload = {
  status: 'simulated' | 'clear';
  summary: {
    activePaths: number;
    totalNodes: number;
    totalEdges: number;
    maxPathRisk: number;
  };
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  recommendations: string[];
};

export function AttackPathGraph({ itemVariants }: any) {
  const [activeNode, setActiveNode] = useState<string | null>(null);

  const { data, loading, error, warning, retry } = useApi<AttackPathPayload>(
    () => apiClient.get('/api/dashboard/attack-path'),
    [],
    {
      fallbackData: {
        status: 'simulated',
        summary: {
          activePaths: 2,
          totalNodes: 4,
          totalEdges: 4,
          maxPathRisk: 92,
        },
        nodes: [
          { id: 'internet', label: 'Public Internet', type: 'cloud', severity: 'LOW', risk: 0, x: 10, y: 50, description: 'Threat ingress origin.' },
          { id: 'pivot-1', label: 'Public bucket exposure', type: 'storage', severity: 'HIGH', risk: 78, x: 46, y: 24, description: 'HIGH on s3://demo-public' },
          { id: 'pivot-2', label: 'IAM wildcard role', type: 'identity', severity: 'CRITICAL', risk: 92, x: 46, y: 76, description: 'CRITICAL on arn:aws:iam::demo:role/admin' },
          { id: 'crown-db', label: 'Production Database', type: 'db', severity: 'CRITICAL', risk: 92, x: 84, y: 50, description: 'Crown-jewel target for lateral movement.' },
        ],
        edges: [
          { id: 'entry-1', from: 'internet', to: 'pivot-1', risk: 78, confidence: 0.82, vector: 'exposure_pivot', recommendation: 'Isolate entry vector and enforce least privilege immediately.', animated: true },
          { id: 'entry-2', from: 'internet', to: 'pivot-2', risk: 92, confidence: 0.93, vector: 'credential_pivot', recommendation: 'Isolate entry vector and enforce least privilege immediately.', animated: true },
          { id: 'target-1', from: 'pivot-1', to: 'crown-db', risk: 78, confidence: 0.82, vector: 'lateral_movement', recommendation: 'Enforce segmentation around crown-jewel assets.', animated: true },
          { id: 'target-2', from: 'pivot-2', to: 'crown-db', risk: 92, confidence: 0.93, vector: 'lateral_movement', recommendation: 'Enforce segmentation around crown-jewel assets.', animated: true },
        ],
        recommendations: [
          'Isolate entry vector and enforce least privilege immediately.',
          'Enforce segmentation around crown-jewel assets.',
        ],
      },
      fallbackWarning: 'Backend unavailable. Simulating attack path with demo threat graph.',
    }
  );

  const severityColor = (severity: string) => {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return '#f43f5e';
    if (s === 'HIGH') return '#f97316';
    if (s === 'MEDIUM') return '#fb923c';
    return '#64748b';
  };

  const graph = useMemo(() => {
    const payload = data;
    if (!payload) {
      return { nodes: [], edges: [], exploitable: false, summary: { activePaths: 0, maxPathRisk: 0 } };
    }

    return {
      nodes: (payload.nodes || []).map((n) => ({
        ...n,
        color: severityColor(n.severity),
      })),
      edges: (payload.edges || []).map((e) => ({
        ...e,
        color: severityColor((payload.nodes || []).find((n) => n.id === e.to)?.severity || 'LOW'),
      })),
      exploitable: (payload.summary?.activePaths || 0) > 0,
      summary: payload.summary,
      recommendations: payload.recommendations || [],
    };
  }, [data]);

  const edgePath = (from: { x: number; y: number }, to: { x: number; y: number }) => {
    const c1x = from.x + 18;
    const c2x = to.x - 18;
    return `M ${from.x}% ${from.y}% C ${c1x}% ${from.y}% ${c2x}% ${to.y}% ${to.x}% ${to.y}%`;
  };

  const nodeById = useMemo(() => {
    const m: Record<string, any> = {};
    graph.nodes.forEach((n) => {
      m[n.id] = n;
    });
    return m;
  }, [graph.nodes]);

  return (
    <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl relative overflow-hidden mt-6 ds-card">
      <div className="absolute inset-0 bg-gradient-to-r from-rose-500/5 to-transparent pointer-events-none" />
      <div className="flex items-center justify-between mb-6 relative z-10">
        <h3 className="text-sm font-medium text-slate-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-500" /> Exploitation Path Simulation
        </h3>
        <div className="flex items-center gap-2">
          {graph.summary && (
            <span className="text-[11px] text-slate-300 border border-white/10 rounded-full px-2 py-1 bg-white/5">
              Paths: {graph.summary.activePaths} | Max Risk: {graph.summary.maxPathRisk}
            </span>
          )}
          <button
            onClick={() => void retry()}
            className="ds-button px-3 py-1.5 text-xs rounded-lg border border-white/10 text-slate-300 hover:bg-white/5 flex items-center gap-1.5"
            aria-label="Refresh exploitation path"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {warning && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs px-3 py-2 relative z-10">
          {warning}
        </div>
      )}

      {loading && <div className="h-80 shimmer-skeleton rounded-xl border border-white/10" />}

      {!loading && error && (
        <div className="h-80 rounded-xl border border-rose-500/20 bg-black/40 flex flex-col items-center justify-center text-center px-6">
          <AlertTriangle className="w-8 h-8 text-rose-400 mb-3" />
          <p className="text-rose-300 text-sm mb-3">Failed to generate exploitation path.</p>
          <button onClick={() => void retry()} className="ds-button px-4 py-2 rounded-lg border border-rose-500/30 text-rose-300 hover:bg-rose-500/10 text-sm">
            Retry
          </button>
        </div>
      )}
      
      {!loading && !error && <div className="relative w-full h-80 bg-black/40 rounded-xl border border-white/5 backdrop-blur-sm p-4">
        {/* Edges */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
          {graph.edges.map((edge) => {
            const from = nodeById[edge.from];
            const to = nodeById[edge.to];
            if (!from || !to) {
              return null;
            }
            return (
              <path
                key={edge.id}
                d={edgePath(from, to)}
                stroke={edge.color}
                strokeWidth="2"
                strokeDasharray="5 5"
                className={edge.animated ? 'edge-flow' : ''}
                opacity={edge.animated ? 0.9 : 0.6}
              />
            );
          })}
        </svg>

        {/* Nodes */}
        {graph.nodes.map(node => (
          <button
            key={node.id}
            className={`absolute flex flex-col items-center justify-center transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-300 ${activeNode === node.id ? 'scale-110' : 'hover:scale-105'}`}
            style={{ left: `${node.x}%`, top: `${node.y}%`, zIndex: 10 }}
            onMouseEnter={() => setActiveNode(node.id)}
            onMouseLeave={() => setActiveNode(null)}
            onFocus={() => setActiveNode(node.id)}
            onBlur={() => setActiveNode(null)}
            aria-label={`${node.label}. ${node.description}`}
          >
            <div className="w-12 h-12 rounded-full flex items-center justify-center bg-[#0a0a0a]" style={{ border: `2px solid ${node.color}`, boxShadow: `0 0 15px ${node.color}40` }}>
              {node.type === 'cloud' && <CloudFog className="w-5 h-5 text-slate-300" />}
              {node.type === 'server' && <Server className="w-5 h-5 text-slate-300" />}
              {node.type === 'db' && <Database className="w-5 h-5 text-slate-300" />}
            </div>
            <div className="mt-3 text-[10px] uppercase font-mono tracking-widest text-slate-300 text-center whitespace-nowrap bg-black/60 px-2 py-1 rounded border border-white/5 shadow-2xl backdrop-blur-xl">
              {node.label}
            </div>
            
            {activeNode === node.id && (
                <div className="absolute top-full mt-[40px] w-56 bg-[#111] border border-white/10 rounded-xl p-4 shadow-2xl z-50 text-xs text-slate-400 backdrop-blur-2xl">
                    <p className="text-white font-medium mb-2 uppercase tracking-widest text-[10px] border-b border-white/10 pb-2">Risk Pivot Point</p>
                    <p className="leading-relaxed">{node.description}</p>
                    {graph.edges.find((e) => e.to === node.id)?.confidence && (
                      <p className="mt-2 text-[10px] text-sky-300">
                        Path confidence: {Math.round((graph.edges.find((e) => e.to === node.id)?.confidence || 0) * 100)}%
                      </p>
                    )}
                </div>
            )}
          </button>
        ))}

        {!graph.exploitable && (
          <div className="absolute bottom-4 left-4 right-4 rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-300 text-xs px-3 py-2 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" />
            No active exploitation chain detected in current telemetry.
          </div>
        )}
      </div>}

      {!loading && !error && graph.recommendations && graph.recommendations.length > 0 && (
        <div className="mt-4 rounded-xl border border-sky-500/20 bg-sky-500/10 px-4 py-3 text-xs text-sky-100">
          <p className="font-medium mb-1">Mitigation Guidance</p>
          <ul className="list-disc pl-4 space-y-1">
            {graph.recommendations.slice(0, 3).map((rec, idx) => (
              <li key={idx}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </motion.div>
  );
}
