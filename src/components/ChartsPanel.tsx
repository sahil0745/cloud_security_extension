import React, { useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, Sector } from 'recharts';
import { motion } from 'motion/react';
import { useApi } from '../hooks/useApi';
import { apiClient } from '../lib/apiClient';

type ChartsPayload = {
  riskTrend: Array<{ time: string; risk: number }>;
  attackVectors: Array<{ name: string; count: number }>;
  severityDistribution: Array<{ name: string; value: number }>;
  heatmap: Array<{ region: string; db: number; storage: number; network: number; iam: number }>;
};

const demoCharts: ChartsPayload = {
  riskTrend: [
    { time: '09:00', risk: 24 },
    { time: '10:00', risk: 46 },
    { time: '11:00', risk: 52 },
    { time: '12:00', risk: 39 },
  ],
  attackVectors: [
    { name: 'iam_policy', count: 5 },
    { name: 'public_s3', count: 3 },
    { name: 'open_port', count: 4 },
  ],
  severityDistribution: [
    { name: 'LOW', value: 2 },
    { name: 'MEDIUM', value: 3 },
    { name: 'HIGH', value: 2 },
    { name: 'CRITICAL', value: 1 },
  ],
  heatmap: [
    { region: 'aws', db: 35, storage: 24, network: 28, iam: 20 },
    { region: 'azure', db: 20, storage: 16, network: 18, iam: 14 },
    { region: 'gcp', db: 12, storage: 10, network: 14, iam: 9 },
  ],
};

const pieColors = ['#3b82f6', '#f59e0b', '#f97316', '#f43f5e'];

const renderActiveShape = (props: any) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill, payload, value, percent } = props;
  return (
    <g>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 6}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
      />
      <text x={cx} y={cy - 4} textAnchor="middle" fill="#e2e8f0" fontSize={11} fontWeight={600}>
        {payload.name}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#94a3b8" fontSize={10}>
        {value} ({(percent * 100).toFixed(0)}%)
      </text>
    </g>
  );
};

export function ChartsPanel({ itemVariants }: any) {
  const [activePieIndex, setActivePieIndex] = useState(0);
  const { data, loading, error, warning, retry } = useApi<ChartsPayload>(
    () => apiClient.get('/api/dashboard/charts'),
    [],
    {
      fallbackData: demoCharts,
      fallbackWarning: 'Backend unavailable. Rendering demo chart data.',
    }
  );

  if (loading) {
    return <div className="h-64 shimmer-skeleton rounded-2xl border border-white/10" />;
  }

  if (error || !data) {
    return (
      <div className="h-64 bg-[#111] rounded-2xl border border-rose-500/20 flex flex-col items-center justify-center gap-3">
        <span className="text-rose-300 text-sm">Unable to load chart data.</span>
        <button onClick={() => void retry()} className="px-3 py-1.5 rounded-lg border border-rose-500/30 text-rose-300 hover:bg-rose-500/10">Retry</button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {warning && (
        <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 text-amber-300 px-4 py-2 text-xs">
          {warning}
        </div>
      )}
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Risk Trends Timeline */}
      <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl backdrop-blur-xl" whileHover={{ y: -2 }} transition={{ duration: 0.25 }}>
        <h3 className="text-sm font-medium text-slate-400 mb-4">Risk Trends (Timeline)</h3>
        <div className="h-64">
          {data.riskTrend.length === 0 ? (
            <div className="h-full rounded-xl border border-white/10 bg-white/[0.02] flex items-center justify-center text-xs text-slate-500">
              No timeline risk data available.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.riskTrend}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#222" />
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }}/>
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }}/>
                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333' }} />
                <Area type="monotone" dataKey="risk" stroke="#f97316" strokeWidth={2} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </motion.div>

      {/* Attack Attempts */}
      <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl backdrop-blur-xl" whileHover={{ y: -2 }} transition={{ duration: 0.25 }}>
        <h3 className="text-sm font-medium text-slate-400 mb-4">Attack Vectors</h3>
        <div className="h-64">
          {data.attackVectors.length === 0 ? (
            <div className="h-full rounded-xl border border-white/10 bg-white/[0.02] flex items-center justify-center text-xs text-slate-500">
              No attack vector activity available.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.attackVectors}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#222" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }}/>
                <Tooltip cursor={{ fill: '#222' }} contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </motion.div>

      {/* Severity Distribution Pie */}
      <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl backdrop-blur-xl" whileHover={{ y: -2 }} transition={{ duration: 0.25 }}>
        <h3 className="text-sm font-medium text-slate-400 mb-4">Severity Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333' }} />
              <Pie
                data={data.severityDistribution}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={54}
                outerRadius={82}
                paddingAngle={2}
                activeIndex={activePieIndex}
                activeShape={renderActiveShape}
                onMouseEnter={(_, index) => setActivePieIndex(index)}
                animationDuration={900}
                animationEasing="ease-out"
              >
                {data.severityDistribution.map((entry, index) => (
                  <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      {/* Regional Risk Heatmap Simulation */}
      <motion.div variants={itemVariants} className="bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl backdrop-blur-xl" whileHover={{ y: -2 }} transition={{ duration: 0.25 }}>
        <h3 className="text-sm font-medium text-slate-400 mb-4">Vuln Risk Heatmap</h3>
        <div className="h-64">
          {data.heatmap.length === 0 ? (
            <div className="h-full rounded-xl border border-white/10 bg-white/[0.02] flex items-center justify-center text-xs text-slate-500">
              No current platform heatmap data.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.heatmap} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#222" />
                <XAxis type="number" hide />
                <YAxis dataKey="region" type="category" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#64748b' }} width={60} />
                <Tooltip cursor={{ fill: '#222' }} contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333' }} />
                <Bar dataKey="db" stackId="a" fill="#f43f5e" />     {/* Critical */}
                <Bar dataKey="iam" stackId="a" fill="#f97316" />    {/* High */}
                <Bar dataKey="storage" stackId="a" fill="#f59e0b" />{/* Medium */}
                <Bar dataKey="network" stackId="a" fill="#3b82f6" />{/* Low */}
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </motion.div>
    </div>
    </div>
  );
}
