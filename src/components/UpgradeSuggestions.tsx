import React from 'react';
import { Shield, Brain, GitBranch, LayoutDashboard, Zap, Activity, Lock, CheckCircle2 } from 'lucide-react';
import { motion } from 'motion/react';

export function UpgradeSuggestions() {
  const upgrades = [
    {
      title: "UI/UX Upgrade",
      icon: <LayoutDashboard className="w-6 h-6 text-cyan-400" />,
      color: "cyan",
      items: [
        "3D dashboard (Three.js)",
        "Neon cyber theme rendering"
      ]
    },
    {
      title: "AI Upgrade",
      icon: <Brain className="w-6 h-6 text-purple-400" />,
      color: "purple",
      items: [
        "AI insights panel",
        "Explainable 'Why this risk occurred' logic"
      ]
    },
    {
      title: "Interaction Upgrade",
      icon: <Activity className="w-6 h-6 text-blue-400" />,
      color: "blue",
      items: [
        "Drill-down raw data",
        "Deep-clickable timeline charts"
      ]
    },
    {
      title: "Enterprise Upgrade",
      icon: <Lock className="w-6 h-6 text-emerald-400" />,
      color: "emerald",
      items: [
        "Multi-user synchronization",
        "Role-based access views (RBAC)"
      ]
    },
    {
      title: "Visual Upgrade",
      icon: <Zap className="w-6 h-6 text-rose-400" />,
      color: "rose",
      items: [
        "Animated attack simulation",
        "Live heat-mapping overlays"
      ]
    }
  ];

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-light text-white">Next-Level System Upgrades</h2>
        <p className="text-slate-400 mt-2">Suggested architectural and feature enhancements for the CloudSec Copilot.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {upgrades.map((upgrade, idx) => (
          <motion.div
            key={upgrade.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="bg-[#111] border border-white/5 rounded-2xl p-6 hover:bg-white/[0.02] transition-colors"
          >
            <div className="flex items-center gap-4 mb-6">
              <div className={`p-3 rounded-xl bg-${upgrade.color}-500/10 border border-${upgrade.color}-500/20`}>
                {upgrade.icon}
              </div>
              <h3 className="text-lg font-medium text-white">{upgrade.title}</h3>
            </div>
            <ul className="space-y-3">
              {upgrade.items.map((item, i) => (
                <li key={i} className="flex items-start gap-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-500/50 shrink-0 mt-0.5" />
                  <span className="text-sm text-slate-300 leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>
        ))}
      </div>
      
      <div className="bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-pink-500/10 border border-white/10 rounded-2xl p-8 text-center relative overflow-hidden">
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-20 mix-blend-overlay"></div>
        <Lock className="w-12 h-12 text-white/50 mx-auto mb-4" />
        <h3 className="text-xl font-medium text-white mb-2">Enterprise Edition</h3>
        <p className="text-slate-400 max-w-2xl mx-auto mb-6">
          Unlock all advanced features including ML-driven auto-learning rules, full CI/CD pipeline integration, and comprehensive compliance mapping.
        </p>
        <button className="px-6 py-2.5 bg-white text-black font-medium rounded-lg hover:bg-slate-200 transition-colors">
          Upgrade to Enterprise
        </button>
      </div>
    </div>
  );
}
