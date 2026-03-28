import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldAlert, CheckCircle, Settings, ChevronRight, AlertTriangle, X, Shield } from 'lucide-react';
import { cn } from './Layout';

export function ExtensionMockup() {
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="flex flex-col items-center justify-center min-h-[700px] bg-[#0a0a0a] rounded-3xl p-8 relative overflow-hidden border border-white/5">
      
      {/* Background Glows */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/10 blur-[100px] rounded-full pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/10 blur-[100px] rounded-full pointer-events-none" />

      {/* Browser Window Mockup */}
      <div className="w-full max-w-5xl h-[650px] bg-[#0f0f0f] rounded-2xl shadow-2xl border border-white/10 overflow-hidden flex flex-col relative z-10">
        {/* Browser Header */}
        <div className="h-14 bg-[#141414] border-b border-white/5 flex items-center px-4 gap-4">
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
          </div>
          <div className="flex-1 max-w-2xl mx-auto bg-[#0a0a0a] h-8 rounded-lg border border-white/5 flex items-center justify-center px-4 text-xs text-slate-400 font-mono shadow-inner">
            https://console.aws.amazon.com/s3/home
          </div>
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsOpen(!isOpen)}
              className="relative p-2 hover:bg-white/5 rounded-lg transition-colors"
            >
              <Shield className="w-5 h-5 text-emerald-400" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-rose-500 rounded-full shadow-[0_0_8px_rgba(244,63,94,0.8)]"></span>
            </button>
          </div>
        </div>

        {/* Browser Content (AWS Console Mock - Dark Mode) */}
        <div className="flex-1 bg-[#0a0a0a] p-10">
          <div className="max-w-4xl mx-auto">
            <h1 className="text-2xl font-medium text-white mb-8">Amazon S3</h1>
            <div className="bg-[#111] p-6 rounded-xl border border-white/5 shadow-lg">
              <h2 className="text-lg font-medium text-white mb-6">Buckets (2)</h2>
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-white/5 text-slate-500 font-medium">
                    <th className="pb-3">Name</th>
                    <th className="pb-3">Region</th>
                    <th className="pb-3">Access</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  <tr>
                    <td className="py-4 font-mono text-blue-400">customer-data-prod</td>
                    <td className="py-4 text-slate-400">us-east-1</td>
                    <td className="py-4">
                      <span className="px-2.5 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-md text-xs font-medium">Public</span>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-4 font-mono text-blue-400">internal-logs-2026</td>
                    <td className="py-4 text-slate-400">us-west-2</td>
                    <td className="py-4">
                      <span className="px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-md text-xs font-medium">Private</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Extension Popup Overlay */}
        <AnimatePresence>
          {isOpen && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: -10, filter: "blur(10px)" }}
              animate={{ opacity: 1, scale: 1, y: 0, filter: "blur(0px)" }}
              exit={{ opacity: 0, scale: 0.95, y: -10, filter: "blur(10px)" }}
              transition={{ type: "spring", stiffness: 400, damping: 30 }}
              className="absolute top-16 right-4 w-[340px] bg-[#111]/90 backdrop-blur-2xl rounded-2xl shadow-2xl border border-white/10 overflow-hidden z-50 flex flex-col"
            >
              {/* Extension Header */}
              <div className="bg-gradient-to-r from-emerald-900/40 to-transparent p-4 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-emerald-400" />
                  <span className="font-medium text-sm text-white tracking-wide">CloudSec Copilot</span>
                </div>
                <button onClick={() => setIsOpen(false)} className="text-slate-400 hover:text-white transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Extension Content */}
              <div className="p-5 flex-1 overflow-y-auto">
                <div className="flex items-center justify-between mb-5">
                  <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Status</span>
                  <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_5px_rgba(52,211,153,0.8)] animate-pulse"></span>
                    Active
                  </span>
                </div>

                <motion.div 
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.1 }}
                  className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4 mb-5 relative overflow-hidden"
                >
                  <div className="absolute top-0 left-0 w-1 h-full bg-rose-500" />
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="text-sm font-medium text-rose-300">Critical Risk Detected</h4>
                      <p className="text-xs text-rose-400/80 mt-1.5 leading-relaxed">
                        Bucket <code className="bg-rose-500/20 px-1 py-0.5 rounded font-mono text-rose-300">customer-data-prod</code> was just made public.
                      </p>
                      <div className="mt-4 flex gap-2">
                        <button className="flex-1 bg-rose-500 hover:bg-rose-600 text-white text-xs font-medium py-2 rounded-lg transition-colors shadow-[0_0_15px_rgba(244,63,94,0.3)]">
                          Auto-Remediate
                        </button>
                        <button className="flex-1 bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-xs font-medium py-2 rounded-lg transition-colors">
                          Ignore
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>

                <div className="space-y-3">
                  <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">Recent Activity</h4>
                  
                  <div className="flex items-center gap-3 p-2.5 hover:bg-white/5 rounded-xl transition-colors cursor-pointer group">
                    <div className="w-8 h-8 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-300 truncate group-hover:text-white transition-colors">IAM Policy Reverted</p>
                      <p className="text-xs text-slate-500 font-mono mt-0.5">2 mins ago</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
                  </div>

                  <div className="flex items-center gap-3 p-2.5 hover:bg-white/5 rounded-xl transition-colors cursor-pointer group">
                    <div className="w-8 h-8 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
                      <ShieldAlert className="w-4 h-4 text-blue-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-300 truncate group-hover:text-white transition-colors">Port 22 Blocked</p>
                      <p className="text-xs text-slate-500 font-mono mt-0.5">15 mins ago</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
