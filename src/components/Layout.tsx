import React, { useState } from 'react';
import { Shield, LayoutDashboard, AlertTriangle, FileBarChart, MonitorSmartphone, BrainCircuit, Activity, Menu, X, LogOut, Sun, Moon } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { motion } from 'motion/react';
import { useApi } from '../hooks/useApi';
import { apiClient } from '../lib/apiClient';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface LayoutProps {
  children: React.ReactNode;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  role?: 'ADMIN' | 'USER';
  theme: 'day' | 'night';
  onToggleTheme: () => void;
  onLogout?: () => void;
}

export function Layout({ children, activeTab, setActiveTab, role = 'USER', theme, onToggleTheme, onLogout }: LayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { data: engineData, warning: engineWarning } = useApi<{
    modelConfidence: number;
    inferenceLatencyMs: number;
  }>(
    () => apiClient.get('/api/dashboard/ai-intel'),
    [],
    {
      fallbackData: {
        modelConfidence: 99.9,
        inferenceLatencyMs: 12,
      },
    }
  );

  const modelConfidence = engineData?.modelConfidence ?? 99.9;
  const inferenceLatency = engineData?.inferenceLatencyMs ?? 12;
  const engineModeLabel = engineWarning ? 'ML Fallback' : 'ML Active';

  const navItems = [
    { id: 'overview', label: 'Command Center', icon: LayoutDashboard },
    { id: 'alerts', label: 'Threat Intelligence', icon: AlertTriangle },
    { id: 'ai-intel', label: 'ML Engine (Copilot)', icon: BrainCircuit },
    { id: 'reports', label: 'Governance', icon: FileBarChart },
    { id: 'extension', label: 'Extension Preview', icon: MonitorSmartphone },
    { id: 'upgrades', label: 'Next-Level Upgrades', icon: Activity },
  ];
  const visibleNavItems = role === 'ADMIN' ? navItems : navItems.filter((item) => !['upgrades'].includes(item.id));

  return (
    <div className="flex h-screen app-shell overflow-hidden selection:bg-[var(--ui-primary-soft)]">
      {mobileMenuOpen && (
        <div className="fixed inset-0 bg-black/45 z-30 md:hidden" onClick={() => setMobileMenuOpen(false)} />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "w-72 app-sidebar border-r flex flex-col relative z-40 transition-transform duration-300 backdrop-blur-xl",
          "fixed md:static inset-y-0 left-0",
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        <div className="absolute top-0 left-0 w-full h-32 bg-[var(--ui-primary-soft)] blur-[50px] pointer-events-none" />
        
        <div className="p-7 flex items-center gap-4 text-[var(--ui-text)] relative">
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br from-[var(--ui-primary-soft)] to-[var(--ui-secondary-soft)] border border-[var(--ui-primary-border)] shadow-[0_0_20px_var(--ui-primary-shadow)]">
            <Shield className="w-5 h-5 text-[var(--ui-primary-text)]" />
          </div>
          <div>
            <span className="font-bold text-lg tracking-wide block">CloudSec</span>
            <span className="text-xs text-[var(--ui-primary-text)] font-mono tracking-widest uppercase">Control Plane</span>
          </div>
        </div>
        
        <nav className="flex-1 px-4 py-4 space-y-2 relative">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setMobileMenuOpen(false);
                }}
                aria-label={`Navigate to ${item.label}`}
                className={cn(
                  "w-full flex items-center gap-3 px-4 py-3.5 rounded-xl transition-all duration-300 text-sm font-medium relative group overflow-hidden",
                  isActive ? "text-[var(--ui-text)]" : "text-[var(--ui-text-muted)] hover:text-[var(--ui-text)] hover:bg-[var(--ui-hover)]"
                )}
              >
                {isActive && (
                  <motion.div 
                    layoutId="activeTab" 
                    className="absolute inset-0 bg-gradient-to-r from-[var(--ui-primary-soft)] to-transparent border-l-2 border-[var(--ui-primary-border)]"
                    initial={false}
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
                <Icon className={cn("w-5 h-5 relative z-10 transition-colors duration-300", isActive ? "text-[var(--ui-primary-text)]" : "group-hover:text-[var(--ui-text)]")} />
                <span className="relative z-10">{item.label}</span>
              </button>
            );
          })}
        </nav>
        
        <div className="ds-card p-6 m-4 relative overflow-hidden">
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-[var(--ui-primary-soft)] blur-2xl rounded-full pointer-events-none" />
          <div className="flex items-center justify-between mb-3 relative">
            <span className="text-xs font-semibold text-[var(--ui-text-muted)] uppercase tracking-wider">Engine Status</span>
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--ui-primary-text)] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--ui-primary-text)] shadow-[0_0_8px_var(--ui-primary-shadow)]"></span>
            </span>
          </div>
          <div className="text-[var(--ui-text)] font-mono text-sm relative">{engineModeLabel} <span className="text-[var(--ui-primary-text)]">{modelConfidence}%</span></div>
          <div className="text-[var(--ui-text-muted)] mt-1 text-xs relative flex items-center gap-1">
            <Activity className="w-3 h-3" /> {inferenceLatency}ms inference
          </div>
        </div>

        {onLogout && (
          <button
            onClick={onLogout}
            className="ds-button mx-4 mb-4 px-4 py-3 rounded-xl border border-[var(--ui-panel-border)] text-[var(--ui-text)] hover:bg-[var(--ui-hover)] transition-colors flex items-center gap-2"
            aria-label="Logout"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        )}
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col relative overflow-hidden">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-[var(--ui-primary-soft)] blur-[120px] rounded-full pointer-events-none" />
        
        <header className="h-20 app-header border-b px-4 md:px-8 lg:px-10 flex items-center justify-between relative z-10 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <button
              className="md:hidden ds-button w-9 h-9 rounded-lg border border-[var(--ui-panel-border)] flex items-center justify-center hover:bg-[var(--ui-hover)]"
              onClick={() => setMobileMenuOpen((v) => !v)}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
            <h1 className="text-lg md:text-2xl font-semibold tracking-tight text-[var(--ui-text)] title-gradient">
              {visibleNavItems.find(i => i.id === activeTab)?.label || 'Command Center'}
            </h1>
          </div>
          <div className="flex items-center gap-4 md:gap-6">
            <motion.button
              type="button"
              onClick={onToggleTheme}
              whileTap={{ scale: 0.96 }}
              className="ds-button relative rounded-full px-3 py-2 border border-[var(--ui-panel-border)] bg-[var(--ui-panel)] text-[var(--ui-text)] flex items-center gap-2"
              aria-label="Toggle day and night mode"
            >
              <span className="relative flex h-5 w-10 rounded-full bg-[var(--ui-hover)] border border-[var(--ui-panel-border)]">
                <motion.span
                  className="absolute top-[1px] h-4 w-4 rounded-full bg-[var(--ui-primary-text)]"
                  animate={{ x: theme === 'night' ? 20 : 1 }}
                  transition={{ type: 'spring', stiffness: 380, damping: 24 }}
                />
              </span>
              {theme === 'night' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
            </motion.button>
            <div className="text-right">
              <div className="text-sm font-medium text-[var(--ui-text)]">{role === 'ADMIN' ? 'Security Admin' : 'Security Analyst'}</div>
              <div className="text-xs text-[var(--ui-primary-text)] font-mono">{role === 'ADMIN' ? 'Level 5 Clearance' : 'Level 2 Clearance'}</div>
            </div>
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-[var(--ui-primary-soft)] to-[var(--ui-secondary-soft)] border border-[var(--ui-panel-border)] flex items-center justify-center shadow-lg">
              <span className="text-sm font-bold text-[var(--ui-text)]">SA</span>
            </div>
          </div>
        </header>
        
        <div className="flex-1 overflow-auto p-4 md:p-7 lg:p-10 relative z-10 scrollbar-hide">
          <motion.div
            key={activeTab}
            className="max-w-7xl mx-auto"
            initial={{ opacity: 0, y: 16, filter: 'blur(4px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ duration: 0.36, ease: [0.22, 1, 0.36, 1] }}
          >
            {children}
          </motion.div>
        </div>
      </main>
    </div>
  );
}
