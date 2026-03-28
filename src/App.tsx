import React, { useEffect, useState } from 'react';
import { Layout } from './components/Layout';
import { Overview } from './components/Overview';
import { Alerts } from './components/Alerts';
import { AIThreatIntel } from './components/AIThreatIntel';
import { Reports } from './components/Reports';
import { ExtensionMockup } from './components/ExtensionMockup';
import { UpgradeSuggestions } from './components/UpgradeSuggestions';
import { apiClient, ApiError, clearStoredToken, getStoredToken } from './lib/apiClient';

type UserRole = 'ADMIN' | 'USER';
type ThemeMode = 'day' | 'night';

function getRoleFromToken(token: string | null): UserRole {
  return 'ADMIN'; // Bypassed authentication
}

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [token, setToken] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const stored = window.localStorage.getItem('ui-theme-mode');
    return stored === 'day' ? 'day' : 'night';
  });
  const role = getRoleFromToken(token);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    window.localStorage.setItem('ui-theme-mode', theme);
  }, [theme]);

  useEffect(() => {
    if (role !== 'ADMIN' && ['upgrades'].includes(activeTab)) {
      setActiveTab('overview');
    }
  }, [activeTab, role]);

  useEffect(() => {
    const handleExpired = () => {
      // Auth is bypassed
    };
    window.addEventListener('auth:expired', handleExpired);
    return () => window.removeEventListener('auth:expired', handleExpired);
  }, []);

  return (
    <Layout
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      role={role}
      theme={theme}
      onToggleTheme={() => setTheme((prev) => (prev === 'night' ? 'day' : 'night'))}
      onLogout={() => {
        clearStoredToken();
        setToken(null);
      }}
    >
      {activeTab === 'overview' && <Overview />}
      {activeTab === 'alerts' && <Alerts />}
      {activeTab === 'ai-intel' && <AIThreatIntel />}
      {activeTab === 'reports' && <Reports role={role} />}
      {activeTab === 'extension' && <ExtensionMockup />}
      {activeTab === 'upgrades' && role === 'ADMIN' && <UpgradeSuggestions />}
    </Layout>
  );
}
