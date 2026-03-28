importScripts('../utils/helpers.js');

const DEFAULT_API_BASE = 'http://localhost:8000';
const MONITOR_ALARM_NAME = 'cloudsec-monitor-tick';
const MONITOR_INTERVAL_MINUTES = 0.5;
const SAME_PLATFORM_REFRESH_MS = 15000;
const DEMO_FALLBACK = {
  riskScore: 42,
  status: 'Warning',
  baselineStatus: 'Demo Mode',
  driftDetails: [{ field: 'connectivity', type: 'backend_unreachable', old: 'online', new: 'offline' }],
  violations: [
    {
      rule_id: 'DEMO_NETWORK_EXPOSURE',
      severity: 'HIGH',
      description: 'Demo fallback: network rule needs review',
      resource: 'sg-demo-001',
    },
  ],
  dashboardCharts: {
    riskTrend: [
      { time: '00:00', risk: 30 }, { time: '04:00', risk: 35 }, { time: '08:00', risk: 45 },
      { time: '12:00', risk: 42 }, { time: '16:00', risk: 38 }, { time: '20:00', risk: 40 }
    ],
    severityDistribution: [
      { name: 'LOW', value: 2 }, { name: 'MEDIUM', value: 5 }, { name: 'HIGH', value: 3 }, { name: 'CRITICAL', value: 1 }
    ],
    heatmap: [{ region: 'AWS', db: 40, storage: 60, network: 80, iam: 20 }],
    attackVectors: [{ name: 's3_access', count: 12 }, { name: 'iam_policy', count: 8 }]
  },
  dashboardVulns: [
    { rule_id: 'S3_PUBLIC_ACCESS', severity: 'HIGH', description: 'Public S3 bucket detected', resource: 'bucket-demo' },
    { rule_id: 'IAM_WILDCARD', severity: 'CRITICAL', description: 'Overly permissive IAM policy', resource: 'role-demo' }
  ]
};

function getExtensionStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => resolve(result));
  });
}

async function getApiBase() {
  const cfg = await getExtensionStorage(['apiBaseUrl']);
  return (cfg.apiBaseUrl || DEFAULT_API_BASE).replace(/\/$/, '');
}

async function getAuthToken() {
  const cfg = await getExtensionStorage(['authToken']);
  return cfg.authToken || null;
}

async function getRefreshToken() {
  const cfg = await getExtensionStorage(['refreshToken']);
  return cfg.refreshToken || null;
}

function setAuthState(next) {
  return new Promise((resolve) => {
    chrome.storage.local.set(next, () => resolve());
  });
}

function detectPlatformFromUrl(url, title = '') {
  if (!url) return null;

  let hostname = '';
  let pathname = '';
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
    pathname = (parsed.pathname || '').toLowerCase();
  } catch (error) {
    return null;
  }

  if (hostname.endsWith('.aws.amazon.com') || hostname === 'aws.amazon.com' || hostname === 'console.aws.amazon.com') return 'AWS';
  if ((hostname.endsWith('.amazon.com') || hostname === 'amazon.com') && pathname.includes('/aws')) return 'AWS';

  if (
    hostname === 'portal.azure.com' ||
    hostname === 'azure.microsoft.com' ||
    hostname.endsWith('.azure.com') ||
    hostname.endsWith('.azure.microsoft.com')
  ) {
    return 'Azure';
  }
  if ((hostname.endsWith('.microsoft.com') || hostname === 'microsoft.com') && pathname.includes('/azure')) return 'Azure';

  if (
    hostname === 'cloud.google.com' ||
    hostname.endsWith('.cloud.google.com') ||
    hostname === 'console.cloud.google.com'
  ) {
    return 'GCP';
  }
  if (hostname.endsWith('.google.com') && (pathname.includes('/cloud') || pathname.includes('/gcp'))) return 'GCP';

  if (hostname.endsWith('.oraclecloud.com') || hostname === 'oraclecloud.com') return 'Oracle Cloud';
  if (hostname.endsWith('.cloud.ibm.com') || hostname === 'cloud.ibm.com') return 'IBM Cloud';
  if (hostname.endsWith('.digitalocean.com') || hostname === 'digitalocean.com') return 'DigitalOcean';
  if (hostname.endsWith('.alibabacloud.com') || hostname === 'alibabacloud.com') return 'Alibaba Cloud';
  if (hostname.endsWith('.linode.com') || hostname === 'linode.com') return 'Linode';

  const normalizedTitle = String(title || '').toLowerCase();
  if (normalizedTitle.includes('azure') && (hostname.includes('microsoft') || hostname.includes('azure'))) return 'Azure';
  if ((normalizedTitle.includes('aws') || normalizedTitle.includes('amazon web services')) && hostname.includes('amazon')) return 'AWS';
  if (normalizedTitle.includes('google cloud') || (normalizedTitle.includes('gcp') && hostname.includes('google'))) return 'GCP';

  return null;
}

function ensureContentScriptInjected(tabId, url) {
  if (!tabId || !url || !detectPlatformFromUrl(url)) {
    return;
  }

  chrome.scripting.executeScript(
    {
      target: { tabId },
      files: ['content/content.js'],
    },
    () => {
      if (chrome.runtime.lastError) {
        CloudSecUtils.log('Content script inject skipped:', chrome.runtime.lastError.message);
      }
    }
  );
}

function scanOpenTabsForCloudPlatforms() {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      ensureContentScriptInjected(tab.id, tab.url);
      checkTabInfo(tab.url, tab.title || '');
    }
  });
}

function syncActiveTabPlatform() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      return;
    }
    const tab = tabs[0];
    ensureContentScriptInjected(tab.id, tab.url);
    checkTabInfo(tab.url, tab.title || '');
  });
}

function ensureMonitoringAlarm() {
  chrome.alarms.create(MONITOR_ALARM_NAME, {
    periodInMinutes: MONITOR_INTERVAL_MINUTES,
  });
}

async function refreshAuthToken(base) {
  const refreshToken = await getRefreshToken();
  if (!refreshToken) {
    return null;
  }

  const refreshRes = await fetch(`${base}/api/auth/refresh`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${refreshToken}`,
    },
  });

  if (!refreshRes.ok) {
    return null;
  }

  const refreshed = await refreshRes.json();
  if (!refreshed?.access_token || !refreshed?.refresh_token) {
    return null;
  }

  await setAuthState({
    authToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token,
    authStatus: 'authenticated',
    authError: null,
  });
  return refreshed.access_token;
}

async function apiRequest(path, options = {}) {
  const base = await getApiBase();
  let token = await getAuthToken();

  const buildHeaders = (activeToken) => {
    const headers = new Headers(options.headers || {});
    if (activeToken) {
      headers.set('Authorization', `Bearer ${activeToken}`);
    }
    if (!headers.has('Content-Type') && options.body) {
      headers.set('Content-Type', 'application/json');
    }
    return headers;
  };

  let res = await fetch(`${base}${path}`, {
    ...options,
    headers: buildHeaders(token),
  });

  if (res.status === 401) {
    token = await refreshAuthToken(base);
    if (token) {
      res = await fetch(`${base}${path}`, {
        ...options,
        headers: buildHeaders(token),
      });
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      await setAuthState({
        authToken: null,
        refreshToken: null,
        authUser: null,
        authStatus: 'expired',
        authError: 'Authentication expired. Please sign in again.',
      });
    }
    const detail = await res.text().catch(() => '');
    throw new Error(`API ${path} failed (${res.status}): ${detail}`);
  }

  return res.json();
}

async function loginToBackend(username, password, explicitApiBase) {
  const base = (explicitApiBase || (await getApiBase())).replace(/\/$/, '');
  const form = new URLSearchParams();
  form.set('username', username);
  form.set('password', password);

  const res = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
  });

  const payload = await res.json().catch(() => ({}));
  if (!res.ok || !payload?.access_token) {
    throw new Error('Login failed. Verify credentials and backend URL.');
  }

  await setAuthState({
    apiBaseUrl: base,
    authToken: payload.access_token,
    refreshToken: payload.refresh_token || null,
    authUser: username,
    authStatus: 'authenticated',
    authError: null,
  });
}

// 1. Extension Activation & State Initialization
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    CloudSecUtils.log('CloudSec Extension Installed. Initializing system...');
    
    // Initialize default storage state
    chrome.storage.local.set({ 
      isMonitoring: false, 
      riskScore: 0, 
      status: 'Safe',
      theme: 'dark',
      currentPlatform: null,
      lastDetectionTime: 0,
      baselineStatus: 'None',
      driftDetails: null,
      lastScanTime: null,
      demoMode: false,
      demoWarning: null,
      authStatus: 'logged_out',
      authError: null,
      authToken: null,
      refreshToken: null,
      authUser: null,
      apiBaseUrl: DEFAULT_API_BASE,
    });
  }

  // Run a one-time scan so already-open cloud tabs auto-activate without reload.
  ensureMonitoringAlarm();
  scanOpenTabsForCloudPlatforms();
});

chrome.runtime.onStartup.addListener(() => {
  ensureMonitoringAlarm();
  scanOpenTabsForCloudPlatforms();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== MONITOR_ALARM_NAME) {
    return;
  }

  syncActiveTabPlatform();

  chrome.storage.local.get(['isMonitoring', 'currentPlatform'], (res) => {
    if (!res.isMonitoring || !res.currentPlatform) {
      return;
    }
    performCloudAnalysis(res.currentPlatform);
  });
});

// 2. Background Service Worker - Central Event Handler
let lastNotifiedPlatform = null;
let lastNotificationTime = 0;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const safeLogRequest = {
    type: request?.type || 'unknown',
    platform: request?.platform || null,
    hasToken: Boolean(request?.token),
  };
  CloudSecUtils.log('Background received message:', safeLogRequest);

  // Handle Cloud Detection from Content Script
  if (request.type === 'CLOUD_DETECTED') {
    handleCloudDetection(request.platform);
    sendResponse({ success: true });
    return true;
  }

  // Handle Manual Start Monitoring Request from Popup
  if (request.type === 'START_MONITORING') {
    chrome.storage.local.set({ isMonitoring: true });
    chrome.storage.local.get(['currentPlatform'], (res) => {
      if (res.currentPlatform) {
        performCloudAnalysis(res.currentPlatform);
      } else {
        chrome.storage.local.set({ status: 'Safe' });
      }
    });
    sendResponse({ success: true, status: 'Analyzing', score: 0 });
    return true;
  }

  // Handle Stop Monitoring Request from Popup
  if (request.type === 'STOP_MONITORING') {
    chrome.storage.local.set({ 
      isMonitoring: false, 
      riskScore: 0, 
      status: 'Safe',
      currentPlatform: null,
      baselineStatus: 'None',
      driftDetails: null
    });
    lastNotifiedPlatform = null; // Reset notification state
    sendResponse({ success: true });
  }

  if (request.type === 'CONTENT_SCRIPT_READY') {
    sendResponse({ acknowledged: true });
  }

  if (request.type === 'SET_AUTH_TOKEN') {
    chrome.storage.local.set({ authToken: request.token || null, authStatus: request.token ? 'authenticated' : 'logged_out' }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.type === 'AUTH_LOGIN') {
    loginToBackend(request.username || '', request.password || '', request.apiBaseUrl || '')
      .then(() => sendResponse({ success: true }))
      .catch((error) => {
        chrome.storage.local.set({ authStatus: 'error', authError: error.message || 'Login failed' });
        sendResponse({ success: false, error: error.message || 'Login failed' });
      });
    return true;
  }

  if (request.type === 'AUTH_LOGOUT') {
    chrome.storage.local.set({
      authToken: null,
      refreshToken: null,
      authUser: null,
      authStatus: 'logged_out',
      authError: null,
    }, () => sendResponse({ success: true }));
    return true;
  }

  if (request.type === 'AUTH_STATUS') {
    chrome.storage.local.get(['authToken', 'authUser', 'authStatus', 'authError', 'apiBaseUrl'], (res) => {
      sendResponse({
        authenticated: Boolean(res.authToken),
        user: res.authUser || null,
        status: res.authStatus || 'logged_out',
        error: res.authError || null,
        apiBaseUrl: res.apiBaseUrl || DEFAULT_API_BASE,
      });
    });
    return true;
  }
});

// 3. Auto-Activation Logic
function handleCloudDetection(platform) {
  chrome.storage.local.get(['currentPlatform', 'isMonitoring', 'demoMode', 'lastAnalysisAt'], (res) => {
    const now = Date.now();
    const lastAnalysisAt = Number(res.lastAnalysisAt || 0);
    const shouldRefreshSamePlatform = now - lastAnalysisAt >= SAME_PLATFORM_REFRESH_MS;
    
    // Prevent spamming if already monitoring the same platform,
    // but allow retries when we are in demo fallback mode.
    if (res.currentPlatform === platform && res.isMonitoring && !res.demoMode && !shouldRefreshSamePlatform) {
      return; 
    }

    CloudSecUtils.log(`Auto-activating monitoring for ${platform}`);

    // Update state to trigger UI changes in popup
    chrome.storage.local.set({
      currentPlatform: platform,
      isMonitoring: true,
      status: 'Analyzing', // Triggers progress bar in popup
      lastDetectionTime: now,
      baselineStatus: 'Fetching...',
      driftDetails: null
    });

    // Smart Notification (Debounce 10 seconds to avoid spam on rapid tab switches)
    if (lastNotifiedPlatform !== platform || (now - lastNotificationTime > 10000)) {
      chrome.notifications.create(`cloud-detect-${now}`, {
        type: 'basic',
        iconUrl: 'assets/icons/icon128.png',
        title: `Cloud Platform Detected: ${platform}`,
        message: 'Monitoring Started Successfully. Analyzing configuration...'
      }, () => {
        if (chrome.runtime.lastError) {
          CloudSecUtils.log('Notification skipped (icon missing or permission denied).');
        }
      });
      
      lastNotifiedPlatform = platform;
      lastNotificationTime = now;
    }

    // Perform actual API analysis
    chrome.storage.local.set({ demoMode: false, demoWarning: null });
    performCloudAnalysis(platform);
  });
}

// 4. Tab Switching Handling (Re-detect when user returns)
chrome.tabs.onActivated.addListener(activeInfo => {
  chrome.tabs.get(activeInfo.tabId, tab => {
    ensureContentScriptInjected(tab.id, tab.url);
    checkTabInfo(tab.url, tab.title || '');
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'complete') {
    ensureContentScriptInjected(tabId, changeInfo.url || tab.url);
    checkTabInfo(changeInfo.url || tab.url, tab.title || '');
  }
});

function checkTabInfo(url, title = '') {
  if (!url) return;
  
  const platform = detectPlatformFromUrl(url, title);

  if (platform) {
    handleCloudDetection(platform);
  }
}

// 5. Real-Time Cloud Data Fetch & Baseline System
async function performCloudAnalysis(platform) {
  try {
    CloudSecUtils.log(`Fetching config for ${platform} from backend...`);
    
    // Step 1: Fetch Config
    const configData = await apiRequest('/api/fetch-config', {
      method: 'POST',
      body: JSON.stringify({ platform: platform, account_id: 'default' }),
    });
    const currentConfig = configData.configuration;

    // Step 2: Compare Config (Drift Detection)
    const comparison = await apiRequest('/api/compare-config', {
      method: 'POST',
      body: JSON.stringify({
        platform: platform, 
        account_id: 'default',
        current_configuration: currentConfig
      }),
    });
    const now = new Date().toLocaleTimeString();

    let dashboardCharts = null;
    let dashboardVulns = null;
    try {
      dashboardCharts = await apiRequest(`/api/dashboard/charts?platform=${encodeURIComponent(platform)}`, { method: 'GET' });
      dashboardVulns = await apiRequest(`/api/dashboard/vulnerabilities?platform=${encodeURIComponent(platform)}`, { method: 'GET' });
    } catch (e) {
      CloudSecUtils.log('Failed to fetch full dashboard telemetry', e);
    }

    // Step 3: Handle Baseline Creation or Drift
    if (comparison.needs_baseline) {
      CloudSecUtils.log('No baseline found. Creating new baseline...');
      await apiRequest('/api/create-baseline', {
        method: 'POST',
        body: JSON.stringify({
          platform: platform,
          account_id: 'default',
          configuration: currentConfig
        })
      });
      const derivedRisk = (comparison.risk_data && comparison.risk_data.risk_score) || 0;
      const status = derivedRisk >= 70 ? 'Critical' : (derivedRisk >= 30 ? 'Risk' : 'Safe');
      
      chrome.storage.local.set({ 
        riskScore: derivedRisk,
        status: status,
        baselineStatus: 'Created',
        driftDetails: null,
        violations: null,
        mlPrediction: comparison.ml_prediction || null,
        behaviorAnalysis: null,
        demoMode: false,
        demoWarning: null,
        lastAnalysisAt: Date.now(),
        lastScanTime: now,
        dashboardCharts,
        dashboardVulns
      });
      
    } else if (comparison.drift_detected || (comparison.violations && comparison.violations.length > 0)) {
      CloudSecUtils.log('Drift or Violations detected!', comparison.changes, comparison.violations);
      
      const derivedRisk = (comparison.risk_data && comparison.risk_data.risk_score) || 0;
      const status = derivedRisk >= 70 ? 'Critical' : (derivedRisk >= 30 ? 'Risk' : 'Warning');
      
      chrome.storage.local.set({ 
        riskScore: derivedRisk,
        status: status,
        baselineStatus: comparison.drift_detected ? 'Drift Detected' : 'Violations Found',
        driftDetails: comparison.changes,
        violations: comparison.violations,
        mlPrediction: comparison.ml_prediction || null,
        behaviorAnalysis: comparison.behavior_analysis || null,
        demoMode: false,
        demoWarning: null,
        lastAnalysisAt: Date.now(),
        lastScanTime: now,
        dashboardCharts,
        dashboardVulns
      });
      
      // Trigger Warning Notification
      chrome.notifications.create(`drift-alert-${Date.now()}`, {
        type: 'basic',
        iconUrl: 'assets/icons/icon128.png',
        title: `⚠️ ${status} Configuration Detected`,
        message: 'Unauthorized changes or security violations found.'
      });
      
    } else {
      CloudSecUtils.log('Configuration matches baseline and no violations. Safe.');
      const derivedRisk = (comparison.risk_data && comparison.risk_data.risk_score) || 0;
      const status = derivedRisk >= 70 ? 'Critical' : (derivedRisk >= 30 ? 'Risk' : 'Safe');
      chrome.storage.local.set({ 
        riskScore: derivedRisk,
        status: status,
        baselineStatus: 'Verified',
        driftDetails: null,
        violations: null,
        mlPrediction: comparison.ml_prediction || null,
        behaviorAnalysis: comparison.behavior_analysis || null,
        demoMode: false,
        demoWarning: null,
        lastAnalysisAt: Date.now(),
        lastScanTime: now,
        dashboardCharts,
        dashboardVulns
      });
    }

  } catch (error) {
    CloudSecUtils.log('Backend API failed.', error);
    const base = await getApiBase();
    let backendReachable = false;
    try {
      const healthRes = await fetch(`${base}/health`, { method: 'GET' });
      backendReachable = healthRes.ok;
    } catch (healthError) {
      backendReachable = false;
    }

    if (backendReachable) {
      chrome.storage.local.set({
        riskScore: 0,
        status: 'Warning',
        baselineStatus: 'Analysis Error',
        driftDetails: [{ field: 'analysis', type: 'error', old: 'ok', new: String(error?.message || error) }],
        violations: [],
        demoMode: false,
        demoWarning: 'Backend connected, but analysis failed for this platform/config. Retrying on next detection.',
        lastAnalysisAt: Date.now(),
        lastScanTime: new Date().toLocaleTimeString(),
        dashboardCharts: null,
        dashboardVulns: null
      });
      return;
    }

    chrome.storage.local.set({
      riskScore: DEMO_FALLBACK.riskScore,
      status: DEMO_FALLBACK.status,
      baselineStatus: DEMO_FALLBACK.baselineStatus,
      driftDetails: DEMO_FALLBACK.driftDetails,
      violations: DEMO_FALLBACK.violations,
      demoMode: true,
      demoWarning: 'Backend unreachable. Showing demo-safe data.',
      lastAnalysisAt: Date.now(),
      lastScanTime: new Date().toLocaleTimeString(),
      dashboardCharts: DEMO_FALLBACK.dashboardCharts || null,
      dashboardVulns: DEMO_FALLBACK.dashboardVulns || null
    });
  }
}
