// 2. Content Script Setup - Cloud Detection

let debounceTimer;
let lastDetectedPlatform = null;
let lastBannerKey = null;
let lastDetectionAnnounceAt = 0;
let cloudSecPanelRoot = null;
let cloudSecPanelBody = null;
let cloudSecPanelStatus = null;
let cloudSecPanelPlatform = null;
let cloudSecPanelRisk = null;
let cloudSecPanelMl = null;
let cloudSecPanelBehavior = null;
let cloudSecPanelScan = null;
let cloudSecPanelStatusChip = null;
let cloudSecPanelRiskFill = null;
let cloudSecPanelVisible = false;

const DETECTION_REANNOUNCE_MS = 12000;

function ensureCloudSecPanel() {
  if (cloudSecPanelRoot) return;
  const style = document.createElement('style');
  style.id = 'cloudsec-inline-panel-style';
  style.innerHTML = `
    @keyframes panelEntry {
      0% { transform: translateY(20px) scale(0.95); opacity: 0; filter: blur(10px); }
      100% { transform: translateY(0) scale(1); opacity: 1; filter: blur(0); }
    }
    @keyframes pulseGlow {
      0%, 100% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.4), inset 0 0 10px rgba(56, 189, 248, 0.2); }
      50% { box-shadow: 0 0 30px rgba(56, 189, 248, 0.8), inset 0 0 20px rgba(56, 189, 248, 0.5); }
    }
    @keyframes shimmer {
      0% { transform: translateX(-150%) skewX(-15deg); }
      100% { transform: translateX(250%) skewX(-15deg); }
    }
    @keyframes radarSpin {
      100% { transform: rotate(360deg); }
    }
    #cloudsec-inline-panel {
      position: fixed;
      top: 80px;
      right: 24px;
      width: 420px;
      max-height: calc(100vh - 100px);
      overflow-y: auto;
      background: linear-gradient(145deg, rgba(10, 15, 30, 0.95) 0%, rgba(2, 6, 20, 0.98) 100%);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 20px;
      box-shadow: 0 30px 60px -12px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.05) inset;
      z-index: 2147483647;
      color: #e2e8f0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      transform: translateY(20px) scale(0.95);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.4s cubic-bezier(0.16, 1, 0.3, 1), transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    #cloudsec-inline-panel::-webkit-scrollbar { width: 4px; }
    #cloudsec-inline-panel::-webkit-scrollbar-thumb { background: rgba(148,163,184,0.3); border-radius: 4px; }
    #cloudsec-inline-panel.visible { 
      transform: translateY(0) scale(1); 
      opacity: 1; 
      pointer-events: auto; 
    }
    
    #cloudsec-inline-panel .head {
      display: flex; align-items: center; justify-content: space-between;
      padding: 18px 24px; border-bottom: 1px solid rgba(255,255,255,0.08); 
      background: linear-gradient(90deg, rgba(56,189,248,0.05) 0%, transparent 100%);
      position: relative;
      overflow: hidden;
    }
    #cloudsec-inline-panel .head::before {
      content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
      background: linear-gradient(90deg, #38bdf8, #818cf8, #e879f9);
    }
    #cloudsec-inline-panel .title { display: flex; align-items: center; gap: 12px; font-size: 22px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
    #cloudsec-inline-panel .shield {
      width: 14px; height: 14px; border-radius: 50%;
      background: linear-gradient(180deg, #38bdf8, #2563eb); 
      animation: pulseGlow 3s infinite;
    }
    #cloudsec-inline-panel .badge {
      font-size: 10px; font-weight: 800; color: #fff; border: 1px solid rgba(255,255,255,0.2);
      background: rgba(255,255,255,0.1); border-radius: 6px; padding: 4px 8px; text-transform: uppercase;
      letter-spacing: 1px; backdrop-filter: blur(4px); box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    #cloudsec-inline-panel .body { padding: 20px 24px; }
    
    #cloudsec-inline-panel .hero {
      display: flex; justify-content: space-between; align-items: center; padding: 16px 20px;
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; margin-bottom: 20px;
      box-shadow: inset 0 2px 10px rgba(0,0,0,0.2);
    }
    #cloudsec-inline-panel .platform { font-size: 20px; font-weight: 800; color: #fff; background: linear-gradient(135deg, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    #cloudsec-inline-panel .pill {
      font-size: 11px; font-weight: 800; padding: 6px 12px; border-radius: 8px; text-transform: uppercase;
      letter-spacing: 0.5px; display: inline-flex; align-items: center; gap: 6px;
    }
    
    #cloudsec-inline-panel .section-title {
      font-size: 13px; font-weight: 700; color: #cbd5e1; text-transform: uppercase; letter-spacing: 1px;
      margin: 20px 0 12px; display: flex; justify-content: space-between; align-items: center;
    }
    
    #cloudsec-inline-panel .chart-card {
      background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
      border-radius: 16px; padding: 18px; margin-bottom: 16px; position: relative;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    #cloudsec-inline-panel .chart-card:hover {
      background: rgba(255,255,255,0.03); border-color: rgba(255,255,255,0.1);
      box-shadow: 0 10px 30px rgba(0,0,0,0.3); transform: translateY(-2px);
    }

    /* Premium Radar Feature */
    .radar-container {
      width: 100%; height: 120px; background: rgba(0,0,0,0.3); border-radius: 12px;
      border: 1px solid rgba(56, 189, 248, 0.2); position: relative; overflow: hidden;
      display: flex; align-items: center; justify-content: center; margin-bottom: 16px;
    }
    .radar {
      width: 100px; height: 100px; border-radius: 50%;
      border: 1px solid rgba(56, 189, 248, 0.3); position: relative;
    }
    .radar::before, .radar::after {
      content: ''; position: absolute; border: 1px solid rgba(56, 189, 248, 0.3);
      border-radius: 50%; top: 50%; left: 50%; transform: translate(-50%, -50%);
    }
    .radar::before { width: 60px; height: 60px; }
    .radar::after { width: 20px; height: 20px; background: rgba(56, 189, 248, 0.2); }
    .radar-sweep {
      position: absolute; top: 0; left: 50%; width: 50px; height: 50px;
      background: linear-gradient(90deg, rgba(56, 189, 248, 0.8), transparent);
      transform-origin: bottom left; border-radius: 100% 0 0 0;
      animation: radarSpin 2s linear infinite;
    }
    .radar-blip {
      position: absolute; width: 6px; height: 6px; background: #e11d48; border-radius: 50%;
      box-shadow: 0 0 10px #e11d48; top: 20px; left: 30px; animation: pulseGlow 1s infinite alternate;
    }
    .radar-overlay {
      position: absolute; top: 10px; left: 14px; font-size: 10px; color: #38bdf8; font-family: monospace;
      text-transform: uppercase; font-weight: bold; pointer-events: none;
    }

    #cloudsec-inline-panel svg { overflow: visible; }
    #cloudsec-inline-panel .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    #cloudsec-inline-panel .threat-list { display: flex; flex-direction: column; gap: 10px; }
    #cloudsec-inline-panel .threat-item {
      background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); 
      border-radius: 12px; padding: 14px; font-size: 12px; position: relative; overflow: hidden;
      transition: all 0.2s;
    }
    #cloudsec-inline-panel .threat-item:hover { background: rgba(255,255,255,0.05); }
    #cloudsec-inline-panel .threat-item::before {
      content: ''; position: absolute; left: 0; top: 0; height: 100%; width: 4px;
    }
    #cloudsec-inline-panel .threat-item.high::before { background: #f43f5e; box-shadow: 0 0 10px #f43f5e; }
    #cloudsec-inline-panel .threat-item.critical::before { background: #e11d48; box-shadow: 0 0 15px #e11d48; }
    #cloudsec-inline-panel .threat-item.critical { background: rgba(225,29,72,.08); border-color: rgba(225,29,72,.2); }
    #cloudsec-inline-panel .threat-item.medium::before { background: #f59e0b; box-shadow: 0 0 10px #f59e0b; }
    
    #cloudsec-inline-panel .btn-primary {
      width: 100%; 
      background: linear-gradient(135deg, #2563eb, #4f46e5); 
      color: #fff; font-weight: 700; font-size: 14px; padding: 16px; 
      border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; cursor: pointer; 
      margin-top: 16px; transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative; overflow: hidden; box-shadow: 0 10px 20px rgba(37,99,235,0.3);
      text-transform: uppercase; letter-spacing: 1px;
    }
    #cloudsec-inline-panel .btn-primary::after {
      content: ''; position: absolute; top: 0; left: 0; width: 50%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
      animation: shimmer 3s infinite;
    }
    #cloudsec-inline-panel .btn-primary:hover { 
      transform: translateY(-2px); box-shadow: 0 15px 25px rgba(37,99,235,0.5); 
      background: linear-gradient(135deg, #3b82f6, #6366f1);
    }
    
    /* Toggle Switch */
    .premium-toggle-container {
      display: flex; justify-content: space-between; align-items: center; 
      padding: 12px 16px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2);
      border-radius: 12px; margin-bottom: 20px;
    }
    .toggle-label { font-size: 13px; font-weight: 700; color: #10b981; display: flex; align-items: center; gap: 8px;}
    .toggle-switch {
      position: relative; width: 44px; height: 24px; background: #10b981; border-radius: 12px;
      box-shadow: inset 0 2px 4px rgba(0,0,0,0.3); cursor: pointer;
    }
    .toggle-switch::after {
      content: ''; position: absolute; top: 2px; left: 22px; width: 20px; height: 20px;
      background: #fff; border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.3); transition: all 0.3s;
    }

    #cloudsec-inline-panel .flex-col { display: flex; flex-direction: column; gap: 6px; }
    #cloudsec-inline-panel .flex-row { display: flex; align-items: center; justify-content: space-between; }
    #cloudsec-inline-panel .bar-bg { height: 8px; background: rgba(0,0,0,0.4); border-radius: 4px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.5); }
    #cloudsec-inline-panel .bar-fill { height: 100%; background: linear-gradient(90deg, #3b82f6, #8b5cf6); border-radius: 4px; position: relative; }
    #cloudsec-inline-panel .bar-fill::after {
      content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
      animation: shimmer 2s infinite;
    }
  `;
  document.documentElement.appendChild(style);

  cloudSecPanelRoot = document.createElement('div');
  cloudSecPanelRoot.id = 'cloudsec-inline-panel';
  cloudSecPanelRoot.innerHTML = `
    <div class="head">
      <div class="title"><span class="shield"></span>CloudSec <span class="badge">Enterprise</span></div>
      <button class="close" id="cloudsec-inline-panel-close" style="background:transparent;border:none;color:#94a3b8;cursor:pointer;font-size:24px;line-height:1;transition:color 0.2s;">&times;</button>
    </div>
    <div class="body" id="cloudsec-inline-panel-body">
      
      <!-- Premium Auto-Remediation Toggle -->
      <div class="premium-toggle-container">
        <div class="toggle-label">
           <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
           Auto-Remediation Active
        </div>
        <div class="toggle-switch" onclick="this.style.background=this.style.background==='rgb(51, 65, 85)'?'#10b981':'#334155'; this.children[0].style.left=this.style.background==='rgb(51, 65, 85)'?'2px':'22px';"><div style="position:absolute;top:2px;left:22px;width:20px;height:20px;background:#fff;border-radius:50%;transition:left 0.3s;"></div></div>
      </div>

      <div class="hero">
        <div>
          <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;font-weight:800;letter-spacing:1px;">Active Environment</div>
          <div class="platform" id="csp-platform">--</div>
        </div>
        <div class="pill" id="csp-status" style="background:rgba(234,179,8,.2);color:#fde047;border:1px solid rgba(234,179,8,.4);box-shadow:0 0 15px rgba(234,179,8,0.2);">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="margin-right: -2px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
          <span id="csp-status-text">ANALYZING...</span>
        </div>
      </div>

      <!-- AI Threat Radar (New Premium Feature) -->
      <div class="radar-container" id="csp-radar-container">
        <div class="radar-overlay">LIVE AI THREAT RADAR // DEEP SCAN MODE</div>
        <div class="radar">
           <div class="radar-sweep"></div>
           <div class="radar-blip"></div>
        </div>
      </div>

      <div class="chart-card">
        <div class="section-title" style="margin-top:0;">Risk Posture <span id="csp-score" style="color:#f8fafc;font-size:18px;font-weight:800;text-shadow:0 0 10px rgba(255,255,255,0.3);">--</span></div>
        <div class="bar-bg" style="height:10px;"><div class="bar-fill" id="csp-meter" style="width:0%; transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1);"></div></div>
      </div>

      <div class="chart-card">
        <div class="section-title" style="margin-top:0;">24h Risk Trends</div>
        <div id="csp-sparkline" style="height:60px; width:100%; position:relative;"></div>
      </div>

      <div class="grid-2">
        <div class="chart-card" style="margin:0;">
          <div class="section-title" style="margin-top:0;font-size:11px;">Attack Vectors</div>
          <div id="csp-attack-bars" class="flex-col" style="margin-top:12px;"></div>
        </div>
        <div class="chart-card" style="margin:0; text-align:center; display:flex; flex-direction:column;">
          <div class="section-title" style="margin-top:0;font-size:11px;justify-content:center;">Threat Severity</div>
          <div id="csp-severity-donut" style="margin-top:auto; margin-bottom:auto; display:flex; justify-content:center; filter: drop-shadow(0 0 10px rgba(0,0,0,0.5));"></div>
        </div>
      </div>

      <div class="section-title" style="border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px;">
        Active Threats <span class="pill" id="csp-threat-count" style="background:rgba(225,29,72,0.2);color:#fb7185;border:1px solid rgba(225,29,72,0.4);border-radius:12px;">0</span>
      </div>
      <div class="threat-list" id="csp-threats"></div>

      <button class="btn-primary" id="csp-report-btn">Generate Security Report</button>
      <div style="text-align:center; font-size:11px; color:#64748b; margin-top:16px; font-family:monospace; letter-spacing:0.5px;" id="csp-scan-time">Last scan: --:--</div>
    </div>
  `;
  document.documentElement.appendChild(cloudSecPanelRoot);

  cloudSecPanelRoot.querySelector('#cloudsec-inline-panel-close').addEventListener('click', () => {
    cloudSecPanelRoot.classList.remove('visible');
    cloudSecPanelVisible = false;
  });
  
  cloudSecPanelRoot.querySelector('#cloudsec-inline-panel-close').addEventListener('mouseover', function() {
    this.style.color = '#fff';
  });
  cloudSecPanelRoot.querySelector('#cloudsec-inline-panel-close').addEventListener('mouseout', function() {
    this.style.color = '#94a3b8';
  });
  
  cloudSecPanelRoot.querySelector('#csp-report-btn').addEventListener('click', () => {
    window.open('http://localhost:3000', '_blank');
  });
}


function riskClass(score) {
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function panelStatusClass(status, score) {
  const normalized = String(status || '').toLowerCase();
  if (normalized.includes('critical') || score >= 70) return 'high';
  if (normalized.includes('risk') || normalized.includes('warning') || score >= 30) return 'medium';
  return 'low';
}

function updateInlinePanelFromState(state = {}) {
  // Prevent cross-tab data leakage: only accept updates for the active platform in this tab
  if (state.currentPlatform && lastDetectedPlatform && state.currentPlatform !== lastDetectedPlatform) {
    return;
  }
  
  ensureCloudSecPanel();
  
  const platform = state.currentPlatform || lastDetectedPlatform || '--';
  const status = state.status || 'Analyzing...';
  const score = Number(state.riskScore ?? 0);
  const scan = state.lastScanTime || '--:--';
  const isDemo = state.demoMode || false;

  cloudSecPanelRoot.querySelector('#csp-platform').textContent = platform + (isDemo ? ' (Offline Fallback)' : '');
  
  const statusEl = cloudSecPanelRoot.querySelector('#csp-status');
  const statusTextEl = cloudSecPanelRoot.querySelector('#csp-status-text');
  if (statusTextEl) statusTextEl.textContent = status.toUpperCase();
  if (score >= 70) {
    statusEl.style.color = '#fda4af'; statusEl.style.borderColor = 'rgba(244,63,94,.4)'; statusEl.style.background = 'rgba(159,18,57,.2)';
  } else if (score >= 30) {
    statusEl.style.color = '#fde047'; statusEl.style.borderColor = 'rgba(250,204,21,.4)'; statusEl.style.background = 'rgba(161,98,7,.2)';
  } else {
    statusEl.style.color = '#86efac'; statusEl.style.borderColor = 'rgba(34,197,94,.4)'; statusEl.style.background = 'rgba(21,128,61,.2)';
  }

  cloudSecPanelRoot.querySelector('#csp-score').textContent = score + '/100';
  cloudSecPanelRoot.querySelector('#csp-meter').style.width = Math.min(100, Math.max(0, score)) + '%';
  cloudSecPanelRoot.querySelector('#csp-meter').style.background = score >= 70 ? '#e11d48' : (score >= 30 ? '#d97706' : '#16a34a');
  cloudSecPanelRoot.querySelector('#csp-scan-time').textContent = 'Last sync: ' + scan;

  // Render Charts if data is available
  if (state.dashboardCharts) {
    renderSparkline(state.dashboardCharts.riskTrend || []);
    renderAttackBars(state.dashboardCharts.attackVectors || []);
    renderSeverityDonut(state.dashboardCharts.severityDistribution || []);
  }
  
  // Render Threats
  if (state.dashboardVulns) {
    renderThreats(state.dashboardVulns);
  }

  if (!cloudSecPanelVisible) {
    cloudSecPanelRoot.classList.add('visible');
    cloudSecPanelVisible = true;
  }
}

// SVG Graphing Helpers
function renderSparkline(data) {
  const container = cloudSecPanelRoot.querySelector('#csp-sparkline');
  container.innerHTML = '';
  if (!data || data.length === 0) return;
  
  const width = container.clientWidth || 320;
  const height = 50;
  const maxRisk = Math.max(...data.map(d => Number(d.risk) || 0), 100);
  const minRisk = 0;
  
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - (((Number(d.risk)||0) - minRisk) / (maxRisk - minRisk) * height);
    return `${x},${y}`;
  });
  
  const svg = `
    <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="lineGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.5"/>
          <stop offset="100%" stop-color="#3b82f6" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <polyline points="${pts.join(' ')}" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <polygon points="0,${height} ${pts.join(' ')} ${width},${height}" fill="url(#lineGrad)"/>
    </svg>
  `;
  container.innerHTML = svg;
}

function renderAttackBars(data) {
  const container = cloudSecPanelRoot.querySelector('#csp-attack-bars');
  container.innerHTML = '';
  if (!data || data.length === 0) return;
  
  const max = Math.max(...data.map(d => d.count), 1);
  const top3 = data.slice(0, 3);
  
  top3.forEach(item => {
    const pct = (item.count / max) * 100;
    container.innerHTML += `
      <div style="margin-bottom:4px;">
        <div class="flex-row" style="font-size:10px; color:#cbd5e1; margin-bottom:2px;">
          <span style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:80px;">${item.name}</span>
          <span>${item.count}</span>
        </div>
        <div class="bar-bg" style="height:4px;"><div class="bar-fill" style="width:${pct}%; background:#8b5cf6;"></div></div>
      </div>
    `;
  });
}

function renderSeverityDonut(data) {
  const container = cloudSecPanelRoot.querySelector('#csp-severity-donut');
  container.innerHTML = '';
  if (!data || data.length === 0) return;
  
  const total = data.reduce((sum, item) => sum + (item.value||0), 0);
  if (total === 0) {
    container.innerHTML = '<span style="font-size:10px;color:#64748b;">No Events</span>';
    return;
  }
  
  let cumulative = 0;
  const segments = data.map(item => {
    const val = item.value || 0;
    const pct = val / total;
    const offset = cumulative;
    cumulative += pct;
    let color = '#3b82f6';
    if(item.name.includes('CRITICAL')) color = '#e11d48';
    else if(item.name.includes('HIGH')) color = '#f43f5e';
    else if(item.name.includes('MEDIUM')) color = '#f59e0b';
    else color = '#22c55e';
    
    return `<circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="${color}" stroke-width="5" stroke-dasharray="${pct * 100} ${100 - (pct * 100)}" stroke-dashoffset="${25 - (offset * 100)}"></circle>`;
  });

  const svg = `
    <div style="position:relative; width:48px; height:48px;">
      <svg width="100%" height="100%" viewBox="0 0 42 42">
        <circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="rgba(255,255,255,0.05)" stroke-width="5"></circle>
        ${segments.join('')}
      </svg>
      <div style="position:absolute; top:0; left:0; width:100%; height:100%; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:800; color:#fff;">${total}</div>
    </div>
  `;
  container.innerHTML = svg;
}

function renderThreats(vulns) {
  const container = cloudSecPanelRoot.querySelector('#csp-threats');
  const countEl = cloudSecPanelRoot.querySelector('#csp-threat-count');
  container.innerHTML = '';
  
  if (!vulns || vulns.length === 0) {
    countEl.textContent = '0';
    container.innerHTML = '<div style="font-size:11px; color:#64748b; padding:10px; text-align:center;">No active threats detected.</div>';
    return;
  }
  
  countEl.textContent = vulns.length;
  // Show top 3
  vulns.slice(0, 3).forEach(v => {
    const sevClass = (v.severity || 'low').toLowerCase();
    container.innerHTML += `
      <div class="threat-item ${sevClass}">
        <div style="font-weight:700; color:#e2e8f0; margin-bottom:2px;">${v.title || v.rule_id || 'UNKNOWN_RULE'}</div>
        <div style="color:#94a3b8; font-size:10px;">${v.resource || 'Global'}</div>
      </div>
    `;
  });
}


function showCloudActivationPopup(platform) {
  if (!platform) return;

  const bannerKey = `${platform}:${location.hostname}`;
  if (bannerKey === lastBannerKey) {
    return;
  }
  lastBannerKey = bannerKey;

  const existing = document.getElementById('cloudsec-auto-activation-banner');
  if (existing) {
    existing.remove();
  }

  const banner = document.createElement('div');
  banner.id = 'cloudsec-auto-activation-banner';
  banner.style.position = 'fixed';
  banner.style.top = '16px';
  banner.style.right = '16px';
  banner.style.zIndex = '2147483647';
  banner.style.maxWidth = '360px';
  banner.style.background = 'linear-gradient(135deg, #0f172a, #1e293b)';
  banner.style.color = '#e2e8f0';
  banner.style.border = '1px solid #334155';
  banner.style.borderRadius = '12px';
  banner.style.padding = '12px 14px';
  banner.style.boxShadow = '0 10px 30px rgba(2,6,23,.35)';
  banner.style.fontFamily = 'Segoe UI, Tahoma, sans-serif';
  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px;">
      <div style="font-size:18px;line-height:1;">Shield</div>
      <div style="flex:1;">
        <div style="font-size:13px;font-weight:700;letter-spacing:.2px;">CloudSec Copilot Activated</div>
        <div style="font-size:12px;opacity:.9;margin-top:4px;">${platform} detected. Monitoring started automatically.</div>
      </div>
      <button id="cloudsec-auto-activation-close" style="background:transparent;border:none;color:#94a3b8;font-size:16px;cursor:pointer;line-height:1;">x</button>
    </div>
  `;

  document.documentElement.appendChild(banner);
  const closeBtn = banner.querySelector('#cloudsec-auto-activation-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => banner.remove());
  }

  setTimeout(() => {
    banner.remove();
  }, 6500);
}

function detectPlatformFromUrl(url) {
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

  return null;
}

function detectPlatformFromPageContext() {
  const title = (document.title || '').toLowerCase();
  const host = (location.hostname || '').toLowerCase();

  if (title.includes('azure') && (host.includes('microsoft') || host.includes('azure'))) {
    return 'Azure';
  }
  if ((title.includes('aws') || title.includes('amazon web services')) && host.includes('amazon')) {
    return 'AWS';
  }
  if (title.includes('google cloud') || (title.includes('gcp') && host.includes('google'))) {
    return 'GCP';
  }

  return null;
}

function notifyCloudDetected(platform, retries = 2) {
  chrome.runtime.sendMessage(
    {
      type: 'CLOUD_DETECTED',
      platform,
    },
    (response) => {
      const failed = chrome.runtime.lastError || !response?.success;
      if (failed && retries > 0) {
        setTimeout(() => notifyCloudDetected(platform, retries - 1), 500);
      }
    }
  );
}

function shouldAnnouncePlatform(platform) {
  const now = Date.now();
  if (platform !== lastDetectedPlatform) {
    return true;
  }
  return now - lastDetectionAnnounceAt >= DETECTION_REANNOUNCE_MS;
}

// Function to detect cloud platform based on URL
function detectCloudPlatform() {
  clearTimeout(debounceTimer);
  
  debounceTimer = setTimeout(() => {
    const url = window.location.href;
    const platform = detectPlatformFromUrl(url) || detectPlatformFromPageContext();

    if (platform && shouldAnnouncePlatform(platform)) {
      lastDetectedPlatform = platform;
      lastDetectionAnnounceAt = Date.now();

      showCloudActivationPopup(platform);
      updateInlinePanelFromState({ currentPlatform: platform, status: 'Analyzing...', riskScore: 0 });
      notifyCloudDetected(platform);
    }
  }, 1000); // 1-second debounce to prevent spam on rapid redirects
}

// Run detection on initial load
detectCloudPlatform();

// Set up a MutationObserver to handle SPA (Single Page Application) navigations
// Cloud consoles often change URLs without full page reloads
let lastUrl = location.href; 
new MutationObserver(() => {
  const url = location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    detectCloudPlatform();
  }
}).observe(document, { subtree: true, childList: true });

window.addEventListener('popstate', detectCloudPlatform);
window.addEventListener('hashchange', detectCloudPlatform);
window.addEventListener('focus', detectCloudPlatform);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    detectCloudPlatform();
  }
});

setInterval(() => {
  detectCloudPlatform();
}, DETECTION_REANNOUNCE_MS);

function isCurrentPageCloudPlatform() {
  const url = window.location.href;
  return !!(detectPlatformFromUrl(url) || detectPlatformFromPageContext());
}

chrome.storage.local.get([
  'currentPlatform',
  'status',
  'riskScore',
  'mlPrediction',
  'behaviorAnalysis',
  'lastScanTime',
  'dashboardCharts',
  'dashboardVulns'
], (res) => {
  if (isCurrentPageCloudPlatform()) {
    if (res && res.currentPlatform && res.currentPlatform !== lastDetectedPlatform) return;
    updateInlinePanelFromState(res || {});
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (!isCurrentPageCloudPlatform()) return;
  
  const relevant = ['currentPlatform', 'status', 'riskScore', 'mlPrediction', 'behaviorAnalysis', 'lastScanTime', 'dashboardCharts', 'dashboardVulns'];
  const hasRelevant = relevant.some((key) => key in changes);
  if (!hasRelevant) return;

  chrome.storage.local.get(relevant, (res) => {
    updateInlinePanelFromState(res || {});
  });
});

const originalPushState = history.pushState;
history.pushState = function (...args) {
  const result = originalPushState.apply(this, args);
  detectCloudPlatform();
  return result;
};

const originalReplaceState = history.replaceState;
history.replaceState = function (...args) {
  const result = originalReplaceState.apply(this, args);
  detectCloudPlatform();
  return result;
};

// Listen for manual scan requests from background or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'SCAN_PAGE') {
    const elementsFound = document.querySelectorAll('*').length;
    sendResponse({ 
      scanned: true, 
      elementsFound: elementsFound,
      url: window.location.href,
      platform: lastDetectedPlatform
    });
  }
});
