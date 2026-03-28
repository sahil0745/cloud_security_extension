import re

with open("c:/Users/Lenovo/Downloads/remix_-generated/extension/content/content.js", "r", encoding="utf-8") as f:
    content = f.read()

# Define the new CSS and HTML for injectCloudSecPanel
new_inject = """function injectCloudSecPanel() {
  if (document.getElementById('cloudsec-inline-panel-style')) return;

  const style = document.createElement('style');
  style.id = 'cloudsec-inline-panel-style';
  style.innerHTML = `
    #cloudsec-inline-panel {
      position: fixed;
      top: 20px;
      right: 20px;
      width: 400px;
      max-height: 90vh;
      overflow-y: auto;
      background: linear-gradient(180deg, rgba(15, 23, 42, 0.95), rgba(2, 6, 23, 0.98));
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid rgba(148,163,184,.15);
      border-radius: 16px;
      box-shadow: 0 20px 40px -10px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,.05) inset;
      z-index: 2147483647;
      color: #cbd5e1;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      transform: translateY(10px) scale(0.98);
      opacity: 0;
      pointer-events: none;
      transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    #cloudsec-inline-panel::-webkit-scrollbar { width: 6px; }
    #cloudsec-inline-panel::-webkit-scrollbar-thumb { background: rgba(148,163,184,.2); border-radius: 4px; }
    #cloudsec-inline-panel.visible {
      transform: translateY(0) scale(1);
      opacity: 1;
      pointer-events: auto;
    }
    #cloudsec-inline-panel .head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 20px 14px;
      border-bottom: 1px solid rgba(148,163,184,.1);
      background: rgba(30,30,30, 0.1);
    }
    #cloudsec-inline-panel .title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 20px;
      font-weight: 800;
      color: #f8fafc;
    }
    #cloudsec-inline-panel .shield {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      background: linear-gradient(180deg, #38bdf8, #2563eb);
      box-shadow: 0 0 12px rgba(56, 189, 248, .8);
    }
    #cloudsec-inline-panel .badge {
      font-size: 10px;
      font-weight: 700;
      color: #38bdf8;
      border: 1px solid rgba(56,189,248,.35);
      background: rgba(14,165,233,.14);
      border-radius: 999px;
      padding: 4px 8px;
      text-transform: uppercase;
    }
    #cloudsec-inline-panel .body {
      padding: 16px 20px;
    }
    #cloudsec-inline-panel .hero {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      border: 1px solid rgba(148,163,184,.15);
      border-radius: 12px;
      background: rgba(15, 23, 42, .4);
      margin-bottom: 16px;
    }
    #cloudsec-inline-panel .platform {
      font-size: 18px;
      font-weight: 800;
      color: #fff;
    }
    #cloudsec-inline-panel .pill {
      font-size: 10px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 999px;
      text-transform: uppercase;
      background: rgba(255,255,255,0.1);
      color: #fff;
    }
    #cloudsec-inline-panel .section-title {
      font-size: 12px;
      font-weight: 700;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin: 16px 0 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    #cloudsec-inline-panel .chart-card {
      background: rgba(15, 23, 42, .5);
      border: 1px solid rgba(148,163,184,.12);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 12px;
      position: relative;
    }
    #cloudsec-inline-panel .chart-value {
      font-size: 24px;
      font-weight: 800;
      color: #f8fafc;
      line-height: 1;
      margin-bottom: 10px;
    }
    #cloudsec-inline-panel svg {
      overflow: visible;
    }
    /* Grid for side-by-side charts */
    #cloudsec-inline-panel .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }
    #cloudsec-inline-panel .threat-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    #cloudsec-inline-panel .threat-item {
      background: rgba(15, 23, 42, .5);
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 10px;
      font-size: 11px;
    }
    #cloudsec-inline-panel .threat-item.high { border-left: 3px solid #f43f5e; }
    #cloudsec-inline-panel .threat-item.critical { border-left: 3px solid #e11d48; background: rgba(225,29,72,.05); }
    #cloudsec-inline-panel .threat-item.medium { border-left: 3px solid #f59e0b; }
    
    #cloudsec-inline-panel .btn-primary {
      width: 100%;
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      color: #fff;
      font-weight: 600;
      font-size: 13px;
      padding: 12px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      margin-top: 8px;
      transition: all 0.2s;
    }
    #cloudsec-inline-panel .btn-primary:hover {
      opacity: 0.9;
      transform: translateY(-1px);
    }
    #cloudsec-inline-panel .flex-col { display: flex; flex-direction: column; gap: 4px; }
    #cloudsec-inline-panel .flex-row { display: flex; align-items: center; justify-content: space-between; }
    #cloudsec-inline-panel .bar-bg { height: 6px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }
    #cloudsec-inline-panel .bar-fill { height: 100%; background: #3b82f6; border-radius: 4px; }
  `;

  document.documentElement.appendChild(style);

  cloudSecPanelRoot = document.createElement('div');
  cloudSecPanelRoot.id = 'cloudsec-inline-panel';
  cloudSecPanelRoot.innerHTML = `
    <div class="head">
      <div class="title"><span class="shield"></span>CloudSec <span class="badge">Monitoring</span></div>
      <button class="close" id="cloudsec-inline-panel-close" style="background:transparent;border:none;color:#94a3b8;cursor:pointer;font-size:18px;">&times;</button>
    </div>
    <div class="body" id="cloudsec-inline-panel-body">
      <div class="hero">
        <div>
          <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;margin-bottom:4px;font-weight:bold;">Active Environment</div>
          <div class="platform" id="csp-platform">--</div>
        </div>
        <div class="pill" id="csp-status" style="background:rgba(234,179,8,.2);color:#fde047;border:1px solid rgba(234,179,8,.4);">ANALYZING...</div>
      </div>

      <div class="chart-card">
        <div class="section-title" style="margin-top:0;">Risk Posture <span id="csp-score" style="color:#f8fafc;font-size:16px;">--</span></div>
        <div class="bar-bg" style="height:8px;"><div class="bar-fill" id="csp-meter" style="width:0%; transition: width 0.5s;"></div></div>
      </div>

      <div class="chart-card">
        <div class="section-title" style="margin-top:0;">24h Risk Trends</div>
        <div id="csp-sparkline" style="height:50px; width:100%; position:relative;"></div>
      </div>

      <div class="grid-2">
        <div class="chart-card" style="margin:0;">
          <div class="section-title" style="margin-top:0;">Attack Vectors</div>
          <div id="csp-attack-bars" class="flex-col" style="margin-top:10px;"></div>
        </div>
        <div class="chart-card" style="margin:0; text-align:center;">
          <div class="section-title" style="margin-top:0;">Severity</div>
          <div id="csp-severity-donut" style="margin-top:10px; display:flex; justify-content:center;"></div>
        </div>
      </div>

      <div class="section-title">Active Threats <span class="pill" id="csp-threat-count" style="background:#334155;">0</span></div>
      <div class="threat-list" id="csp-threats"></div>

      <button class="btn-primary" id="csp-report-btn">Generate Security Report</button>
      <div style="text-align:center; font-size:10px; color:#64748b; margin-top:12px;" id="csp-scan-time">Last scan: --:--</div>
    </div>
  `;

  document.documentElement.appendChild(cloudSecPanelRoot);

  cloudSecPanelRoot.querySelector('#cloudsec-inline-panel-close').addEventListener('click', () => {
    cloudSecPanelRoot.classList.remove('visible');
    cloudSecPanelVisible = false;
  });
  
  cloudSecPanelRoot.querySelector('#csp-report-btn').addEventListener('click', () => {
    window.open('http://localhost:3000', '_blank');
  });
}
"""

# Define the new update function
new_update = """function updateInlinePanelFromState(state = {}) {
  ensureCloudSecPanel();
  
  const platform = state.currentPlatform || lastDetectedPlatform || '--';
  const status = state.status || 'Analyzing...';
  const score = Number(state.riskScore ?? 0);
  const scan = state.lastScanTime || '--:--';
  const isDemo = state.demoMode || false;

  document.getElementById('csp-platform').textContent = platform + (isDemo ? ' (Offline Fallback)' : '');
  
  const statusEl = document.getElementById('csp-status');
  statusEl.textContent = status.toUpperCase();
  if (score >= 70) {
    statusEl.style.color = '#fda4af'; statusEl.style.borderColor = 'rgba(244,63,94,.4)'; statusEl.style.background = 'rgba(159,18,57,.2)';
  } else if (score >= 30) {
    statusEl.style.color = '#fde047'; statusEl.style.borderColor = 'rgba(250,204,21,.4)'; statusEl.style.background = 'rgba(161,98,7,.2)';
  } else {
    statusEl.style.color = '#86efac'; statusEl.style.borderColor = 'rgba(34,197,94,.4)'; statusEl.style.background = 'rgba(21,128,61,.2)';
  }

  document.getElementById('csp-score').textContent = score + '/100';
  document.getElementById('csp-meter').style.width = Math.min(100, Math.max(0, score)) + '%';
  document.getElementById('csp-meter').style.background = score >= 70 ? '#e11d48' : (score >= 30 ? '#d97706' : '#16a34a');
  document.getElementById('csp-scan-time').textContent = 'Last sync: ' + scan;

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
  const container = document.getElementById('csp-sparkline');
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
  const container = document.getElementById('csp-attack-bars');
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
  const container = document.getElementById('csp-severity-donut');
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
  const container = document.getElementById('csp-threats');
  const countEl = document.getElementById('csp-threat-count');
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
        <div style="font-weight:700; color:#e2e8f0; margin-bottom:2px;">${v.rule_id || 'UNKNOWN_RULE'}</div>
        <div style="color:#94a3b8; font-size:10px;">${v.resource || 'Global'}</div>
      </div>
    `;
  });
}
"""

# Regex replacements
content = re.sub(r"function injectCloudSecPanel\(\) \{[\s\S]*?(?=function showCloudActivationPopup)", new_inject + "\n\n", content)
content = re.sub(r"function updateInlinePanelFromState\(state = \{\}\) \{[\s\S]*?(?=function showCloudActivationPopup)", new_update + "\n\n", content)

with open("c:/Users/Lenovo/Downloads/remix_-generated/extension/content/content.js", "w", encoding="utf-8") as f:
    f.write(content)
