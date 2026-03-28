import re

with open("c:/Users/Lenovo/Downloads/remix_-generated/extension/content/content.js", "r", encoding="utf-8") as f:
    content = f.read()

new_ensure = """function ensureCloudSecPanel() {
  if (cloudSecPanelRoot) return;
  const style = document.createElement('style');
  style.id = 'cloudsec-inline-panel-style';
  style.innerHTML = `
    #cloudsec-inline-panel {
      position: fixed;
      top: 80px;
      right: 24px;
      width: 400px;
      max-height: calc(100vh - 100px);
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
    #cloudsec-inline-panel.visible { transform: translateY(0) scale(1); opacity: 1; pointer-events: auto; }
    #cloudsec-inline-panel .head {
      display: flex; align-items: center; justify-content: space-between;
      padding: 16px 20px 14px; border-bottom: 1px solid rgba(148,163,184,.1); background: rgba(30,30,30, 0.1);
    }
    #cloudsec-inline-panel .title { display: flex; align-items: center; gap: 10px; font-size: 20px; font-weight: 800; color: #f8fafc; }
    #cloudsec-inline-panel .shield {
      width: 12px; height: 12px; border-radius: 999px;
      background: linear-gradient(180deg, #38bdf8, #2563eb); box-shadow: 0 0 12px rgba(56, 189, 248, .8);
    }
    #cloudsec-inline-panel .badge {
      font-size: 10px; font-weight: 700; color: #38bdf8; border: 1px solid rgba(56,189,248,.35);
      background: rgba(14,165,233,.14); border-radius: 999px; padding: 4px 8px; text-transform: uppercase;
    }
    #cloudsec-inline-panel .body { padding: 16px 20px; }
    #cloudsec-inline-panel .hero {
      display: flex; justify-content: space-between; align-items: center; padding: 14px 16px;
      border: 1px solid rgba(148,163,184,.15); border-radius: 12px; background: rgba(15, 23, 42, .4); margin-bottom: 16px;
    }
    #cloudsec-inline-panel .platform { font-size: 18px; font-weight: 800; color: #fff; }
    #cloudsec-inline-panel .pill {
      font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 999px; text-transform: uppercase;
      background: rgba(255,255,255,0.1); color: #fff;
    }
    #cloudsec-inline-panel .section-title {
      font-size: 12px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px;
      margin: 16px 0 8px; display: flex; justify-content: space-between; align-items: center;
    }
    #cloudsec-inline-panel .chart-card {
      background: rgba(15, 23, 42, .5); border: 1px solid rgba(148,163,184,.12);
      border-radius: 12px; padding: 14px; margin-bottom: 12px; position: relative;
    }
    #cloudsec-inline-panel svg { overflow: visible; }
    #cloudsec-inline-panel .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
    #cloudsec-inline-panel .threat-list { display: flex; flex-direction: column; gap: 8px; }
    #cloudsec-inline-panel .threat-item {
      background: rgba(15, 23, 42, .5); border: 1px solid #334155; border-radius: 8px; padding: 10px; font-size: 11px;
    }
    #cloudsec-inline-panel .threat-item.high { border-left: 3px solid #f43f5e; }
    #cloudsec-inline-panel .threat-item.critical { border-left: 3px solid #e11d48; background: rgba(225,29,72,.05); }
    #cloudsec-inline-panel .threat-item.medium { border-left: 3px solid #f59e0b; }
    #cloudsec-inline-panel .btn-primary {
      width: 100%; background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff; font-weight: 600;
      font-size: 13px; padding: 12px; border: none; border-radius: 8px; cursor: pointer; margin-top: 8px; transition: all 0.2s;
    }
    #cloudsec-inline-panel .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
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

content = re.sub(r"function ensureCloudSecPanel\(\) \{[\s\S]*?(?=function riskClass)", new_ensure + "\n\n", content)

with open("c:/Users/Lenovo/Downloads/remix_-generated/extension/content/content.js", "w", encoding="utf-8") as f:
    f.write(content)
