document.addEventListener('DOMContentLoaded', async () => {
  const toast = document.getElementById('toast');
  const warningBanner = document.getElementById('warningBanner');

  const monitorBtn = document.getElementById('monitorBtn');
  const btnText = monitorBtn.querySelector('.btn-text');
  const btnSpinner = document.getElementById('btnSpinner');
  
  const scoreSection = document.getElementById('scoreSection');
  const progressSection = document.getElementById('progressSection');
  const baselineSection = document.getElementById('baselineSection');
  
  const scoreCircle = document.getElementById('scoreCircle');
  const scoreText = document.getElementById('scoreText');
  const statusText = document.getElementById('statusText');
  const statusIndicator = document.getElementById('statusIndicator');
  const themeToggle = document.getElementById('themeToggle');
  
  const platformBadge = document.getElementById('platformBadge');
  const platformIconContainer = document.querySelector('.platform-icon-container');
  const platformIcon = document.getElementById('platformIcon');
  const platformName = document.getElementById('platformName');
  const platformIndicator = document.getElementById('platformIndicator');
  
  const progressStatusText = document.getElementById('progressStatusText');
  const progressPercentage = document.getElementById('progressPercentage');
  const progressBar = document.getElementById('progressBar');
  
  const baselineStatus = document.getElementById('baselineStatus');
  const lastScanTime = document.getElementById('lastScanTime');
  const driftContainer = document.getElementById('driftContainer');
  const driftList = document.getElementById('driftList');
  const violationsContainer = document.getElementById('violationsContainer');
  const violationsList = document.getElementById('violationsList');
  
  const detectSound = document.getElementById('detectSound');
  const iconMap = {
    AWS: chrome.runtime.getURL('assets/icons/aws.png'),
    Azure: chrome.runtime.getURL('assets/icons/azure.png'),
    GCP: chrome.runtime.getURL('assets/icons/gcp.png'),
  };
  
  let isMonitoring = false;
  let currentPlatform = null;
  let playedSoundForPlatform = null;
  let lastPlayedDetectionTime = 0;
  let toastTimer = null;

  const sendRuntimeMessage = (message) =>
    new Promise((resolve) => chrome.runtime.sendMessage(message, (response) => resolve(response || {})));

  const showWarning = (message) => {
    if (!message) {
      warningBanner.textContent = '';
      warningBanner.classList.add('hidden');
      return;
    }
    warningBanner.textContent = message;
    warningBanner.classList.remove('hidden');
  };

  const verifyBackendConnectivity = async (baseUrl) => {
    const base = (baseUrl || 'http://localhost:8000').replace(/\/$/, '');
    try {
      const res = await fetch(`${base}/health`, { method: 'GET' });
      if (res.ok) {
        chrome.storage.local.set({ demoWarning: null, demoMode: false });
        showWarning('');
      }
    } catch (error) {
      // Keep existing warning state if backend remains unavailable.
    }
  };

  const showToast = (message, type = 'success') => {
    if (!toast) {
      return;
    }
    if (toastTimer) {
      clearTimeout(toastTimer);
      toastTimer = null;
    }
    toast.textContent = message;
    toast.classList.remove('hidden', 'success', 'error', 'warning');
    toast.classList.add('visible', type);
    toastTimer = setTimeout(() => {
      toast.classList.remove('visible');
      setTimeout(() => toast.classList.add('hidden'), 220);
    }, 2200);
  };

  function detectPlatformFromUrl(url) {
    if (!url) return null;
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const pathname = (parsed.pathname || '').toLowerCase();
      if (hostname.endsWith('.aws.amazon.com') || hostname === 'aws.amazon.com' || hostname === 'console.aws.amazon.com') return 'AWS';
      if ((hostname.endsWith('.amazon.com') || hostname === 'amazon.com') && pathname.includes('/aws')) return 'AWS';
      if (hostname === 'portal.azure.com' || hostname === 'azure.microsoft.com' || hostname.endsWith('.azure.com') || hostname.endsWith('.azure.microsoft.com')) return 'Azure';
      if ((hostname.endsWith('.microsoft.com') || hostname === 'microsoft.com') && pathname.includes('/azure')) return 'Azure';
      if (hostname === 'cloud.google.com' || hostname.endsWith('.cloud.google.com') || hostname === 'console.cloud.google.com') return 'GCP';
      if (hostname.endsWith('.google.com') && (pathname.includes('/cloud') || pathname.includes('/gcp'))) return 'GCP';
    } catch { }
    return null;
  }

  // Initialize state from storage
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentTab = tabs[0];
    const platform = currentTab ? detectPlatformFromUrl(currentTab.url) : null;

    chrome.storage.local.get([
      'isMonitoring', 'riskScore', 'status', 'theme', 'currentPlatform',
      'baselineStatus', 'driftDetails', 'lastScanTime', 'violations', 'mlPrediction', 'behaviorAnalysis',
      'lastDetectionTime', 'lastSoundedDetectionTime', 'demoWarning', 'apiBaseUrl'
    ], (result) => {
      if (result.theme === 'light') {
        document.body.classList.replace('dark-theme', 'light-theme');
      }

      if (!platform) {
        showWarning('Please navigate to a supported Cloud Platform (AWS, GCP, Azure) to use CloudSec Copilot.');
        monitorBtn.disabled = true;
        monitorBtn.style.opacity = '0.5';
        return;
      }
      
      lastPlayedDetectionTime = result.lastSoundedDetectionTime || 0;

      if (result.currentPlatform) {
        updatePlatformBadge(result.currentPlatform, result.lastDetectionTime || 0);
      }

      showWarning(result.demoWarning || '');
      void verifyBackendConnectivity(result.apiBaseUrl || 'http://localhost:8000');

      if (result.isMonitoring) {
        setMonitoringState(true);
        if (result.status === 'Analyzing') {
          startProgressAnimation();
        } else {
          updateScore(result.riskScore || 0, result.status || 'Safe');
          updateBaselineUI(result.baselineStatus, result.lastScanTime, result.driftDetails, result.violations);
          updateMLUI(result.mlPrediction);
          updateBehaviorUI(result.behaviorAnalysis);
        }
      }
    });
  });

  // Listen for real-time updates from background script
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local') {
      if (changes.demoWarning) {
        showWarning(changes.demoWarning.newValue || '');
      }

      if (changes.currentPlatform && changes.currentPlatform.newValue) {
        const detectionTime = changes.lastDetectionTime ? changes.lastDetectionTime.newValue : 0;
        updatePlatformBadge(changes.currentPlatform.newValue, detectionTime);
      }

      if (changes.lastDetectionTime && currentPlatform) {
        updatePlatformBadge(currentPlatform, changes.lastDetectionTime.newValue || 0);
      }
      
      if (changes.status) {
        if (changes.status.newValue === 'Analyzing') {
          startProgressAnimation();
        } else if (changes.status.newValue !== 'Analyzing' && isMonitoring) {
          // Analysis finished
          chrome.storage.local.get(['riskScore', 'baselineStatus', 'lastScanTime', 'driftDetails', 'violations', 'mlPrediction', 'behaviorAnalysis'], (res) => {
            updateScore(res.riskScore || 0, changes.status.newValue);
            updateBaselineUI(res.baselineStatus, res.lastScanTime, res.driftDetails, res.violations);
            updateMLUI(res.mlPrediction);
            updateBehaviorUI(res.behaviorAnalysis);
          });
        }
      }
      
      if (changes.isMonitoring) {
        setMonitoringState(changes.isMonitoring.newValue);
        if (!changes.isMonitoring.newValue) {
          updateScore(0, 'Safe');
          hidePlatformBadge();
          baselineSection.classList.add('hidden');
          document.getElementById('mlSection').classList.add('hidden');
          document.getElementById('behaviorSection').classList.add('hidden');
        }
      }
    }
  });

  // Theme Toggle with micro-interaction
  themeToggle.addEventListener('click', () => {
    const isDark = document.body.classList.contains('dark-theme');
    if (isDark) {
      document.body.classList.replace('dark-theme', 'light-theme');
      chrome.storage.local.set({ theme: 'light' });
    } else {
      document.body.classList.replace('light-theme', 'dark-theme');
      chrome.storage.local.set({ theme: 'dark' });
    }
    
    themeToggle.style.transform = 'scale(0.9)';
    setTimeout(() => {
      themeToggle.style.transform = 'scale(1)';
    }, 100);
  });

  // Monitor Button Click (Manual Override)
  monitorBtn.addEventListener('click', async () => {
    if (isMonitoring) {
      // Stop Monitoring
      chrome.runtime.sendMessage({ type: 'STOP_MONITORING' });
      showToast('Monitoring stopped.', 'warning');
    } else {
      // Start Monitoring
      btnText.textContent = 'Initializing...';
      btnSpinner.classList.remove('hidden');
      chrome.runtime.sendMessage({ type: 'START_MONITORING' });
      showToast('Monitoring started.', 'success');
    }
  });

  function updatePlatformBadge(platform, detectionTime = 0) {
    currentPlatform = platform;
    platformName.textContent = platform;
    
    // Set icon source
    const iconPath = iconMap[platform];
    platformIcon.src = iconPath || '';
    platformIcon.style.display = 'block';
    
    platformIconContainer.classList.remove('icon-enter', 'icon-glow');
    void platformIconContainer.offsetWidth;
    platformIconContainer.classList.add('icon-enter', 'icon-glow');
    setTimeout(() => platformIconContainer.classList.remove('icon-enter'), 320);
    
    platformBadge.classList.remove('hidden');
    
    // Play sound once per real detection event.
    const shouldPlayForDetection = detectionTime > 0 && detectionTime !== lastPlayedDetectionTime;
    if (shouldPlayForDetection || playedSoundForPlatform !== platform) {
      playSound();
      playedSoundForPlatform = platform;
      if (detectionTime > 0) {
        lastPlayedDetectionTime = detectionTime;
        chrome.storage.local.set({ lastSoundedDetectionTime: detectionTime });
      }
    }
  }

  function hidePlatformBadge() {
    currentPlatform = null;
    platformBadge.classList.add('hidden');
    playedSoundForPlatform = null;
  }

  function playSound() {
    try {
      detectSound.currentTime = 0;
      detectSound.play().catch(e => {
        console.warn('Audio play prevented by browser policy or missing file:', e);
      });
    } catch (e) {
      console.warn('Audio element error:', e);
    }
  }

  function setMonitoringState(active) {
    isMonitoring = active;
    if (active) {
      monitorBtn.classList.add('monitoring');
      btnText.textContent = 'Stop Monitoring';
      btnSpinner.classList.add('hidden');
    } else {
      monitorBtn.classList.remove('monitoring');
      btnText.textContent = 'Start Monitoring';
      btnSpinner.classList.add('hidden');
      scoreSection.classList.remove('hidden');
      progressSection.classList.add('hidden');
      baselineSection.classList.add('hidden');
    }
  }

  function startProgressAnimation() {
    scoreSection.classList.add('hidden');
    baselineSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    
    statusText.textContent = 'Analyzing';
    updateStatusColors('analyzing');
    
    let progress = 0;
    progressStatusText.textContent = 'Connecting...';
    progressBar.style.width = '0%';
    progressPercentage.textContent = '0%';
    
    const interval = setInterval(() => {
      progress += Math.floor(Math.random() * 5) + 2; // Random increment
      
      if (progress >= 30 && progress < 50) {
        progressStatusText.textContent = 'Fetching Cloud Config...';
      } else if (progress >= 50 && progress < 80) {
        progressStatusText.textContent = 'Comparing to Baseline...';
      } else if (progress >= 80 && progress < 100) {
        progressStatusText.textContent = 'Evaluating Risk...';
      }
      
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        progressStatusText.textContent = 'Monitoring Active';
        
        // The background script will update the status to Risk/Safe/Warning,
        // which will trigger the storage listener to show the score section.
      }
      
      progressBar.style.width = `${progress}%`;
      progressPercentage.textContent = `${progress}%`;
    }, 100);
  }

  function updateScore(score, status) {
    // Hide progress, show score
    progressSection.classList.add('hidden');
    scoreSection.classList.remove('hidden');

    // Animate score number
    let currentScore = parseInt(scoreText.textContent) || 0;
    const duration = 1000;
    const steps = 20;
    const stepTime = duration / steps;
    const increment = (score - currentScore) / steps;
    
    let step = 0;
    const timer = setInterval(() => {
      step++;
      currentScore += increment;
      scoreText.textContent = Math.round(currentScore);
      if (step >= steps) {
        clearInterval(timer);
        scoreText.textContent = score;
      }
    }, stepTime);

    // Update SVG Circle Dasharray
    scoreCircle.setAttribute('stroke-dasharray', `${score}, 100`);
    statusText.textContent = status;
    
    updateStatusColors(status.toLowerCase());
  }

  function updateBaselineUI(status, time, drift, violations) {
    baselineSection.classList.remove('hidden');
    
    baselineStatus.textContent = status || 'None';
    lastScanTime.textContent = time || '--:--';
    
    baselineStatus.className = 'baseline-value';
    if (status === 'Created' || status === 'Verified') {
      baselineStatus.classList.add('created');
    } else if (status === 'Drift Detected' || status === 'Violations Found') {
      baselineStatus.classList.add('drift');
    }
    
    if (drift && drift.length > 0) {
      driftContainer.classList.remove('hidden');
      driftList.innerHTML = '';
      
      // Show up to 3 changes to save space
      const displayDrift = drift.slice(0, 3);
      displayDrift.forEach(change => {
        const li = document.createElement('li');
        const fieldName = change.field.split('.').pop();
        li.textContent = `${fieldName} was ${change.type}`;
        driftList.appendChild(li);
      });
      
      if (drift.length > 3) {
        const li = document.createElement('li');
        li.textContent = `+ ${drift.length - 3} more changes...`;
        li.style.color = 'var(--text-muted)';
        driftList.appendChild(li);
      }
    } else {
      driftContainer.classList.add('hidden');
    }

    if (violations && violations.length > 0) {
      violationsContainer.classList.remove('hidden');
      violationsList.innerHTML = '';

      violations.forEach(v => {
        const li = document.createElement('li');
        li.className = `severity-${v.severity}`;
        
        li.innerHTML = `
          <div class="violation-header">
            <span class="violation-rule">${v.rule_id}</span>
            <span class="violation-severity ${v.severity}">${v.severity}</span>
          </div>
          <div class="violation-desc">${v.description}</div>
          <div class="violation-resource">${v.resource}</div>
        `;
        violationsList.appendChild(li);
      });
    } else {
      violationsContainer.classList.add('hidden');
    }
  }

  function updateMLUI(mlPrediction) {
    const mlSection = document.getElementById('mlSection');
    if (mlPrediction) {
      mlSection.classList.remove('hidden');
      
      const mlBadge = document.getElementById('mlPredictionBadge');
      const mlConfidence = document.getElementById('mlConfidence');
      const mlConfidenceBar = document.getElementById('mlConfidenceBar');
      const mlAnomaly = document.getElementById('mlAnomaly');
      
      mlBadge.textContent = mlPrediction.prediction;
      mlConfidence.textContent = `${(mlPrediction.confidence * 100).toFixed(1)}%`;
      mlConfidenceBar.style.width = `${mlPrediction.confidence * 100}%`;
      mlAnomaly.textContent = mlPrediction.anomaly_score.toFixed(2);
      
      const mlExplanationContainer = document.getElementById('mlExplanationContainer');
      const mlExplanation = document.getElementById('mlExplanation');
      
      if (mlPrediction.insights && mlPrediction.insights.explanation) {
        mlExplanationContainer.style.display = 'block';
        mlExplanation.textContent = mlPrediction.insights.explanation;
      } else {
        mlExplanationContainer.style.display = 'none';
      }
      
      // Color coding based on prediction
      let color = '#10b981'; // safe
      if (mlPrediction.prediction === 'CRITICAL') color = '#ef4444';
      else if (mlPrediction.prediction === 'RISK') color = '#f59e0b';
      
      mlSection.style.borderLeftColor = color;
      mlBadge.style.color = color;
      mlBadge.style.background = `${color}33`;
      mlConfidenceBar.style.background = color;
      mlSection.querySelector('svg').style.color = color;
      mlSection.querySelector('span').style.color = color;
    } else {
      mlSection.classList.add('hidden');
    }
  }

  function updateBehaviorUI(behaviorAnalysis) {
    const behaviorSection = document.getElementById('behaviorSection');
    if (behaviorAnalysis) {
      behaviorSection.classList.remove('hidden');
      
      const behaviorBadge = document.getElementById('behaviorBadge');
      const behaviorScore = document.getElementById('behaviorScore');
      const behaviorScoreBar = document.getElementById('behaviorScoreBar');
      const behaviorInsightsList = document.getElementById('behaviorInsightsList');
      const behaviorInsightsContainer = document.getElementById('behaviorInsightsContainer');
      
      behaviorBadge.textContent = behaviorAnalysis.status.toUpperCase();
      behaviorScore.textContent = `${behaviorAnalysis.score}/100`;
      behaviorScoreBar.style.width = `${behaviorAnalysis.score}%`;
      
      if (behaviorAnalysis.insights && behaviorAnalysis.insights.length > 0) {
        behaviorInsightsContainer.style.display = 'block';
        behaviorInsightsList.innerHTML = '';
        behaviorAnalysis.insights.forEach(insight => {
          const li = document.createElement('li');
          li.textContent = insight;
          behaviorInsightsList.appendChild(li);
        });
      } else {
        behaviorInsightsContainer.style.display = 'none';
      }

      // Populate Timeline
      const timelineContainer = document.getElementById('behaviorTimeline');
      if (timelineContainer && behaviorAnalysis.timeline) {
        timelineContainer.innerHTML = '';
        behaviorAnalysis.timeline.slice().reverse().forEach(item => {
          const div = document.createElement('div');
          div.style.display = 'flex';
          div.style.justifyContent = 'space-between';
          div.style.marginBottom = '4px';
          div.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
          div.style.paddingBottom = '2px';
          
          const timeStr = new Date(item.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
          div.innerHTML = `
            <span style="color: #94a3b8;">${timeStr}</span>
            <span style="color: #e2e8f0;">${item.action} (${item.service})</span>
          `;
          timelineContainer.appendChild(div);
        });
      }

      // Populate Risk Evolution
      const riskGraph = document.getElementById('riskEvolutionGraph');
      if (riskGraph && behaviorAnalysis.risk_evolution) {
        riskGraph.innerHTML = '';
        behaviorAnalysis.risk_evolution.forEach(item => {
          const bar = document.createElement('div');
          bar.style.flex = '1';
          bar.style.backgroundColor = item.score > 70 ? '#ef4444' : (item.score > 40 ? '#f59e0b' : '#8b5cf6');
          bar.style.height = `${Math.max(10, item.score)}%`;
          bar.style.borderRadius = '2px 2px 0 0';
          bar.title = `Score: ${item.score} at ${new Date(item.timestamp).toLocaleTimeString()}`;
          riskGraph.appendChild(bar);
        });
      }

      // Populate Heatmap
      const heatmapContainer = document.getElementById('behaviorHeatmap');
      if (heatmapContainer && behaviorAnalysis.heatmap) {
        heatmapContainer.innerHTML = '';
        for (let i = 0; i < 24; i++) {
          const count = behaviorAnalysis.heatmap[i.toString()] || 0;
          const cell = document.createElement('div');
          cell.style.flex = '1';
          
          let opacity = 0.1;
          if (count > 0) opacity = 0.3;
          if (count > 5) opacity = 0.6;
          if (count > 10) opacity = 1.0;
          
          cell.style.backgroundColor = `rgba(139, 92, 246, ${opacity})`;
          cell.style.borderRadius = '1px';
          cell.title = `Hour ${i}: ${count} actions`;
          heatmapContainer.appendChild(cell);
        }
      }
      
      // Color coding based on status
      let color = '#8b5cf6'; // Normal (Purple)
      if (behaviorAnalysis.status === 'Suspicious') color = '#f59e0b'; // Warning (Orange)
      else if (behaviorAnalysis.status === 'Critical') color = '#ef4444'; // Critical (Red)
      
      behaviorSection.style.borderLeftColor = color;
      behaviorBadge.style.color = color;
      behaviorBadge.style.background = `${color}33`;
      behaviorScoreBar.style.background = color;
      behaviorSection.querySelector('svg').style.color = color;
      behaviorSection.querySelector('span').style.color = color;
    } else {
      behaviorSection.classList.add('hidden');
    }
  }

  function updateStatusColors(statusClass) {
    // Reset classes
    scoreCircle.classList.remove('safe', 'risk', 'warning', 'analyzing', 'critical');
    statusText.classList.remove('safe', 'risk', 'warning', 'analyzing', 'critical');
    statusIndicator.classList.remove('safe', 'risk', 'warning', 'analyzing', 'critical');
    platformIndicator.classList.remove('safe', 'risk', 'warning', 'analyzing', 'critical');

    scoreCircle.classList.add(statusClass);
    statusText.classList.add(statusClass);
    statusIndicator.classList.add(statusClass);
    platformIndicator.classList.add(statusClass);
    
    // Update shield glow color
    const shieldGlow = document.querySelector('.logo-glow');
    const shieldIcon = document.querySelector('.shield-icon');
    
    if (statusClass === 'risk' || statusClass === 'critical') {
      shieldGlow.style.background = 'var(--risk-color)';
      shieldIcon.style.color = 'var(--risk-color)';
    } else if (statusClass === 'warning') {
      shieldGlow.style.background = 'var(--warning-color)';
      shieldIcon.style.color = 'var(--warning-color)';
    } else if (statusClass === 'analyzing') {
      shieldGlow.style.background = 'var(--analyzing-color)';
      shieldIcon.style.color = 'var(--analyzing-color)';
    } else {
      shieldGlow.style.background = 'var(--safe-color)';
      shieldIcon.style.color = 'var(--safe-color)';
    }
  }
});
