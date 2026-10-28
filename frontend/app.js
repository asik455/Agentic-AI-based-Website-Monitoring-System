// ═══════════════════════════════════════════════════════════════════════════
// HF Guardian Sentinel — Real-time Continuous Monitor & Intrusion Alerting
// ═══════════════════════════════════════════════════════════════════════════

// State
let targets = [];
let alerts = [];
let audioAlertsEnabled = true;
let sseSource = null;
let audioCtx = null;

// DOM Elements
const breachBanner = document.getElementById('breachBanner');
const breachBannerText = document.getElementById('breachBannerText');
const sirenSoundBtn = document.getElementById('sirenSoundBtn');
const viewBreachBtn = document.getElementById('viewBreachBtn');

const metricTargetCount = document.getElementById('metricTargetCount');
const metricActiveBreaches = document.getElementById('metricActiveBreaches');
const metricBreachSub = document.getElementById('metricBreachSub');
const metricTotalAlerts = document.getElementById('metricTotalAlerts');

const targetsGrid = document.getElementById('targetsGrid');
const alertsStream = document.getElementById('alertsStream');
const openAddTargetBtn = document.getElementById('openAddTargetBtn');
const closeAddTargetBtn = document.getElementById('closeAddTargetBtn');
const cancelAddTargetBtn = document.getElementById('cancelAddTargetBtn');
const addTargetCard = document.getElementById('addTargetCard');
const addTargetForm = document.getElementById('addTargetForm');
const targetTypeSelect = document.getElementById('targetTypeSelect');
const targetUrlLabel = document.getElementById('targetUrlLabel');
const targetUrlInput = document.getElementById('targetUrlInput');
const clearAlertsBtn = document.getElementById('clearAlertsBtn');

// Navigation Tabs
const navTabs = {
  monitor: { btn: document.getElementById('tab-btn-monitor'), panel: document.getElementById('view-monitor') },
  targets: { btn: document.getElementById('tab-btn-targets'), panel: document.getElementById('view-targets') },
  ondemand: { btn: document.getElementById('tab-btn-ondemand'), panel: document.getElementById('view-ondemand') },
  intel: { btn: document.getElementById('tab-btn-intel'), panel: document.getElementById('view-intel') }
};

// ─── Initialization ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  setupTheme();
  setupNavigation();
  setupTargetManagement();
  setupAlertControls();
  setupAudioAlerts();
  setupAdHocScanner();
  setupAuth();
  
  loadTargets();
  loadAlerts();
  connectSSE();
});

// ─── Navigation Switcher ───────────────────────────────────────────────────

function setupNavigation() {
  const topNavTitle = document.getElementById('topNavTitle');
  const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
  const appSidebar = document.getElementById('appSidebar');

  const tabTitles = {
    monitor: 'Continuous Monitor',
    targets: 'Target Management',
    ondemand: 'On-Demand Scan',
    intel: 'Threat Intelligence'
  };

  if (sidebarToggleBtn && appSidebar) {
    sidebarToggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      appSidebar.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
      if (window.innerWidth <= 900 &&
          appSidebar.classList.contains('open') &&
          !appSidebar.contains(e.target) &&
          !sidebarToggleBtn.contains(e.target)) {
        appSidebar.classList.remove('open');
      }
    });
  }

  Object.keys(navTabs).forEach(key => {
    const { btn, panel } = navTabs[key];
    btn.addEventListener('click', () => {
      Object.values(navTabs).forEach(item => {
        item.btn.classList.remove('active');
        item.btn.setAttribute('aria-selected', 'false');
        item.panel.classList.remove('active');
        item.panel.hidden = true;
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      panel.hidden = false;
      setTimeout(() => panel.classList.add('active'), 10);

      if (topNavTitle && tabTitles[key]) {
        topNavTitle.textContent = tabTitles[key];
      }

      if (window.innerWidth <= 900 && appSidebar) {
        appSidebar.classList.remove('open');
      }
    });
  });

  if (viewBreachBtn) {
    viewBreachBtn.addEventListener('click', () => {
      navTabs.monitor.btn.click();
      const consoleEl = document.getElementById('alertsConsole');
      if (consoleEl) {
        consoleEl.scrollIntoView({ behavior: 'smooth' });
      }
    });
  }
}

// ─── Web Audio Siren / Alert Sound (Zero External Dependencies) ─────────────

function setupAudioAlerts() {
  sirenSoundBtn.addEventListener('click', () => {
    audioAlertsEnabled = !audioAlertsEnabled;
    sirenSoundBtn.textContent = audioAlertsEnabled ? '🔔 Audio ON' : '🔕 Audio Muted';
    showToast(audioAlertsEnabled ? 'Intrusion audio siren enabled' : 'Intrusion audio siren muted');
  });
}

function playSecuritySiren() {
  if (!audioAlertsEnabled) return;
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    if (!audioCtx) audioCtx = new AudioContext();
    if (audioCtx.state === 'suspended') audioCtx.resume();

    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = 'sawtooth';
    // Two-tone emergency siren frequency modulation
    osc.frequency.setValueAtTime(880, now);
    osc.frequency.linearRampToValueAtTime(440, now + 0.25);
    osc.frequency.linearRampToValueAtTime(880, now + 0.5);
    osc.frequency.linearRampToValueAtTime(440, now + 0.75);

    gain.gain.setValueAtTime(0.15, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.8);

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.start(now);
    osc.stop(now + 0.8);
  } catch (e) {
    console.warn('Audio siren playback error:', e);
  }
}

// ─── Real-time Server-Sent Events (SSE) ─────────────────────────────────────

function connectSSE() {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/events');

  sseSource.onopen = () => {
    document.getElementById('ssePulseDot').style.background = '#10b981';
  };

  sseSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleServerEvent(data);
    } catch (e) {
      console.error('Failed to parse SSE event data', e);
    }
  };

  sseSource.onerror = () => {
    document.getElementById('ssePulseDot').style.background = '#f59e0b';
    // Automatic browser reconnection will trigger
  };
}

function handleServerEvent(evt) {
  if (evt.type === 'new_alert') {
    alerts.unshift(evt.alert);
    renderAlerts();
    updateMetrics();
    playSecuritySiren();
    showToast(`🚨 ALERT: ${evt.alert.title}`, true);

    // Update target if provided
    if (evt.target) {
      const idx = targets.findIndex(t => t.id === evt.target.id);
      if (idx !== -1) targets[idx] = evt.target;
      renderTargets();
    }
  } else if (evt.type === 'target_updated') {
    const idx = targets.findIndex(t => t.id === evt.target.id);
    if (idx !== -1) {
      targets[idx] = evt.target;
    } else {
      targets.push(evt.target);
    }
    renderTargets();
    renderManageTargetsTable();
    updateMetrics();
  } else if (evt.type === 'target_added') {
    if (!targets.some(t => t.id === evt.target.id)) {
      targets.push(evt.target);
      renderTargets();
      renderManageTargetsTable();
      updateMetrics();
    }
  } else if (evt.type === 'target_removed') {
    targets = targets.filter(t => t.id !== evt.target_id);
    renderTargets();
    renderManageTargetsTable();
    updateMetrics();
  } else if (evt.type === 'alert_acknowledged') {
    const a = alerts.find(x => x.id === evt.alert_id);
    if (a) a.acknowledged = true;
    renderAlerts();
    updateMetrics();
  } else if (evt.type === 'alerts_cleared') {
    alerts = [];
    renderAlerts();
    updateMetrics();
  }
}

// ─── API Data Fetching ─────────────────────────────────────────────────────

async function loadTargets() {
  try {
    const res = await fetch('/api/targets');
    if (res.ok) {
      targets = await res.json();
      renderTargets();
      renderManageTargetsTable();
      updateMetrics();
    }
  } catch (e) {
    console.error('Failed to load targets:', e);
  }
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    if (res.ok) {
      alerts = await res.json();
      renderAlerts();
      updateMetrics();
    }
  } catch (e) {
    console.error('Failed to load alerts:', e);
  }
}

// ─── Render Targets ────────────────────────────────────────────────────────

function renderTargets() {
  if (targets.length === 0) {
    targetsGrid.innerHTML = `
      <div style="grid-column: 1/-1; padding: 3.5rem 2rem; text-align: center; color: var(--text-muted); background: var(--bg-surface); border-radius: 12px; border: 1px dashed var(--border); display: flex; flex-direction: column; align-items: center; justify-content: center;">
        <div style="width: 48px; height: 48px; border-radius: 50%; background: var(--primary-light); color: var(--primary); display: flex; align-items: center; justify-content: center; margin-bottom: 1rem;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <h3 style="font-size: 1.15rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.35rem;">No Monitored Targets</h3>
        <p style="font-size: 0.88rem; max-width: 480px; margin-bottom: 1.25rem;">No active websites or model repositories are currently configured. Add a target to initiate continuous integrity scanning.</p>
        <button type="button" class="btn-primary" onclick="navTabs.targets.btn.click()" style="display: inline-flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; padding: 0.55rem 1.1rem;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Go to Target Management →
        </button>
      </div>
    `;
    return;
  }

  targetsGrid.innerHTML = targets.map(t => {
    const isCompromised = t.status === 'COMPROMISED';
    const statusText = t.status || 'PENDING';
    const lastScanTime = t.last_scanned ? timeAgo(t.last_scanned) : 'Pending initial check';

    return `
      <div class="target-card status-${statusText}" id="target-${t.id}">
        <div class="target-card-top">
          <div class="target-title-block">
            <span class="target-title">${escapeHTML(t.name)}</span>
            <span class="target-endpoint">${escapeHTML(t.url_or_repo)}</span>
          </div>
          <span class="status-badge ${statusText}">${statusText}</span>
        </div>

        <div class="target-meta-row">
          <div class="target-meta-item">
            <span class="meta-title">Type</span>
            <span class="meta-val">${getTargetTypeBadge(t.target_type)}</span>
          </div>
          <div class="target-meta-item">
            <span class="meta-title">Frequency</span>
            <span class="meta-val">Every ${t.interval_seconds}s</span>
          </div>
          <div class="target-meta-item">
            <span class="meta-title">Last Audit</span>
            <span class="meta-val">${lastScanTime}</span>
          </div>
        </div>

        <div style="font-size: 0.76rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.35rem; padding: 0.3rem 0.6rem; background: var(--bg-surface-elevated); border-radius: 6px; margin-bottom: 0.65rem;">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          <span>Email Alerts: <strong style="color: var(--text-main); font-weight:600;">${escapeHTML(t.alert_emails || 'Default Recipients')}</strong></span>
        </div>

        <div class="target-findings">
          ${(t.last_findings && t.last_findings.length > 0)
            ? t.last_findings.map(f => `<div>${escapeHTML(f)}</div>`).join('')
            : '<div>Continuous background watcher initialized. Awaiting delta.</div>'}
        </div>

        <div class="target-card-actions">
          <button class="btn-sm btn-sm-primary" onclick="forceScanTarget('${t.id}')">Scan Now</button>
          <button class="btn-sm btn-sm-outline" style="margin-left: auto;" onclick="deleteTarget('${t.id}')">Remove</button>
        </div>
      </div>
    `;
  }).join('');
}

// ─── Render Alerts Stream ──────────────────────────────────────────────────

function renderAlerts() {
  if (alerts.length === 0) {
    alertsStream.innerHTML = `
      <div class="no-alerts-state">
        <div class="no-alerts-icon">✓</div>
        <strong>No Security Incidents Detected</strong>
        <span style="font-size: 0.85rem;">The continuous sentinel has not detected any intrusions, defacements, or unauthorized commits.</span>
      </div>
    `;
    return;
  }

  alertsStream.innerHTML = alerts.map(a => {
    const sevClass = a.severity || 'HIGH';
    const ackClass = a.acknowledged ? 'acknowledged' : '';
    const dateStr = new Date(a.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return `
      <div class="alert-row ${sevClass} ${ackClass}" id="alert-${a.id}">
        <div class="alert-sev-icon ${sevClass}">
          ${sevClass === 'CRITICAL' ? '⚠️' : '⚡'}
        </div>
        <div class="alert-body">
          <div class="alert-top">
            <span class="alert-title">${escapeHTML(a.title)}</span>
            <span class="alert-time">${dateStr}</span>
          </div>
          <span class="alert-target-badge">${escapeHTML(a.target_name)}</span>
          <p class="alert-msg">${escapeHTML(a.message)}</p>
          
          ${a.evidence && a.evidence.length > 0 ? `
            <div class="alert-evidence-box">${a.evidence.map(e => escapeHTML(e)).join('\n')}</div>
          ` : ''}

          <div style="margin-top: 0.4rem; display: flex; gap: 0.5rem;">
            ${!a.acknowledged ? `
              <button class="btn-sm btn-sm-outline" style="font-size: 0.75rem;" onclick="acknowledgeAlert('${a.id}')">Acknowledge Alert</button>
            ` : '<span style="font-size: 0.75rem; color: var(--text-muted); align-self: center;">✓ Acknowledged</span>'}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// ─── Update Metrics Bar & Breach Banner ────────────────────────────────────

function updateMetrics() {
  metricTargetCount.textContent = targets.length;
  metricTotalAlerts.textContent = alerts.length;

  const activeBreaches = targets.filter(t => t.status === 'COMPROMISED').length;
  const downTargets = targets.filter(t => t.status === 'DOWN').length;
  metricActiveBreaches.textContent = activeBreaches;

  const unackCriticalAlerts = alerts.filter(a => !a.acknowledged && (a.severity === 'CRITICAL' || a.severity === 'HIGH'));
  const bannerTitle = document.getElementById('breachBannerTitle');

  if (activeBreaches > 0) {
    metricBreachSub.textContent = `${activeBreaches} target(s) compromised!`;
    metricBreachSub.className = 'metric-sub text-danger';
    if (bannerTitle) bannerTitle.textContent = 'SECURITY INTRUSION DETECTED';
    breachBanner.hidden = false;
    const latestBreach = unackCriticalAlerts.find(a => !a.title.includes('Offline') && !a.title.includes('Outage')) || unackCriticalAlerts[0] || alerts[0];
    if (latestBreach) {
      breachBannerText.textContent = `Target "${latestBreach.target_name}": ${latestBreach.title}`;
    }
  } else if (downTargets > 0) {
    metricBreachSub.textContent = `${downTargets} target(s) offline`;
    metricBreachSub.className = 'metric-sub';
    metricBreachSub.style.color = '#b45309';
    if (bannerTitle) bannerTitle.textContent = 'SERVICE OFFLINE DETECTED';
    breachBanner.hidden = false;
    const latestDown = targets.find(t => t.status === 'DOWN');
    if (latestDown) {
      breachBannerText.textContent = `Target "${latestDown.name}" is currently unreachable (Connection Refused / Process Stopped).`;
    }
  } else {
    metricBreachSub.textContent = 'All monitored targets clean';
    metricBreachSub.className = 'metric-sub text-success';
    metricBreachSub.style.color = '';
    breachBanner.hidden = true;
  }
}

// ─── Target Actions ────────────────────────────────────────────────────────

window.forceScanTarget = async function(id) {
  try {
    showToast('Triggering immediate audit scan...');
    const res = await fetch(`/api/targets/${id}/scan`, { method: 'POST' });
    if (!res.ok) throw new Error('Scan request failed');
  } catch (e) {
    showToast('Failed to trigger scan: ' + e.message, true);
  }
};

window.simulateAttack = async function(id) {
  try {
    showToast('Simulating active security breach & dispatching alerts...');
    const res = await fetch(`/api/targets/${id}/simulate-attack`, { method: 'POST' });
    if (!res.ok) throw new Error('Simulation failed');
  } catch (e) {
    showToast('Failed to simulate attack: ' + e.message, true);
  }
};

window.deleteTarget = async function(id) {
  if (!confirm('Stop continuous protection on this target?')) return;
  try {
    const res = await fetch(`/api/targets/${id}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Target removed from continuous monitoring');
    }
  } catch (e) {
    showToast('Failed to delete target: ' + e.message, true);
  }
};

window.acknowledgeAlert = async function(id) {
  try {
    await fetch(`/api/alerts/${id}/ack`, { method: 'POST' });
  } catch (e) {
    console.error('Failed to ack alert', e);
  }
};

// ─── Alert History Clear Setup ─────────────────────────────────────────────

function setupAlertControls() {
  if (clearAlertsBtn) {
    clearAlertsBtn.addEventListener('click', async () => {
      if (!confirm('Clear all alert records from console?')) return;
      try {
        await fetch('/api/alerts/clear', { method: 'POST' });
        showToast('Alert history cleared');
      } catch (e) {
        console.error('Failed to clear alerts', e);
      }
    });
  }
}

// ─── Ad-Hoc Scanner (View 2) ───────────────────────────────────────────────

function setupAdHocScanner() {
  const form = document.getElementById('scanForm');
  const input = document.getElementById('repoInput');
  const resultsSection = document.getElementById('resultsSection');
  const loadingState = document.getElementById('loadingState');
  const resultsContainer = document.getElementById('resultsContainer');
  const threatsList = document.getElementById('threatsList');
  const exampleChips = document.querySelectorAll('.example-chip');

  exampleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      input.value = chip.dataset.repo;
      form.dispatchEvent(new Event('submit'));
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const repo = input.value.trim();
    if (!repo) return;

    resultsSection.hidden = false;
    loadingState.hidden = false;
    resultsContainer.hidden = true;
    threatsList.innerHTML = '';

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_id: repo })
      });
      const data = await res.json();
      loadingState.hidden = true;
      resultsContainer.hidden = false;

      if (data.scan_error) {
        threatsList.innerHTML = `<div style="color:#ef4444; padding:1rem;">Error: ${escapeHTML(data.scan_error)}</div>`;
        return;
      }

      document.getElementById('riskRepoId').textContent = data.repo_id;
      document.getElementById('riskScoreNumber').textContent = data.risk_score;
      const arc = document.getElementById('gaugeArc');
      const offset = 314 - (data.risk_score / 100) * 314;
      arc.style.strokeDashoffset = offset;

      const riskLabel = document.getElementById('riskLabel');
      if (data.risk_score > 60) {
        riskLabel.textContent = 'Critical Risk';
        riskLabel.style.color = '#ef4444';
        arc.style.stroke = '#ef4444';
      } else if (data.risk_score > 25) {
        riskLabel.textContent = 'High Risk';
        riskLabel.style.color = '#f59e0b';
        arc.style.stroke = '#f59e0b';
      } else {
        riskLabel.textContent = 'Safe';
        riskLabel.style.color = '#10b981';
        arc.style.stroke = '#10b981';
      }

      document.getElementById('riskStats').innerHTML = `
        <div style="font-size:0.9rem; color:var(--text-muted);">
          Scanned <strong>${data.files_scanned.length}</strong> files | Found <strong>${data.threats.length}</strong> threats
        </div>
      `;

      if (data.threats.length === 0) {
        threatsList.innerHTML = '<div style="color:#10b981; padding:1rem; font-weight:600;">✓ No malicious payloads or pickle vulnerabilities detected.</div>';
      } else {
        threatsList.innerHTML = data.threats.map(t => `
          <div style="border-left: 3px solid #ef4444; padding: 0.75rem 1rem; margin-bottom: 0.75rem; background: rgba(0,0,0,0.25); border-radius: 4px;">
            <div style="font-weight:700; color:white;">[${t.severity}] ${escapeHTML(t.title)}</div>
            <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">${escapeHTML(t.description)}</p>
          </div>
        `).join('');
      }

    } catch (err) {
      loadingState.hidden = true;
      resultsSection.hidden = false;
      threatsList.innerHTML = `<div style="color:#ef4444; padding:1rem;">Scan failed: ${escapeHTML(err.message)}</div>`;
    }
  });
}

// ─── Utilities ─────────────────────────────────────────────────────────────

function escapeHTML(str) {
  if (!str) return '';
  return String(str).replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

function timeAgo(epochSec) {
  const diff = Math.floor(Date.now() / 1000 - epochSec);
  if (diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function showToast(msg, isError = false) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'toast-danger' : ''}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// ─── Authentication State Manager ──────────────────────────────────────────

function setupAuth() {
  const headerLoginBtn = document.getElementById('headerLoginBtn');
  const headerUserProfile = document.getElementById('headerUserProfile');
  const headerUserAvatar = document.getElementById('headerUserAvatar');
  const headerUserName = document.getElementById('headerUserName');
  const headerUserRole = document.getElementById('headerUserRole');
  const headerSignOutBtn = document.getElementById('headerSignOutBtn');

  const token = localStorage.getItem('guardian_token');
  const cachedUserStr = localStorage.getItem('guardian_user');

  if (!token) {
    window.location.replace('/login');
    return;
  }

  if (cachedUserStr) {
    try {
      const u = JSON.parse(cachedUserStr);
      renderLoggedInUser(u);
    } catch (e) {}
  }

  // Verify token with backend
  fetch('/api/auth/me', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(r => {
    if (!r.ok) throw new Error('Session expired');
    return r.json();
  })
  .then(user => {
    localStorage.setItem('guardian_user', JSON.stringify(user));
    renderLoggedInUser(user);
  })
  .catch(() => {
    localStorage.removeItem('guardian_token');
    localStorage.removeItem('guardian_user');
    window.location.replace('/login');
  });

  function renderLoggedInUser(user) {
    if (!headerUserProfile || !headerLoginBtn) return;
    headerLoginBtn.style.display = 'none';
    headerUserProfile.style.display = 'flex';
    
    // Initials
    const names = (user.full_name || user.username || 'User').split(' ');
    const initials = names.length > 1 ? (names[0][0] + names[1][0]).toUpperCase() : names[0].substring(0, 2).toUpperCase();
    headerUserAvatar.textContent = initials;
    headerUserName.textContent = user.full_name || user.username;
    headerUserRole.textContent = user.role || 'Analyst';
  }

  function renderLoggedOut() {
    window.location.replace('/login');
  }

  if (headerSignOutBtn) {
    headerSignOutBtn.addEventListener('click', () => {
      localStorage.removeItem('guardian_token');
      localStorage.removeItem('guardian_user');
      window.location.replace('/login');
    });
  }
}

// ─── Theme Switcher (White / Light Default with Dark Option) ───────────────

function setupTheme() {
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeIcon = document.getElementById('themeIcon');
  
  // Default to light (white theme)
  const currentTheme = localStorage.getItem('sentinel_theme') || 'light';
  applyTheme(currentTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const active = document.documentElement.getAttribute('data-theme') || 'light';
      const nextTheme = active === 'light' ? 'dark' : 'light';
      applyTheme(nextTheme);
      showToast(`Switched to ${nextTheme === 'light' ? 'White / Light' : 'Dark Slate'} theme`);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('sentinel_theme', theme);
    if (themeIcon) {
      themeIcon.textContent = theme === 'light' ? '🌙' : '☀️';
    }
  }
}

// ─── Target Management Operations (Add, Edit, Delete) ──────────────────────

function renderManageTargetsTable() {
  const tbody = document.getElementById('manageTargetsTableBody');
  const countBadge = document.getElementById('inventoryCountBadge');
  const searchInput = document.getElementById('inventorySearchInput');
  if (!tbody) return;

  const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
  const filtered = targets.filter(t => {
    if (!query) return true;
    return (t.name || '').toLowerCase().includes(query) ||
           (t.url_or_repo || '').toLowerCase().includes(query) ||
           (t.alert_emails || '').toLowerCase().includes(query) ||
           (t.target_type || '').toLowerCase().includes(query);
  });

  if (countBadge) {
    countBadge.textContent = `${targets.length} Target${targets.length === 1 ? '' : 's'}`;
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 3rem 1.5rem; color: var(--text-muted);">
          <div style="font-size: 1.05rem; font-weight: 600; color: var(--text-main); margin-bottom: 0.25rem;">
            ${query ? 'No matching targets found' : 'No monitored targets in inventory'}
          </div>
          <p style="font-size: 0.85rem; margin-bottom: 1rem;">
            ${query ? 'Try a different search term or clear the filter.' : 'Add your first asset to begin continuous integrity monitoring.'}
          </p>
          ${!query ? `<button type="button" class="btn-primary" onclick="document.getElementById('openManageAddTargetBtn').click()" style="padding: 0.45rem 1rem; font-size: 0.82rem;">+ Add Monitored Target</button>` : ''}
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(t => {
    const statusClass = t.status || 'PENDING';
    const emails = t.alert_emails || 'Default Recipients';
    const typeLabel = getTargetTypeBadge(t.target_type);

    return `
      <tr id="manage-target-${t.id}">
        <td>
          <span class="target-cell-title">${escapeHTML(t.name)}</span>
          <span class="target-cell-sub">${escapeHTML(t.url_or_repo)}</span>
        </td>
        <td>
          <span style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted); background: var(--bg-surface-elevated); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid var(--border);">
            ${typeLabel}
          </span>
        </td>
        <td>
          <span style="font-size: 0.85rem; font-weight: 600;">Every ${t.interval_seconds}s</span>
        </td>
        <td style="max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <span title="${escapeHTML(emails)}" style="font-size: 0.82rem; color: var(--text-body);">
            ✉️ ${escapeHTML(emails)}
          </span>
        </td>
        <td>
          <span class="status-badge ${statusClass}">${statusClass}</span>
        </td>
        <td>
          <div class="target-action-btns">
            <button type="button" class="btn-action-icon btn-action-edit" onclick="openEditTargetModal('${t.id}')" title="Edit Target Configuration">
              ✏️ Edit
            </button>
            <button type="button" class="btn-action-icon" onclick="forceScanTarget('${t.id}')" title="Force Immediate Audit">
              🔄 Scan
            </button>
            <button type="button" class="btn-action-icon btn-action-delete" onclick="deleteTarget('${t.id}')" title="Remove Asset">
              🗑️ Delete
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function getTargetTypeBadge(type) {
  switch (type) {
    case 'api': return 'REST API';
    case 'model': return 'AI Model';
    case 'huggingface': return 'AI Model';
    case 'website':
    default: return 'Website';
  }
}

window.openEditTargetModal = function(id) {
  const target = targets.find(t => t.id === id);
  if (!target) return;

  document.getElementById('editTargetId').value = target.id;
  document.getElementById('editTargetNameInput').value = target.name || '';
  
  let currentType = target.target_type || 'website';
  if (currentType === 'huggingface') currentType = 'model';
  document.getElementById('editTargetTypeSelect').value = currentType;

  const editUrlLabel = document.getElementById('editTargetUrlLabel');
  const editUrlInput = document.getElementById('editTargetUrlInput');
  if (editUrlLabel && editUrlInput) {
    if (currentType === 'api') {
      editUrlLabel.textContent = 'REST API Endpoint URL';
      editUrlInput.placeholder = 'https://api.domain.com/v1/health';
    } else if (currentType === 'model') {
      editUrlLabel.textContent = 'AI Model ID or Service URL';
      editUrlInput.placeholder = 'e.g. meta-llama/Llama-3-8b or https://model-api.domain.com';
    } else {
      editUrlLabel.textContent = 'Target Website / Web App URL';
      editUrlInput.placeholder = 'https://example.com';
    }
  }
  
  document.getElementById('editTargetUrlInput').value = target.url_or_repo || '';
  document.getElementById('editTargetIntervalSelect').value = String(target.interval_seconds || 30);
  document.getElementById('editTargetEmailInput').value = target.alert_emails || '';
  document.getElementById('editTargetWebhookInput').value = target.webhook_url || '';

  const modal = document.getElementById('editTargetModal');
  if (modal) modal.hidden = false;
};

function setupTargetManagement() {
  const openBtn = document.getElementById('openManageAddTargetBtn');
  const closeBtn = document.getElementById('closeManageAddTargetBtn');
  const cancelBtn = document.getElementById('cancelManageAddTargetBtn');
  const addCard = document.getElementById('manageAddTargetCard');
  const addForm = document.getElementById('manageAddTargetForm');
  const typeSelect = document.getElementById('mTargetTypeSelect');
  const urlLabel = document.getElementById('mTargetUrlLabel');
  const urlInput = document.getElementById('mTargetUrlInput');
  const searchInput = document.getElementById('inventorySearchInput');

  if (openBtn && addCard) {
    openBtn.addEventListener('click', () => {
      addCard.hidden = false;
      addCard.scrollIntoView({ behavior: 'smooth' });
      const nameInput = document.getElementById('mTargetNameInput');
      if (nameInput) nameInput.focus();
    });
  }

  const closeForm = () => { if (addCard) addCard.hidden = true; };
  if (closeBtn) closeBtn.addEventListener('click', closeForm);
  if (cancelBtn) cancelBtn.addEventListener('click', closeForm);

  if (typeSelect && urlLabel && urlInput) {
    const updatePlaceholders = () => {
      if (typeSelect.value === 'api') {
        urlLabel.textContent = 'REST API Endpoint URL';
        urlInput.placeholder = 'https://api.domain.com/v1/health or https://api.service.io';
      } else if (typeSelect.value === 'model') {
        urlLabel.textContent = 'AI Model ID or Service URL';
        urlInput.placeholder = 'e.g. meta-llama/Llama-3-8b or https://model-api.domain.com';
      } else {
        urlLabel.textContent = 'Target Website / Web App URL';
        urlInput.placeholder = 'https://example.com or https://app.domain.com';
      }
    };
    typeSelect.addEventListener('change', updatePlaceholders);
  }

  if (addForm) {
    addForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('mTargetNameInput').value.trim(),
        target_type: typeSelect.value,
        url_or_repo: urlInput.value.trim(),
        interval_seconds: parseInt(document.getElementById('mTargetIntervalSelect').value, 10),
        alert_emails: document.getElementById('mTargetEmailInput') ? document.getElementById('mTargetEmailInput').value.trim() : '',
        webhook_url: document.getElementById('mTargetWebhookInput') ? document.getElementById('mTargetWebhookInput').value.trim() : ''
      };

      try {
        const res = await fetch('/api/targets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || 'Could not add target');
        }
        addForm.reset();
        closeForm();
        showToast('Target created and monitoring initiated!');
        loadTargets();
      } catch (err) {
        showToast(err.message, true);
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderManageTargetsTable();
    });
  }

  // Edit Modal Setup
  const editModal = document.getElementById('editTargetModal');
  const closeEditBtn = document.getElementById('closeEditTargetModalBtn');
  const cancelEditBtn = document.getElementById('cancelEditTargetBtn');
  const editForm = document.getElementById('editTargetForm');

  const closeEditModal = () => { if (editModal) editModal.hidden = true; };
  if (closeEditBtn) closeEditBtn.addEventListener('click', closeEditModal);
  if (cancelEditBtn) cancelEditBtn.addEventListener('click', closeEditModal);

  if (editModal) {
    editModal.addEventListener('click', (e) => {
      if (e.target === editModal) closeEditModal();
    });
  }

  const editTypeSelect = document.getElementById('editTargetTypeSelect');
  const editUrlLabel = document.getElementById('editTargetUrlLabel');
  const editUrlInput = document.getElementById('editTargetUrlInput');
  if (editTypeSelect && editUrlLabel && editUrlInput) {
    editTypeSelect.addEventListener('change', () => {
      if (editTypeSelect.value === 'api') {
        editUrlLabel.textContent = 'REST API Endpoint URL';
        editUrlInput.placeholder = 'https://api.domain.com/v1/health';
      } else if (editTypeSelect.value === 'model') {
        editUrlLabel.textContent = 'AI Model ID or Service URL';
        editUrlInput.placeholder = 'e.g. meta-llama/Llama-3-8b or https://model-api.domain.com';
      } else {
        editUrlLabel.textContent = 'Target Website / Web App URL';
        editUrlInput.placeholder = 'https://example.com';
      }
    });
  }

  if (editForm) {
    editForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = document.getElementById('editTargetId').value;
      const payload = {
        name: document.getElementById('editTargetNameInput').value.trim(),
        target_type: document.getElementById('editTargetTypeSelect').value,
        url_or_repo: document.getElementById('editTargetUrlInput').value.trim(),
        interval_seconds: parseInt(document.getElementById('editTargetIntervalSelect').value, 10),
        alert_emails: document.getElementById('editTargetEmailInput').value.trim(),
        webhook_url: document.getElementById('editTargetWebhookInput').value.trim()
      };

      try {
        const res = await fetch(`/api/targets/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || 'Failed to update target');
        }
        const updated = await res.json();
        const idx = targets.findIndex(t => t.id === id);
        if (idx !== -1) {
          targets[idx] = updated;
        }
        renderTargets();
        renderManageTargetsTable();
        closeEditModal();
        showToast(`Target "${updated.name}" updated successfully!`);
      } catch (err) {
        showToast(err.message, true);
      }
    });
  }
}

