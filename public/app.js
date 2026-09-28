/**
 * World Monitor - Application JavaScript
 * Handles authentication, data fetching, UI interactions, and navigation
 */

const API_BASE = '';
let authToken = null;
let currentUser = null;
let charts = {};

// ============================================
// Authentication
// ============================================

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const errorEl = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');

  btn.innerHTML = '<span class="spinner"></span> Signing in...';
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = `Authentication failed: ${data.error} (field: ${data.field || 'unknown'})`;
      errorEl.style.display = 'block';
      btn.innerHTML = '<span>Sign In</span>';
      btn.disabled = false;
      return;
    }

    authToken = data.token;
    currentUser = data.user;

    // Store token in localStorage (insecure for demo)
    localStorage.setItem('wm_token', authToken);
    localStorage.setItem('wm_user', JSON.stringify(currentUser));

    showApp();
  } catch (err) {
    errorEl.textContent = 'Network error. Please try again.';
    errorEl.style.display = 'block';
    btn.innerHTML = '<span>Sign In</span>';
    btn.disabled = false;
  }
});

// Check for stored session
function checkSession() {
  const token = localStorage.getItem('wm_token');
  const user = localStorage.getItem('wm_user');
  if (token && user) {
    authToken = token;
    currentUser = JSON.parse(user);
    showApp();
  }
}

function showApp() {
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('appScreen').style.display = 'flex';

  // Update user profile
  document.getElementById('userName').textContent = currentUser.username;
  document.getElementById('userRole').textContent = currentUser.role;
  document.getElementById('userAvatar').textContent = currentUser.username[0].toUpperCase();

  loadDashboard();
}

function logout() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem('wm_token');
  localStorage.removeItem('wm_user');
  document.getElementById('loginScreen').style.display = 'flex';
  document.getElementById('appScreen').style.display = 'none';
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('loginError').style.display = 'none';
}

document.getElementById('logoutBtn').addEventListener('click', logout);

// ============================================
// API Helper
// ============================================

async function apiGet(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Authorization': `Bearer ${authToken}` }
  });
  return res.json();
}

async function apiPost(endpoint, body) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`
    },
    body: JSON.stringify(body)
  });
  return res.json();
}

async function apiDelete(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${authToken}` }
  });
  return res.json();
}

// ============================================
// Dashboard
// ============================================

async function loadDashboard() {
  try {
    const data = await apiGet('/api/monitoring');
    renderMonitoringTable(data.data);
    renderRegionList(data.data);
    renderPerformanceChart();
  } catch (err) {
    console.error('Failed to load dashboard:', err);
  }
}

function renderMonitoringTable(data) {
  const tbody = document.getElementById('monitoringBody');
  tbody.innerHTML = data.map(item => `
    <tr>
      <td><strong>${item.region}</strong></td>
      <td>${item.metric}</td>
      <td><code>${item.value}${item.metric.includes('Latency') || item.metric.includes('Time') ? 'ms' : item.metric.includes('Rate') ? '%' : '%'}</code></td>
      <td><span class="region-status status-${item.status}">${item.status}</span></td>
      <td style="color:var(--text-muted);font-size:0.8rem">${new Date(item.timestamp).toLocaleString()}</td>
    </tr>
  `).join('');
}

function renderRegionList(data) {
  const list = document.getElementById('regionList');
  const colors = { normal: '#00E676', warning: '#FFB300', critical: '#FF4D6A' };
  
  list.innerHTML = data.map(item => `
    <div class="region-item">
      <div class="region-dot" style="background:${colors[item.status]};box-shadow:0 0 8px ${colors[item.status]}"></div>
      <div class="region-info">
        <div class="region-name">${item.region}</div>
        <div class="region-metric">${item.metric}: ${item.value}</div>
      </div>
      <span class="region-status status-${item.status}">${item.status}</span>
    </div>
  `).join('');
}

function renderPerformanceChart() {
  const ctx = document.getElementById('perfChart');
  if (!ctx) return;

  if (charts.perf) charts.perf.destroy();

  const labels = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const cpuData = Array.from({ length: 24 }, () => 40 + Math.random() * 45);
  const memData = Array.from({ length: 24 }, () => 30 + Math.random() * 35);
  const netData = Array.from({ length: 24 }, () => 20 + Math.random() * 50);

  charts.perf = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'CPU Usage %',
          data: cpuData,
          borderColor: '#00D4FF',
          backgroundColor: 'rgba(0, 212, 255, 0.08)',
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 5,
        },
        {
          label: 'Memory %',
          data: memData,
          borderColor: '#7B2FFF',
          backgroundColor: 'rgba(123, 47, 255, 0.05)',
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 5,
        },
        {
          label: 'Network I/O',
          data: netData,
          borderColor: '#00E676',
          backgroundColor: 'rgba(0, 230, 118, 0.05)',
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 5,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { 
          labels: { color: '#8892b0', padding: 20, usePointStyle: true, pointStyleWidth: 8, font: { size: 11 } }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(42, 48, 80, 0.3)' },
          ticks: { color: '#5a6480', font: { size: 10 }, maxTicksLimit: 12 }
        },
        y: {
          grid: { color: 'rgba(42, 48, 80, 0.3)' },
          ticks: { color: '#5a6480', font: { size: 10 } },
          beginAtZero: true,
          max: 100
        }
      }
    }
  });
}

// ============================================
// Search
// ============================================

document.getElementById('searchBtn')?.addEventListener('click', performSearch);
document.getElementById('searchQuery')?.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') performSearch();
});

async function performSearch() {
  const query = document.getElementById('searchQuery').value;
  if (!query.trim()) return;

  try {
    const data = await apiGet(`/api/search?query=${encodeURIComponent(query)}`);
    
    const resultsEl = document.getElementById('searchResults');
    const queryEl = document.getElementById('searchQueryDisplay');

    // Show the generated SQL query (vulnerability demo)
    queryEl.style.display = 'block';
    queryEl.innerHTML = `<strong>Generated SQL Query:</strong><br>${escapeHtml(data.query)}<br><br><strong>Execution Time:</strong> ${data.executionTime?.toFixed(2)}ms`;

    if (data.results && data.results.length > 0) {
      resultsEl.innerHTML = data.results.map(r => `
        <div class="search-result-card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <strong>${r.region}</strong>
            <span class="region-status status-${r.status}">${r.status}</span>
          </div>
          <div style="color:var(--text-secondary);font-size:0.85rem">
            ${r.metric}: <code>${r.value}</code>
          </div>
        </div>
      `).join('');
    } else {
      resultsEl.innerHTML = '<div class="search-result-card"><p style="color:var(--text-muted)">No results found.</p></div>';
    }
  } catch (err) {
    console.error('Search error:', err);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// Reports
// ============================================

async function loadReports() {
  try {
    const data = await apiGet('/api/reports');
    const grid = document.getElementById('reportsGrid');
    
    grid.innerHTML = data.data.map(r => {
      const clsClass = r.classification.toLowerCase().replace(' ', '-');
      return `
        <div class="report-card" onclick="viewReport(${r.id})">
          <span class="report-classification classification-${clsClass}">${r.classification}</span>
          <h3 class="report-title">${r.title}</h3>
          <p class="report-content">${r.content}</p>
          <div class="report-meta">
            <span>ID: ${r.id}</span>
            <span>Owner: User #${r.ownerId}</span>
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load reports:', err);
  }
}

async function viewReport(id) {
  try {
    const report = await apiGet(`/api/reports/${id}`);
    alert(`Report: ${report.title}\nClassification: ${report.classification}\nContent: ${report.content}\n\n⚠️ IDOR Vulnerability: Any user can access this report regardless of ownership or clearance.`);
  } catch (err) {
    console.error('Failed to view report:', err);
  }
}

// ============================================
// Users Management
// ============================================

async function loadUsers() {
  try {
    const data = await apiGet('/api/debug/users');
    const tbody = document.getElementById('usersBody');
    
    tbody.innerHTML = data.users.map(u => `
      <tr>
        <td>
          <div style="display:flex;align-items:center;gap:10px">
            <div class="user-avatar" style="width:32px;height:32px;font-size:0.75rem">${u.username[0].toUpperCase()}</div>
            <div>
              <div style="font-weight:600">${u.username}</div>
              <div style="font-size:0.75rem;color:var(--text-muted)">ID: ${u.id}</div>
            </div>
          </div>
        </td>
        <td>${u.email}</td>
        <td><span class="region-status status-${u.role === 'admin' ? 'critical' : u.role === 'manager' ? 'warning' : 'normal'}">${u.role}</span></td>
        <td><code style="font-size:0.78rem;color:var(--accent-orange)">${u.apiKey}</code></td>
        <td>
          <button class="btn btn-ghost" style="padding:6px 12px;font-size:0.78rem" onclick="deleteUser(${u.id})">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load users:', err);
  }
}

async function deleteUser(id) {
  if (!confirm('Delete this user? (This demonstrates broken access control - any user can delete other users)')) return;
  try {
    await apiDelete(`/api/admin/users/${id}`);
    loadUsers();
  } catch (err) {
    console.error('Failed to delete user:', err);
  }
}

// ============================================
// Alerts
// ============================================

function loadAlerts() {
  const alerts = [
    { type: 'critical', title: 'High CPU Usage - Asia Pacific', desc: 'CPU usage has exceeded 90% threshold for the past 15 minutes.', time: '5 minutes ago' },
    { type: 'critical', title: 'Network Latency Spike - Middle East', desc: 'Response time exceeded 800ms, affecting user experience in the region.', time: '12 minutes ago' },
    { type: 'warning', title: 'Disk I/O Warning - North America', desc: 'Disk I/O is approaching capacity limits. Consider scaling storage.', time: '28 minutes ago' },
    { type: 'warning', title: 'Memory Usage Elevated - Europe', desc: 'Memory usage has been above 70% for the last hour.', time: '45 minutes ago' },
    { type: 'info', title: 'Scheduled Maintenance Window', desc: 'System maintenance scheduled for 2026-09-29 02:00 UTC.', time: '2 hours ago' },
  ];

  const list = document.getElementById('alertsList');
  const iconSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

  list.innerHTML = alerts.map(a => `
    <div class="alert-item">
      <div class="alert-icon ${a.type}">${iconSvg}</div>
      <div class="alert-body">
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.desc}</div>
        <div class="alert-time">${a.time}</div>
      </div>
    </div>
  `).join('');
}

// ============================================
// Analytics Charts
// ============================================

function loadAnalytics() {
  // Analytics trend chart
  const aCtx = document.getElementById('analyticsChart');
  if (aCtx && !charts.analytics) {
    const labels = Array.from({ length: 30 }, (_, i) => `Sep ${i + 1}`);
    charts.analytics = new Chart(aCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Requests/min',
            data: Array.from({ length: 30 }, () => 500 + Math.random() * 1500),
            borderColor: '#00D4FF',
            backgroundColor: 'rgba(0, 212, 255, 0.06)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0,
          },
          {
            label: 'Errors/min',
            data: Array.from({ length: 30 }, () => Math.random() * 30),
            borderColor: '#FF4D6A',
            backgroundColor: 'rgba(255, 77, 106, 0.06)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0,
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#8892b0', usePointStyle: true, font: { size: 11 } } } },
        scales: {
          x: { grid: { color: 'rgba(42,48,80,0.3)' }, ticks: { color: '#5a6480', font: { size: 10 }, maxTicksLimit: 15 } },
          y: { grid: { color: 'rgba(42,48,80,0.3)' }, ticks: { color: '#5a6480', font: { size: 10 } } }
        }
      }
    });
  }

  // Traffic distribution
  const tCtx = document.getElementById('trafficChart');
  if (tCtx && !charts.traffic) {
    charts.traffic = new Chart(tCtx, {
      type: 'doughnut',
      data: {
        labels: ['North America', 'Europe', 'Asia Pacific', 'South America', 'Africa', 'Middle East'],
        datasets: [{
          data: [35, 28, 20, 8, 5, 4],
          backgroundColor: ['#00D4FF', '#7B2FFF', '#00E676', '#FFB300', '#FF4D6A', '#3B82F6'],
          borderWidth: 0,
          spacing: 2,
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: { legend: { position: 'bottom', labels: { color: '#8892b0', padding: 12, usePointStyle: true, font: { size: 10 } } } }
      }
    });
  }

  // Error rate chart
  const eCtx = document.getElementById('errorChart');
  if (eCtx && !charts.errors) {
    charts.errors = new Chart(eCtx, {
      type: 'bar',
      data: {
        labels: ['N. America', 'Europe', 'Asia Pacific', 'S. America', 'Africa', 'Mid East'],
        datasets: [{
          label: 'Error Rate %',
          data: [1.2, 0.8, 3.7, 1.5, 2.1, 4.2],
          backgroundColor: ['rgba(0,212,255,0.6)', 'rgba(123,47,255,0.6)', 'rgba(0,230,118,0.6)', 'rgba(255,179,0,0.6)', 'rgba(255,77,106,0.6)', 'rgba(59,130,246,0.6)'],
          borderRadius: 6,
          borderSkipped: false,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#5a6480', font: { size: 10 } } },
          y: { grid: { color: 'rgba(42,48,80,0.3)' }, ticks: { color: '#5a6480', font: { size: 10 } } }
        }
      }
    });
  }
}

// ============================================
// Settings
// ============================================

document.getElementById('viewConfigBtn')?.addEventListener('click', async () => {
  try {
    const data = await fetch(`${API_BASE}/api/debug/config`).then(r => r.json());
    const display = document.getElementById('configDisplay');
    display.style.display = 'block';
    display.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error('Failed to load config:', err);
  }
});

// ============================================
// Navigation
// ============================================

const pages = {
  dashboard: { el: 'pageDashboard', load: loadDashboard },
  analytics: { el: 'pageAnalytics', load: loadAnalytics },
  reports: { el: 'pageReports', load: loadReports },
  alerts: { el: 'pageAlerts', load: loadAlerts },
  search: { el: 'pageSearch', load: null },
  users: { el: 'pageUsers', load: loadUsers },
  settings: { el: 'pageSettings', load: null },
};

document.querySelectorAll('.nav-item[data-page]').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;
    navigateTo(page);
  });
});

function navigateTo(page) {
  // Update nav
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');

  // Show page
  Object.keys(pages).forEach(key => {
    const el = document.getElementById(pages[key].el);
    if (el) {
      el.style.display = key === page ? 'block' : 'none';
      if (key === page) el.classList.add('active');
      else el.classList.remove('active');
    }
  });

  // Load data
  if (pages[page]?.load) pages[page].load();

  // Close mobile sidebar
  document.getElementById('sidebar').classList.remove('open');
}

// Mobile menu toggle
document.getElementById('menuToggle')?.addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// Refresh button
document.getElementById('refreshBtn')?.addEventListener('click', () => {
  loadDashboard();
});

// ============================================
// Init
// ============================================

checkSession();
