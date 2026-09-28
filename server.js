/**
 * World Monitor - Vulnerable Application Server
 * ================================================
 * THIS SERVER IS INTENTIONALLY VULNERABLE FOR SECURITY ASSESSMENT PURPOSES.
 * DO NOT DEPLOY TO PRODUCTION.
 * 
 * Vulnerabilities embedded:
 * 1. Weak JWT secret
 * 2. No rate limiting
 * 3. SQL injection simulation
 * 4. Missing CORS configuration
 * 5. Sensitive data exposure
 * 6. Broken access control (IDOR)
 * 7. XSS via reflected input
 * 8. Missing security headers
 * 9. Hardcoded credentials
 * 10. Insecure direct object references
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// ========================================
// VULNERABILITY: Weak JWT Secret (V-001)
// ========================================
const JWT_SECRET = 'secret123'; // Easily guessable

// ========================================
// VULNERABILITY: Hardcoded Credentials (V-009)
// ========================================
const USERS_DB = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin', email: 'admin@worldmonitor.com', apiKey: 'ak_prod_8f14e45f' },
  { id: 2, username: 'analyst', password: 'analyst2024', role: 'analyst', email: 'analyst@worldmonitor.com', apiKey: 'ak_prod_7c9e6679' },
  { id: 3, username: 'viewer', password: 'viewer123', role: 'viewer', email: 'viewer@worldmonitor.com', apiKey: 'ak_prod_1b6453b7' },
  { id: 4, username: 'manager', password: 'manager!', role: 'manager', email: 'manager@worldmonitor.com', apiKey: 'ak_prod_4e07408a' },
];

// Simulated monitoring data
const MONITORING_DATA = [
  { id: 1, region: 'North America', metric: 'CPU Usage', value: 78.4, status: 'warning', timestamp: '2026-09-28T10:00:00Z', ownerId: 1 },
  { id: 2, region: 'Europe', metric: 'Memory Usage', value: 45.2, status: 'normal', timestamp: '2026-09-28T10:05:00Z', ownerId: 1 },
  { id: 3, region: 'Asia Pacific', metric: 'Network Latency', value: 120, status: 'critical', timestamp: '2026-09-28T10:10:00Z', ownerId: 2 },
  { id: 4, region: 'South America', metric: 'Disk I/O', value: 62.1, status: 'normal', timestamp: '2026-09-28T10:15:00Z', ownerId: 2 },
  { id: 5, region: 'Africa', metric: 'Error Rate', value: 3.7, status: 'warning', timestamp: '2026-09-28T10:20:00Z', ownerId: 3 },
  { id: 6, region: 'Middle East', metric: 'Response Time', value: 890, status: 'critical', timestamp: '2026-09-28T10:25:00Z', ownerId: 4 },
];

// Sensitive config (exposed via API - V-005)
const SYSTEM_CONFIG = {
  database: { host: 'db.worldmonitor.internal', port: 5432, user: 'wm_admin', password: 'Pr0d_DB_P@ss!2026' },
  redis: { host: 'cache.worldmonitor.internal', port: 6379, password: 'R3d1s_S3cr3t' },
  aws: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
  smtp: { host: 'smtp.worldmonitor.com', user: 'noreply@worldmonitor.com', password: 'Sm7p_P@ss' }
};

const REPORTS = [
  { id: 1, title: 'Q3 Security Audit', content: 'Confidential audit findings...', classification: 'TOP SECRET', ownerId: 1 },
  { id: 2, title: 'Monthly Analytics', content: 'Performance metrics overview...', classification: 'INTERNAL', ownerId: 2 },
  { id: 3, title: 'Incident Report #412', content: 'Data breach details: 50k records exposed...', classification: 'TOP SECRET', ownerId: 1 },
  { id: 4, title: 'Public Dashboard Stats', content: 'General statistics...', classification: 'PUBLIC', ownerId: 3 },
];

// Audit log
const auditLog = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ========================================
// VULNERABILITY: Missing Security Headers (V-008)
// ========================================
// No helmet, no CSP, no X-Frame-Options, etc.

// ========================================
// VULNERABILITY: Permissive CORS (V-004)
// ========================================
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ========================================
// AUTH ENDPOINTS
// ========================================

// Login - V-002: No rate limiting, V-009: accepts hardcoded creds
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABILITY: Timing attack - different response times for valid/invalid users
  const user = USERS_DB.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials', field: 'username' });
    // ^ V-005: Reveals which field is wrong
  }
  
  if (user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials', field: 'password' });
  }

  // V-001: Weak secret, no expiry set properly
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' } // V-001: Overly long expiry
  );

  // V-005: Exposing sensitive info in response
  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
      apiKey: user.apiKey, // Should NOT be returned here
      password: user.password // CRITICAL: password in response
    }
  });
});

// ========================================
// VULNERABILITY: Broken Authentication Middleware (V-001)
// ========================================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // V-005: Detailed error exposure
    return res.status(401).json({ error: 'Token invalid', details: err.message, stack: err.stack });
  }
}

// ========================================
// DATA ENDPOINTS
// ========================================

// Get monitoring data
app.get('/api/monitoring', authMiddleware, (req, res) => {
  res.json({ data: MONITORING_DATA, total: MONITORING_DATA.length });
});

// ========================================
// VULNERABILITY: IDOR - Broken Access Control (V-006)
// ========================================
app.get('/api/reports/:id', authMiddleware, (req, res) => {
  // No authorization check - any authenticated user can access any report
  const report = REPORTS.find(r => r.id === parseInt(req.params.id));
  if (!report) {
    return res.status(404).json({ error: 'Report not found' });
  }
  res.json(report); // Returns regardless of user role or ownership
});

// Get all reports (no role check)
app.get('/api/reports', authMiddleware, (req, res) => {
  res.json({ data: REPORTS }); // All users see all reports
});

// ========================================
// VULNERABILITY: SQL Injection Simulation (V-003)
// ========================================
app.get('/api/search', authMiddleware, (req, res) => {
  const { query } = req.query;
  
  // Simulating SQL injection vulnerability
  // In a real app, this would be: `SELECT * FROM data WHERE name LIKE '%${query}%'`
  const simulatedQuery = `SELECT * FROM monitoring_data WHERE region LIKE '%${query}%'`;
  
  auditLog.push({
    action: 'search',
    query: simulatedQuery,
    user: req.user.username,
    timestamp: new Date().toISOString(),
    injectionDetected: query && (query.includes("'") || query.includes('"') || query.includes('--') || query.includes('UNION'))
  });

  // Filter data (simulating results)
  const results = query 
    ? MONITORING_DATA.filter(d => d.region.toLowerCase().includes((query || '').toLowerCase().replace(/['";\-\-]/g, '')))
    : MONITORING_DATA;

  res.json({
    query: simulatedQuery, // V-005: Exposing internal query
    results,
    executionTime: Math.random() * 100
  });
});

// ========================================
// VULNERABILITY: Reflected XSS (V-007)
// ========================================
app.get('/api/echo', (req, res) => {
  const { message } = req.query;
  // Reflecting user input without sanitization
  res.send(`<html><body><h2>System Message</h2><div>${message}</div></body></html>`);
});

// ========================================
// VULNERABILITY: Sensitive Data Exposure (V-005)
// ========================================
app.get('/api/debug/config', (req, res) => {
  // No authentication required!
  res.json({
    config: SYSTEM_CONFIG,
    environment: process.env,
    serverInfo: {
      nodeVersion: process.version,
      platform: process.platform,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage()
    }
  });
});

app.get('/api/debug/users', (req, res) => {
  // Exposes all user data including passwords
  res.json({ users: USERS_DB });
});

// ========================================
// ADMIN ENDPOINTS - V-006: Missing role checks
// ========================================
app.post('/api/admin/users', authMiddleware, (req, res) => {
  // Any authenticated user can create new users (should be admin only)
  const { username, password, role, email } = req.body;
  const newUser = {
    id: USERS_DB.length + 1,
    username, password, role: role || 'admin', email,
    apiKey: `ak_prod_${crypto.randomBytes(4).toString('hex')}`
  };
  USERS_DB.push(newUser);
  res.json({ success: true, user: newUser });
});

app.delete('/api/admin/users/:id', authMiddleware, (req, res) => {
  // Any authenticated user can delete users (should be admin only)
  const idx = USERS_DB.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const removed = USERS_DB.splice(idx, 1);
  res.json({ success: true, removed: removed[0] });
});

app.put('/api/admin/config', authMiddleware, (req, res) => {
  // Any authenticated user can modify system config
  Object.assign(SYSTEM_CONFIG, req.body);
  res.json({ success: true, config: SYSTEM_CONFIG });
});

// Audit log endpoint
app.get('/api/audit-log', (req, res) => {
  res.json({ log: auditLog });
});

// ========================================
// VULNERABILITY: No Rate Limiting on Password Reset (V-002)
// ========================================
app.post('/api/auth/reset-password', (req, res) => {
  const { email } = req.body;
  const user = USERS_DB.find(u => u.email === email);
  
  // V-005: User enumeration
  if (user) {
    res.json({ success: true, message: `Reset link sent to ${email}`, resetToken: crypto.randomBytes(16).toString('hex') });
  } else {
    res.json({ success: false, message: 'Email not found in our system' });
  }
});

// API Key validation endpoint
app.post('/api/auth/validate-key', (req, res) => {
  const { apiKey } = req.body;
  const user = USERS_DB.find(u => u.apiKey === apiKey);
  if (user) {
    res.json({ valid: true, user: { id: user.id, username: user.username, role: user.role } });
  } else {
    res.json({ valid: false });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    version: '2.4.1',
    buildHash: 'a1b2c3d4', // V-005: Build info exposure
    nodeEnv: process.env.NODE_ENV || 'development'
  });
});

// Serve the main app
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the security dashboard
app.get('/security-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'security-dashboard.html'));
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║          🌍 World Monitor - Security Assessment Lab         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ⚠️  THIS APPLICATION IS INTENTIONALLY VULNERABLE           ║
║  ⚠️  FOR SECURITY ASSESSMENT PURPOSES ONLY                  ║
║                                                              ║
║  🌐 World Monitor App:    http://localhost:${PORT}             ║
║  🔒 Security Dashboard:   http://localhost:${PORT}/security-dashboard  ║
║                                                              ║
║  Test Credentials:                                           ║
║    admin    / admin123                                       ║
║    analyst  / analyst2024                                    ║
║    viewer   / viewer123                                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
