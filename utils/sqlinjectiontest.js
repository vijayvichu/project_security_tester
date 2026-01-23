const axios = require("axios");

// Built-in payloads and keyword patterns. The module will attempt to fetch
// an external list of attacker practices first (best-effort), then fall back
// to these local defaults.
const defaultPayloads = [
  "' OR 1=1 --",
  "' UNION SELECT NULL,NULL --",
  "'; DROP TABLE users; --",
  '\" OR \"\"=\"',
  "' OR 'a'='a",
  "admin' --",
  "' OR '1'='1' /*",
  "' OR '1'='1' LIMIT 1 --",
  "' AND SLEEP(5) --"
];

const keywordPatterns = [
  /union\s+select/i,
  /or\s+1=1/i,
  /--/,
  /;/,
  /drop\s+/i,
  /insert\s+/i,
  /sleep\s*\(/i,
  /benchmark\s*\(/i,
  /xp_/i,
  /cast\s*\(/i,
  /convert\s*\(/i
];

function getPreventionTips(matchedKeywords) {
  const tips = new Set();

  if (matchedKeywords.some(k => /union|select/i.test(k))) {
    tips.add('Use parameterized queries / prepared statements to avoid UNION/SELECT injection.');
  }
  if (matchedKeywords.some(k => /or\s+1=1/i.test(k) || /--/.test(k) || /;/.test(k))) {
    tips.add('Validate and sanitize inputs; disallow control characters and SQL comment markers.');
  }
  if (matchedKeywords.some(k => /drop|insert/i.test(k))) {
    tips.add('Apply least privilege to DB accounts; avoid giving DROP/INSERT rights to web app accounts.');
  }
  if (matchedKeywords.some(k => /sleep|benchmark|xp_/i.test(k))) {
    tips.add('Rate-limit and detect slow/expensive queries; use WAF rules to block time-based injection.');
  }
  if (matchedKeywords.length === 0) {
    tips.add('Use parameterized queries, input validation, and ORM or stored procedures where applicable.');
  }

  tips.add('Use prepared statements, stored procedures, strict input validation, and escape user input.');
  tips.add('Enable a Web Application Firewall (WAF) and keep database users least-privileged.');

  return Array.from(tips);
}

async function fetchRemotePatterns() {
  // Best-effort fetch: if network fails, callers should fall back to defaults.
  try {
    // Example: try to fetch a remote JSON list (this URL is best-effort and may fail).
    const url = 'https://raw.githubusercontent.com/OWASP/OWASP-cheat-sheets/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md';
    const res = await axios.get(url, { timeout: 3000 });
    if (res && res.data && typeof res.data === 'string') {
      // We can't reliably parse the cheat sheet, but we can look for common phrases
      const body = res.data;
      const remotePayloadHints = [];
      if (/union/i.test(body)) remotePayloadHints.push('union select');
      if (/sleep\(/i.test(body)) remotePayloadHints.push('time-based payloads (SLEEP)');
      if (/or\s+1=1/i.test(body)) remotePayloadHints.push("' OR 1=1");
      return { payloads: remotePayloadHints };
    }
  } catch (e) {
    // ignore network errors - fallback to defaults
  }
  return null;
}

async function runSQLInjectionTest(url) {
  const remote = await fetchRemotePatterns();
  const payloads = (remote && remote.payloads && remote.payloads.length) ? remote.payloads.concat(defaultPayloads) : defaultPayloads;

  let vulnerable = false;
  const details = [];
  const matchedKeywords = new Set();

  for (let p of payloads) {
    try {
      const testUrl = url + (url.includes('?') ? '&' : '?') + 'id=' + encodeURIComponent(p);
      const res = await axios.get(testUrl, { timeout: 5000 });

      const body = (res && res.data) ? String(res.data) : '';

      // Heuristics: look for SQL error strings or server errors
      const isSuspicious = /SQL syntax|mysql_fetch|syntax error|unterminated quoted string|ORA-/.test(body) || res.status === 500;

      // Keyword matching against payload and response
      for (const kp of keywordPatterns) {
        if (kp.test(p) || kp.test(body)) matchedKeywords.add(kp.source);
      }

      if (isSuspicious) {
        vulnerable = true;
        details.push({ payload: p, result: 'Suspicious response', status: res.status });
      } else {
        details.push({ payload: p, result: 'No obvious vulnerability detected', status: res.status });
      }
    } catch (err) {
      // Network or timeout errors are returned as part of details but don't mark vulnerable by themselves
      const msg = err && err.message ? err.message : String(err);
      details.push({ payload: p, error: msg });

      // Match keywords in payload even when request fails
      for (const kp of keywordPatterns) {
        if (kp.test(p)) matchedKeywords.add(kp.source);
      }
    }
  }

  const prevention = getPreventionTips(Array.from(matchedKeywords));

  return { vulnerable, testResults: details, matched: Array.from(matchedKeywords), prevention };
}

module.exports = { runSQLInjectionTest };

