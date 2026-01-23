/**
 * ddostest.js
 *
 * Server-side load-testing helper using autocannon.
 *
 * Usage (CLI):
 *   TARGET_URL=https://example.com node ddostest.js
 *
 * Example programmatic usage:
 *   const { runLoadTest } = require('./ddostest');
 *   const res = await runLoadTest('https://example.com', { duration: 20, connections: 100 });
 *
 * Safety:
 * - Only run against targets you own or have written permission to test.
 * - This script is intended for server-side use (backend), not in a browser.
 */

const autocannon = require('autocannon');
const { URL } = require('url');

const DEFAULTS = {
  duration: 10,        // seconds
  connections: 50,     // concurrent connections
  pipelining: 1,       // HTTP pipelining
  method: 'GET',
  headers: {},
  body: null,
};

/**
 * Validate target URL and optional whitelist checks.
 * If process.env.TARGET_WHITELIST is set, only allow hosts in that comma-separated list.
 * If process.env.REQUIRE_TEST_TOKEN is set, require opts.testToken to match it.
 */
function validateTarget(targetUrl, opts = {}) {
  if (!targetUrl) throw new Error('targetUrl required');
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    throw new Error('Invalid targetUrl');
  }
  // Only http/https allowed
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only http/https URLs are allowed');
  }

  const whitelist = process.env.TARGET_WHITELIST;
  if (whitelist) {
    const hosts = whitelist.split(',').map(h => h.trim()).filter(Boolean);
    if (!hosts.includes(parsed.hostname)) {
      throw new Error(`Target host not in whitelist: ${parsed.hostname}`);
    }
  }

  const requiredToken = process.env.REQUIRE_TEST_TOKEN;
  if (requiredToken) {
    if (!opts.testToken || opts.testToken !== requiredToken) {
      throw new Error('Missing or invalid test token (REQUIRE_TEST_TOKEN is set on server)');
    }
  }

  return true;
}

/**
 * Simple scoring heuristic for "vulnerability".
 * Produces 0 (not vulnerable) to 100 (highly vulnerable).
 *
 * This is a heuristic for quick feedback, not a definitive assessment.
 * It weights:
 *  - error rate (requests.non2xx + errors)
 *  - p95 latency
 *  - requests/sec drop vs baseline (not implemented here; a real test would compare to expected capacity)
 */
function computeVulnerabilityScore(metrics) {
  // metrics: { errors, non2xx, requests: { average }, latency: { p50, p95, p99 } }
  const totalRequests = Math.max(metrics.requests?.total || 1, 1);
  const errorCount = (metrics.errors || 0) + (metrics.non2xx || 0);
  const errorRate = errorCount / totalRequests; // 0..1

  // latency in ms
  const p95 = metrics.latency?.p95 || 0;

  // Score components (0..100)
  const errorScore = Math.min(60, errorRate * 200 * 0.6 * 100); // heavy weight on errors
  const latencyScore = Math.min(40, Math.max(0, (p95 - 500) / 1500) * 40); // p95 > 500ms increases score

  const score = Math.min(100, Math.round(errorScore + latencyScore));
  return { score, components: { errorRate, p95, errorScore, latencyScore } };
}

/**
 * Run a load test against `targetUrl` with options:
 *  - duration (seconds)
 *  - connections (concurrency)
 *  - pipelining
 *  - method, headers, body
 *  - testToken (optional; only used for server-side REQUIRE_TEST_TOKEN check)
 *
 * Returns a Promise resolving to { raw: <autocannon result>, summary: {...}, vulnerability: {...} }
 */
async function runLoadTest(targetUrl, opts = {}) {
  opts = Object.assign({}, DEFAULTS, opts);
  validateTarget(targetUrl, opts);

  const acOptions = {
    url: targetUrl,
    duration: opts.duration,
    connections: opts.connections,
    pipelining: opts.pipelining,
    method: opts.method,
    headers: opts.headers,
    body: opts.body,
  };

  // Run autocannon - autocannon is a function that returns a promise
  const results = await autocannon(acOptions);

  // Build metrics summary
  const summary = {
    url: targetUrl,
    duration: results.duration || opts.duration,
    requests: {
      total: results.requests?.total || 0,
      average: results.requests?.average || 0,
      mean: results.requests?.mean || results.requests?.average || 0,
      rates: results.requests || {},
    },
    latency: {
      average: results.latency?.average || 0,
      p50: results.latency?.p50 || 0,
      p75: results.latency?.p75 || 0,
      p95: results.latency?.p95 || 0,
      p99: results.latency?.p99 || 0,
    },
    throughput: {
      bytes: results.throughput?.total || 0,
      average: results.throughput?.average || 0, // bytes/sec
    },
    errors: results.errors || 0,
    non2xx: results.non2xx || 0,
    connections: {
      average: results.connections?.average || 0,
      min: results.connections?.min || 0,
      max: results.connections?.max || 0,
    },
  };

  const vulnerability = computeVulnerabilityScore({
    errors: summary.errors,
    non2xx: summary.non2xx,
    requests: { total: summary.requests.total, average: summary.requests.average },
    latency: { p95: summary.latency.p95, p50: summary.latency.p50 },
  });

  return { raw: results, summary, vulnerability };
}

// Export for programmatic use
module.exports = { runLoadTest };

// If run directly, read TARGET_URL from env or argv and run a sample test
if (require.main === module) {
  (async () => {
    try {
      const target = process.env.TARGET_URL || process.argv[2];
      if (!target) {
        console.error('Usage: TARGET_URL=https://example.com node ddostest.js');
        process.exit(2);
      }

      const options = {
        duration: parseInt(process.env.DURATION || '10', 10),
        connections: parseInt(process.env.CONNECTIONS || '50', 10),
        pipelining: parseInt(process.env.PIPELINING || '1', 10),
        testToken: process.env.TEST_TOKEN, // optional; only used if server REQUIRE_TEST_TOKEN is set
      };

      console.log(`Running test: ${target} for ${options.duration}s with ${options.connections} connections...`);
      const result = await runLoadTest(target, options);
      console.log('Summary:', JSON.stringify(result.summary, null, 2));
      console.log('Vulnerability score:', JSON.stringify(result.vulnerability, null, 2));
      process.exit(0);
    } catch (err) {
      console.error('Error:', err.message || err);
      process.exit(1);
    }
  })();
}
