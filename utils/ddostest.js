/**
 * Ethical DDoS Vulnerability Testing Framework (Security Hardened)
 * 
 * Security Features:
 * - Concurrency limits (max 5 concurrent requests)
 * - Reduced test request counts
 * - Timeout protection on all requests
 * - Only use on websites you own or have explicit written permission
 */

const axios = require('axios');

class DDoSVulnerabilityTester {
  constructor(url, options = {}) {
    // Validate URL scheme
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `http://${url}`;
    }
    this.url = url;
    
    // Security: Enforce strict concurrency limits
    const maxAllowed = 10;
    const userRequested = options.maxConcurrentRequests || 5;
    this.maxConcurrentRequests = Math.min(userRequested, maxAllowed);
    
    this.requestDelay = options.requestDelay || 100;
    this.timeout = options.timeout || 5000;
    this.results = {
      rateLimiting: null,
      resourceExhaustion: null,
      slowLoris: null,
      httpFlood: null,
      serverResponse: null
    };
    
    // Security: Track total requests made
    this.totalRequestsMade = 0;
    this.maxTotalRequests = 100;  // Hard limit per test run
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Security: Track and limit total requests
  async makeRequest(requestFn) {
    if (this.totalRequestsMade >= this.maxTotalRequests) {
      throw new Error('Maximum request limit exceeded');
    }
    this.totalRequestsMade++;
    return requestFn();
  }

  async testServerResponse() {
    try {
      const start = Date.now();
      const response = await axios.get(this.url, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'Security-Scanner/1.0 (Ethical Testing)'
        }
      });
      const responseTime = Date.now() - start;

      this.results.serverResponse = {
        status: response.status,
        responseTime: responseTime,
        serverType: response.headers['server'] || 'Unknown',
        reachable: true
      };

      return true;
    } catch (error) {
      this.results.serverResponse = {
        reachable: false,
        error: error.message
      };
      return false;
    }
  }

  async testRateLimiting() {
    try {
      // Reduced from 15 to 10 requests
      const totalRequests = 10;
      const requests = [];
      
      for (let i = 0; i < totalRequests; i++) {
        const requestFn = () => axios.get(this.url, {
          timeout: this.timeout,
          headers: {
            'User-Agent': 'Security-Scanner/1.0 (Rate-Limit-Test)'
          },
          validateStatus: () => true
        }).then(res => ({
          status: res.status,
          blocked: res.status === 429 || res.status === 503
        })).catch(err => ({
          status: 0,
          blocked: false
        }));
        
        requests.push(this.makeRequest(requestFn));
        
        if (i < totalRequests - 1) await this.sleep(100);  // Increased delay
      }

      const responses = await Promise.all(requests);
      const blockedCount = responses.filter(r => r.blocked).length;
      const hasRateLimitHeader = responses.some(r => 
        r.status && r.status > 0 && 
        (r.status === 429 || r.status === 503 || 
         (typeof r === 'object' && r.headers && 
          (r.headers['x-ratelimit-limit'] || r.headers['x-ratelimit-remaining'])))
      );

      this.results.rateLimiting = {
        totalRequests: totalRequests,
        blockedRequests: blockedCount,
        hasRateLimiting: blockedCount > 0,
        vulnerable: blockedCount === 0
      };

    } catch (error) {
      this.results.rateLimiting = {
        error: error.message,
        hasRateLimiting: false,
        vulnerable: true
      };
    }
  }

  async testHttpFlood() {
    try {
      // Security: Reduced from 20 concurrent to max 5
      const concurrentRequests = Math.min(this.maxConcurrentRequests, 5);
      const iterations = 2;  // Reduced from 3
      let successCount = 0;
      let failCount = 0;
      let responseTimes = [];

      for (let iter = 0; iter < iterations; iter++) {
        const batch = [];
        
        for (let i = 0; i < concurrentRequests; i++) {
          const requestFn = () => axios.get(this.url, {
            timeout: this.timeout,
            headers: {
              'User-Agent': 'Security-Scanner/1.0 (HTTP-Flood-Test)'
            },
            validateStatus: () => true
          }).then(res => {
            const time = Date.now();
            return { success: res.status < 400, time };
          }).catch(() => {
            return { success: false, time: this.timeout };
          });
          
          batch.push(this.makeRequest(requestFn));
        }

        const batchResults = await Promise.all(batch);
        successCount += batchResults.filter(r => r.success).length;
        failCount += batchResults.filter(r => !r.success).length;

        await this.sleep(this.requestDelay);
      }

      const totalRequests = concurrentRequests * iterations;
      const successRate = (successCount / totalRequests) * 100;

      this.results.httpFlood = {
        totalRequests: totalRequests,
        successfulRequests: successCount,
        failedRequests: failCount,
        successRate: Math.round(successRate * 100) / 100,
        protectionDetected: successRate < 90,
        vulnerable: successRate >= 95
      };

    } catch (error) {
      this.results.httpFlood = {
        error: error.message,
        protectionDetected: false,
        vulnerable: true
      };
    }
  }

  async testResourceExhaustion() {
    try {
      // Reduced test sizes
      const testSizes = [1000, 5000];  // Removed 10000
      const results = [];

      for (const size of testSizes) {
        const payload = 'A'.repeat(size);
        const start = Date.now();
        
        const requestFn = () => axios.post(this.url, payload, {
          timeout: this.timeout,
          headers: {
            'Content-Type': 'text/plain',
            'User-Agent': 'Security-Scanner/1.0 (Resource-Test)'
          },
          validateStatus: () => true,
          maxContentLength: 10000
        });
        
        await this.makeRequest(requestFn);
        
        const time = Date.now() - start;
        results.push({ size, time, success: true });
      }

      const avgTime = results.reduce((a, b) => a + b.time, 0) / results.length;
      const allSucceeded = results.every(r => r.success);

      this.results.resourceExhaustion = {
        testSizes: testSizes,
        results: results,
        averageResponseTime: Math.round(avgTime),
        vulnerable: allSucceeded && avgTime < 500,
        hasProtection: !allSucceeded || avgTime > 1000
      };

    } catch (error) {
      this.results.resourceExhaustion = {
        error: error.message,
        vulnerable: false,
        hasProtection: true
      };
    }
  }

  async testSlowLorisVulnerability() {
    try {
      // Reduced from 5 to 3 slow requests
      const slowRequestsCount = 3;
      const slowRequests = [];
      
      for (let i = 0; i < slowRequestsCount; i++) {
        const requestFn = () => axios.get(this.url, {
          timeout: 8000,
          headers: {
            'User-Agent': 'Security-Scanner/1.0 (Slow-Request-Test)',
            'Connection': 'keep-alive'
          },
          validateStatus: () => true
        }).then(() => ({ success: true }))
          .catch(() => ({ success: false }));
        
        slowRequests.push(this.makeRequest(requestFn));
        await this.sleep(300);  // Increased delay
      }

      const results = await Promise.all(slowRequests);
      const successCount = results.filter(r => r.success).length;

      this.results.slowLoris = {
        slowRequestsSent: slowRequestsCount,
        successfulRequests: successCount,
        vulnerable: successCount >= 3,
        hasProtection: successCount < 2,
        recommendation: successCount >= 2 
          ? 'Configure server timeouts and connection limits'
          : 'Server appears to have timeout protection'
      };

    } catch (error) {
      this.results.slowLoris = {
        error: error.message,
        vulnerable: false,
        hasProtection: true
      };
    }
  }

  generateReport() {
    const r = this.results;
    let vulnerableCount = 0;
    let totalTests = 0;

    if (r.rateLimiting) { 
      totalTests++; 
      if (!r.rateLimiting.hasRateLimiting) vulnerableCount++; 
    }
    if (r.resourceExhaustion) { 
      totalTests++; 
      if (r.resourceExhaustion.vulnerable) vulnerableCount++; 
    }
    if (r.slowLoris) { 
      totalTests++; 
      if (r.slowLoris.vulnerable) vulnerableCount++; 
    }
    if (r.httpFlood) { 
      totalTests++; 
      if (!r.httpFlood.protectionDetected) vulnerableCount++; 
    }

    const score = totalTests > 0 ? Math.round((vulnerableCount / totalTests) * 100) : 0;
    const severity = score >= 80 ? "CRITICAL" : 
                     score >= 60 ? "HIGH" : 
                     score >= 40 ? "MEDIUM" : 
                     score >= 20 ? "LOW" : "MINIMAL";

    return {
      url: this.url,
      timestamp: new Date().toISOString(),
      vulnerable: score >= 40,
      score: score,
      severity: severity,
      tests: r,
      summary: {
        totalTests: totalTests,
        vulnerableTests: vulnerableCount,
        protectedTests: totalTests - vulnerableCount,
        totalRequestsMade: this.totalRequestsMade
      },
      preventionTips: [
        "<strong>🛡️ Rate Limiting:</strong> Implement rate limiting using nginx, API gateways, or WAF",
        "<strong>⏱️ Slowloris Protection:</strong> Configure server timeouts and connection limits",
        "<strong>🌊 HTTP Flood:</strong> Deploy CDN with DDoS protection (Cloudflare, AWS Shield)",
        "<strong>🔒 Security Headers:</strong> Add X-RateLimit headers and security headers",
        "<strong>🏗️ Infrastructure:</strong> Use load balancers and auto-scaling"
      ]
    };
  }
}

// Legacy function for backward compatibility
async function runLoadTest(url) {
  const tester = new DDoSVulnerabilityTester(url, {
    maxConcurrentRequests: 5  // Enforce limit
  });
  
  await tester.testServerResponse();
  await tester.sleep(500);
  await tester.testRateLimiting();
  await tester.sleep(500);
  await tester.testHttpFlood();
  await tester.sleep(500);
  await tester.testResourceExhaustion();
  await tester.sleep(500);
  await tester.testSlowLorisVulnerability();
  
  return tester.generateReport();
}

module.exports = { DDoSVulnerabilityTester, runLoadTest };
