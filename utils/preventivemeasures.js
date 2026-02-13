/**
 * Preventive Measures Fetcher
 * Fetches security recommendations from authoritative sources
 */

const axios = require('axios');

// OWASP and security resource URLs
const SECURITY_RESOURCES = {
  sqlInjection: [
    'https://owasp.org/www-community/attacks/SQL_Injection',
    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
  ],
  xss: [
    'https://owasp.org/www-community/attacks/xss/',
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
  ],
  ddos: [
    'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
    'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html'
  ],
  general: [
    'https://owasp.org/www-project-web-security-testing-guide/',
    'https://cheatsheetseries.owasp.org/Index.html'
  ]
};

// Comprehensive preventive measures database
const PREVENTIVE_MEASURES = {
  sqlInjection: {
    title: "SQL Injection Prevention",
    severity: "CRITICAL",
    owasp: "A03:2021 - Injection",
    measures: [
      {
        category: "Parameterized Queries",
        priority: "HIGHEST",
        description: "Use prepared statements and parameterized queries for all database operations",
        implementation: [
          "Java: Use PreparedStatement with ? placeholders",
          "PHP: Use PDO with parameter binding: $pdo->prepare('SELECT * FROM users WHERE id = ?')",
          "Python: Use parameterized queries with database adapters",
          "Node.js: Use parameterized queries with mysql2/promise or pg"
        ],
        codeExample: `// Safe - Using parameterized query
const query = 'SELECT * FROM users WHERE id = ?';
const result = await db.execute(query, [userId]);`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
      },
      {
        category: "ORM Usage",
        priority: "HIGH",
        description: "Use Object-Relational Mapping (ORM) frameworks that handle parameterization automatically",
        implementation: [
          "TypeORM, Sequelize (Node.js)",
          "SQLAlchemy (Python)",
          "Hibernate (Java)",
          "Entity Framework (C#)"
        ],
        codeExample: `// Safe - Using TypeORM repository
const userRepository = dataSource.getRepository(User);
const users = await userRepository.find({
  where: { id: userId }
});`,
        resources: [
          "https://typeorm.io/"
        ]
      },
      {
        category: "Input Validation",
        priority: "HIGH",
        description: "Validate and sanitize all user inputs before database operations",
        implementation: [
          "Whitelist validation for expected formats",
          "Use strong typing for numeric inputs",
          "Escape special characters for context",
          "Implement strict type checking"
        ],
        codeExample: `// Validate input
const userId = parseInt(req.params.id);
if (isNaN(userId) || userId < 1) {
  throw new Error('Invalid user ID');
}`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        ]
      },
      {
        category: "Least Privilege",
        priority: "MEDIUM",
        description: "Database users should have minimum required permissions",
        implementation: [
          "Separate database users for different application functions",
          "Restrict SELECT, INSERT, UPDATE, DELETE permissions",
          "Deny access to system tables and stored procedures",
          "Use database roles for permission management"
        ],
        codeExample: `-- Database permission best practices
REVOKE ALL ON DATABASE app_db FROM PUBLIC;
GRANT CONNECT ON DATABASE app_db TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO app_user;
GRANT USAGE ON SEQUENCE users_id_seq TO app_user;`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"
        ]
      },
      {
        category: "Error Handling",
        priority: "MEDIUM",
        description: "Disable detailed error messages in production",
        implementation: [
          "Set display_errors = Off in php.ini",
          "Use custom error pages",
          "Log errors server-side with details, show generic to users",
          "Avoid displaying SQL syntax in errors"
        ],
        codeExample: `// Production error handling (Node.js/Express)
app.use((err, req, res, next) => {
  console.error('Detailed error:', err);
  res.status(500).json({
    error: 'An error occurred'
  });
});`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        ]
      }
    ]
  },
  
  ddos: {
    title: "DDoS Attack Mitigation",
    severity: "HIGH",
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    measures: [
      {
        category: "Rate Limiting",
        priority: "HIGHEST",
        description: "Implement rate limiting to prevent abuse",
        implementation: [
          "Use nginx rate limiting: limit_req_zone",
          "Implement application-level rate limiting",
          "Set up IP-based request throttling",
          "Use Redis for distributed rate limiting"
        ],
        codeExample: `// Express rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: 'Too many requests, please try again later'
});
app.use('/api/', limiter);`,
        resources: [
          "https://github.com/nfriedly/express-rate-limit"
        ]
      },
      {
        category: "Load Balancing",
        priority: "HIGH",
        description: "Distribute traffic across multiple servers",
        implementation: [
          "Use nginx/HAProxy as load balancer",
          "Implement horizontal scaling",
          "Set up auto-scaling groups (AWS, GCP, Azure)",
          "Use CDN for static content distribution"
        ],
        resources: [
          "https://aws.amazon.com/elasticloadbalancing/",
          "https://cloud.google.com/load-balancing"
        ]
      },
      {
        category: "DDoS Protection Services",
        priority: "HIGH",
        description: "Use professional DDoS mitigation services",
        implementation: [
          "Cloudflare DDoS protection",
          "AWS Shield/AWS WAF",
          "Google Cloud Armor",
          "Azure DDoS Protection"
        ],
        resources: [
          "https://www.cloudflare.com/ddos/",
          "https://aws.amazon.com/shield/"
        ]
      },
      {
        category: "Timeout Configuration",
        priority: "MEDIUM",
        description: "Configure proper timeout settings to prevent Slowloris attacks",
        implementation: [
          "Set reasonable connection timeouts",
          "Limit request body size",
          "Use keep-alive timeouts appropriately",
          "Configure worker processes and connections"
        ],
        codeExample: `// Nginx timeout configuration
client_body_timeout 10;
client_header_timeout 10;
keepalive_timeout 5 5;
worker_connections 1024;`,
        resources: [
          "https://nginx.org/en/docs/http/ngx_http_core_module.html"
        ]
      },
      {
        category: "Web Application Firewall",
        priority: "HIGH",
        description: "Deploy WAF to filter malicious traffic",
        implementation: [
          "ModSecurity with OWASP Core Rule Set",
          "Cloudflare WAF rules",
          "AWS WAF with managed rules",
          "Custom WAF rules for known attack patterns"
        ],
        codeExample: `// Cloudflare WAF rule example
// Block SQL injection attempts
(http.request.uri.path contains " UNION ") or
(http.request.uri.query contains " OR 1=1")`,
        resources: [
          "https://owasp.org/www-project-modsecurity-core-rule-set/",
          "https://www.modsecurity.org/"
        ]
      }
    ]
  },
  
  xss: {
    title: "Cross-Site Scripting (XSS) Prevention",
    severity: "HIGH",
    owasp: "A03:2021 - Injection",
    measures: [
      {
        category: "Content Security Policy",
        priority: "HIGHEST",
        description: "Implement strict CSP headers to prevent XSS",
        implementation: [
          "Define allowed script sources",
          "Restrict inline scripts and styles",
          "Use nonces for inline scripts",
          "Report violations to monitoring system"
        ],
        codeExample: `// Strict CSP header
res.setHeader('Content-Security-Policy', 
  "default-src 'self'; " +
  "script-src 'self' 'nonce-{random}'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; " +
  "frame-ancestors 'none';"
);`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
      },
      {
        category: "Output Encoding",
        priority: "HIGHEST",
        description: "Encode output based on context (HTML, JS, URL, CSS)",
        implementation: [
          "HTML entity encoding for HTML context",
          "JavaScript encoding for JS context",
          "URL encoding for URL parameters",
          "CSS encoding for style contexts"
        ],
        codeExample: `// Using a library like DOMPurify
const createSafeHTML = (userInput) => {
  return DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p'],
    ALLOWED_ATTR: ['class']
  });
};

// Node.js - escape-html
const escapeHtml = require('escape-html');
const safeContent = escapeHtml(userContent);`,
        resources: [
          "https://github.com/cure53/DOMPurify",
          "https://github.com/component/escape-html"
        ]
      },
      {
        category: "Input Validation",
        priority: "HIGH",
        description: "Validate and sanitize all user inputs",
        implementation: [
          "Whitelist allowed characters",
          "Reject script tags and event handlers",
          "Validate input length and format",
          "Use schema validation libraries"
        ],
        codeExample: `// Input validation with Joi
const schema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().min(13).max(120)
});

const { error, value } = schema.validate(userInput);
if (error) {
  throw new Error('Invalid input: ' + error.details[0].message);
}`,
        resources: [
          "https://joi.dev/"
        ]
      }
    ]
  },
  
  general: {
    title: "General Security Best Practices",
    severity: "MEDIUM",
    owasp: "A01:2021 - Broken Access Control",
    measures: [
      {
        category: "HTTPS/TLS",
        priority: "HIGHEST",
        description: "Enforce HTTPS for all communications",
        implementation: [
          "Use TLS 1.2 or higher",
          "Implement HSTS headers",
          "Use strong cipher suites",
          "Redirect HTTP to HTTPS"
        ],
        codeExample: `// HSTS Header
res.setHeader('Strict-Transport-Security', 
  'max-age=31536000; includeSubDomains; preload'
);`,
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        ]
      },
      {
        category: "Access Control",
        priority: "HIGHEST",
        description: "Implement proper authentication and authorization",
        implementation: [
          "Use strong password policies",
          "Implement multi-factor authentication",
          "Follow principle of least privilege",
          "Implement proper session management"
        ],
        resources: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
          "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
        ]
      },
      {
        category: "Security Headers",
        priority: "HIGH",
        description: "Implement comprehensive security headers",
        implementation: [
          "X-Content-Type-Options: nosniff",
          "X-Frame-Options: DENY",
          "Referrer-Policy: strict-origin-when-cross-origin",
          "Permissions-Policy: geolocation=(), microphone=()"
        ],
        codeExample: `// Express security headers
const helmet = require('helmet');
app.use(helmet());`,
        resources: [
          "https://helmetjs.github.io/",
          "https://owasp.org/www-project-secure-headers/"
        ]
      },
      {
        category: "Regular Security Audits",
        priority: "MEDIUM",
        description: "Perform regular security testing and code reviews",
        implementation: [
          "Automated vulnerability scanning",
          "Penetration testing",
          "Code review for security issues",
          "Dependency vulnerability checking"
        ],
        resources: [
          "https://owasp.org/www-project-top-ten/",
          "https://snyk.io/",
          "https://github.com/OWASP/Amass"
        ]
      }
    ]
  }
};

/**
 * Get preventive measures based on vulnerability type
 * @param {string} vulnerabilityType - Type of vulnerability (sql, ddos, xss)
 * @param {number} severity - Severity score (0-100)
 * @returns {Object} Preventive measures with recommendations
 */
function getPreventiveMeasures(vulnerabilityType, severity = 0) {
  const type = vulnerabilityType.toLowerCase();
  let measures = PREVENTIVE_MEASURES.general;
  
  if (type.includes('sql') || type.includes('injection')) {
    measures = PREVENTIVE_MEASURES.sqlInjection;
  } else if (type.includes('ddos') || type.includes('dos') || type.includes('flood')) {
    measures = PREVENTIVE_MEASURES.ddos;
  } else if (type.includes('xss') || type.includes('script')) {
    measures = PREVENTIVE_MEASURES.xss;
  }
  
  // Filter measures based on severity
  const filteredMeasures = {
    ...measures,
    detectedSeverity: severity,
    severityLevel: getSeverityLevel(severity),
    timestamp: new Date().toISOString(),
    measures: filterBySeverity(measures.measures, severity)
  };
  
  return filteredMeasures;
}

/**
 * Get severity level label
 */
function getSeverityLevel(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "MINIMAL";
}

/**
 * Filter measures by priority based on severity
 * Always returns at least basic measures regardless of severity
 */
function filterBySeverity(measures, severity) {
  // Always show measures if severity > 0, even basic ones
  if (severity <= 0) {
    // For minimal/no severity, still show HIGHEST priority measures as best practices
    return measures.filter(m => m.priority === 'HIGHEST');
  }
  
  const minPriority = severity >= 80 ? 'HIGHEST' : 
                     severity >= 60 ? 'HIGH' :
                     severity >= 40 ? 'MEDIUM' : 'LOW';
  
  const priorityOrder = ['HIGHEST', 'HIGH', 'MEDIUM', 'LOW'];
  const minIndex = priorityOrder.indexOf(minPriority);
  
  return measures.filter(m => priorityOrder.indexOf(m.priority) >= minIndex);
}

/**
 * Generate a comprehensive security report
 */
function generateSecurityReport(vulnerabilities) {
  const report = {
    generatedAt: new Date().toISOString(),
    summary: {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.score >= 80).length,
      highCount: vulnerabilities.filter(v => v.score >= 60 && v.score < 80).length,
      mediumCount: vulnerabilities.filter(v => v.score >= 40 && v.score < 60).length,
      lowCount: vulnerabilities.filter(v => v.score >= 20 && v.score < 40).length
    },
    vulnerabilities: [],
    overallRecommendations: []
  };
  
  // Process each vulnerability
  for (const vuln of vulnerabilities) {
    const measures = getPreventiveMeasures(vuln.type || vuln.name, vuln.score);
    report.vulnerabilities.push({
      name: vuln.name,
      type: vuln.type || 'general',
      score: vuln.score,
      severity: getSeverityLevel(vuln.score),
      preventiveMeasures: measures
    });
  }
  
  // Generate overall recommendations
  report.overallRecommendations = generateOverallRecommendations(vulnerabilities);
  
  return report;
}

/**
 * Generate overall security recommendations
 */
function generateOverallRecommendations(vulnerabilities) {
  const recommendations = [];
  
  const criticalVulns = vulnerabilities.filter(v => v.score >= 80);
  const highVulns = vulnerabilities.filter(v => v.score >= 60 && v.score < 80);
  
  if (criticalVulns.length > 0) {
    recommendations.push({
      priority: "IMMEDIATE",
      action: "URGENT: Address critical vulnerabilities immediately",
      details: criticalVulns.map(v => v.name).join(", ") + " require immediate attention"
    });
  }
  
  if (highVulns.length > 0) {
    recommendations.push({
      priority: "HIGH",
      action: "Address high-priority vulnerabilities within 1 week",
      details: highVulns.map(v => v.name).join(", ") + " should be addressed soon"
    });
  }
  
  recommendations.push({
    priority: "ONGOING",
    action: "Implement regular security maintenance",
    details: [
      "Schedule weekly vulnerability scans",
      "Update dependencies monthly",
      "Conduct quarterly penetration tests",
      "Review access logs daily"
    ]
  });
  
  return recommendations;
}

module.exports = {
  getPreventiveMeasures,
  generateSecurityReport,
  PREVENTIVE_MEASURES
};
