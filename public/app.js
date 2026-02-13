async function runSQLTest() {
  const url = document.getElementById("url").value;
  if (!url) {
    out({ error: "Please enter a URL" });
    return;
  }
  
  try {
    const res = await fetch("/scan/sql", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
      
    if (!res.ok) {
      const errorText = await res.text();
      out({ error: `Server error: ${res.status} ${res.statusText}`, details: errorText });
      return;
    }
    
    const data = await res.json();
    out(data);
    
    // Update vulnerability chart
    if (data && typeof updateVulnChart === 'function') {
      updateVulnChart(data, 'sql');
    }
    
    // Display preventive measures in scanner interface
    if (data && typeof displayPreventiveMeasures === 'function') {
      displayPreventiveMeasures(data, 'sql');
    }
  } catch (err) {
    out({ error: `Failed to connect: ${err.message}. Make sure the server is running.` });
  }
}

async function runDDOSTest() {
  const url = document.getElementById("url").value;
  if (!url) {
    out({ error: "Please enter a URL" });
    return;
  }
  
  try {
    const res = await fetch("/scan/ddos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
      
    if (!res.ok) {
      const errorText = await res.text();
      out({ error: `Server error: ${res.status} ${res.statusText}`, details: errorText });
      return;
    }
    
    const data = await res.json();
    out(data);
    if (typeof updateVulnChart === 'function') {
      updateVulnChart(data, 'ddos');
    }
    
    // Display preventive measures in scanner interface
    if (data && typeof displayPreventiveMeasures === 'function') {
      displayPreventiveMeasures(data, 'ddos');
    }
  } catch (err) {
    out({ error: `Failed to connect: ${err.message}. Make sure the server is running.` });
  }
}

async function fetchMaliciousIPs() {
  try {
    const res = await fetch("/malicious-ips");
    const data = await res.json();
    
    // Show the IP logs section
    document.getElementById("ip-logs-section").classList.remove("hidden");
    
    // Display IP logs in the dedicated container
    displayIPLogs(data);
    
    // Also show in output area
    out(data);
  } catch (err) {
    out({ error: err.message });
  }
}

function displayIPLogs(data) {
  const container = document.getElementById("ip-logs-container");
  
  if (!data || data.length === 0) {
    container.innerHTML = `
      <div class="text-center text-gray-400 col-span-full py-8">
        <i class="fas fa-info-circle text-cyan-400 text-4xl mb-2"></i>
        <p>No IP logs found</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = data.map((log, index) => {
    const ip = log.ip_address || log.ip;
    const timestamp = log.detected_at || log.timestamp;
    const id = log.id || index + 1;
    
    return `
      <div class="bg-gray-800/50 rounded-lg p-4 border border-cyan-900/50">
        <div class="flex justify-between items-center mb-2">
          <span class="font-mono font-bold text-lg text-cyan-300">${ip}</span>
          <span class="px-2 py-1 bg-purple-900/50 text-purple-300 text-xs rounded">ID: ${id}</span>
        </div>
        <div class="text-sm text-gray-400">
          <div><span class="text-cyan-200">Detected:</span> ${timestamp || 'N/A'}</div>
        </div>
      </div>
    `;
  }).join('');
}

function closeIPLogs() {
  document.getElementById("ip-logs-section").classList.add("hidden");
}

async function runML() {
  const url = document.getElementById("url").value;
  
  // Show loading state
  out({ loading: "Running ML analysis..." });
  
  try {
    // First, run the ML analysis for the URL (POST request)
    if (url && url.trim() !== '') {
      const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
      if (urlPattern.test(url)) {
        await fetch("/analyze/anomalies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        });
      }
    }
    
    // Fetch accurate ML analysis results using GET endpoint
    const res = await fetch("/detected-malicious-ips");
    const data = await res.json();
    
    out(data);
    
    if (typeof displayMaliciousIPs === 'function') {
      displayMaliciousIPs(data);
    }
  } catch (err) {
    out({ error: err.message });
  }
}

async function fetchDetectedMaliciousIPs() {
  try {
    const res = await fetch("/detected-malicious-ips");
    const data = await res.json();
    
    if (typeof displayMaliciousIPs === 'function') {
      displayMaliciousIPs(data);
    }
    
    out(data);
  } catch (err) {
    out({ error: err.message });
  }
}

function displayMaliciousIPs(data) {
  const container = document.getElementById("malicious-ips-container");
  const summary = document.getElementById("ml-summary");
  
  if (!container) return;
  
  if (summary) {
    summary.classList.remove("hidden");
    const totalEl = document.getElementById("total-analyzed");
    const countEl = document.getElementById("malicious-count");
    if (totalEl) totalEl.textContent = data.totalAnalyzed || 0;
    if (countEl) countEl.textContent = data.anomaliesDetected || data.maliciousIPs?.length || 0;
  }
  
  const maliciousIPs = data.maliciousIPs || data.anomalies || [];
  
  if (maliciousIPs.length === 0) {
    container.innerHTML = `
      <div class="text-center text-gray-400 col-span-full py-8">
        <i class="fas fa-check-circle text-green-400 text-4xl mb-2"></i>
        <p>No malicious IPs detected</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = maliciousIPs.map(ipData => {
    const ip = ipData.ip || ipData;
    const score = ipData.score !== undefined ? Math.abs(ipData.score) : 0;
    const count = ipData.count || 0;
    const rpm = ipData.rpm || 0;
    const reasons = ipData.reasons || [];
    const threatLevel = score > 0.8 ? 'high' : score > 0.5 ? 'medium' : 'low';
    const threatLabel = score > 0.8 ? 'HIGH' : score > 0.5 ? 'MEDIUM' : 'LOW';
    
    return `
      <div class="threat-${threatLevel} rounded-lg p-4">
        <div class="flex justify-between items-center mb-2">
          <span class="font-mono font-bold text-lg">${ip}</span>
          <span class="px-2 py-1 rounded text-xs font-bold ${score > 0.8 ? 'bg-red-600 text-white' : score > 0.5 ? 'bg-yellow-600 text-white' : 'bg-green-600 text-white'}">${threatLabel}</span>
        </div>
        <div class="text-sm text-gray-300 space-y-1">
          <div><span class="text-cyan-200">Score:</span> ${(score * 100).toFixed(1)}%</div>
          <div><span class="text-cyan-200">Requests:</span> ${count}</div>
          <div><span class="text-cyan-200">RPM:</span> ${rpm ? rpm.toFixed(1) : 'N/A'}</div>
        </div>
        ${reasons.length > 0 ? `
        <div class="mt-3 pt-2 border-t border-gray-600">
          <div class="text-xs text-gray-400 mb-1">Reasons:</div>
          <div class="flex flex-wrap gap-1">
            ${reasons.map(r => `<span class="px-2 py-0.5 bg-red-900/50 text-red-300 text-xs rounded">${r}</span>`).join('')}
          </div>
        </div>
        ` : ''}
      </div>
    `;
  }).join('');
}

async function clearRecentAndReload() {
  if (!confirm('Clear all recent threat entries from the UI and server? This cannot be undone.')) return;

  try {
    const res = await fetch('/malicious-ips', { method: 'DELETE' });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      console.warn('Server delete failed', body);
    }
  } catch (err) {
    console.warn('Failed to call server delete:', err.message);
  }

  localStorage.setItem('recentCleared', '1');
  setTimeout(() => location.reload(), 100);
}

function restoreRecentAndReload() {
  localStorage.removeItem('recentCleared');
  setTimeout(() => location.reload(), 100);
}

// Vulnerability Chart - handles both SQL and DDoS tests
let vulnChart = null;

function displayPreventiveMeasures(data, testType) {
  const displaySection = document.getElementById('prevention-display');
  const contentDiv = document.getElementById('prevention-content');
  
  if (!displaySection || !contentDiv) return;
  
  // Check if preventive measures exist
  if (!data || (!data.preventiveMeasures && !data.preventionTips)) {
    displaySection.classList.add('hidden');
    return;
  }
  
  displaySection.classList.remove('hidden');
  let html = '';
  
  if (data.preventiveMeasures) {
    const pm = data.preventiveMeasures;
    const testLabel = testType === 'sql' ? 'SQL Injection Prevention' : 'DDoS Mitigation';
    
    html = `
      <div class="mb-4 p-4 bg-gray-800/50 rounded-lg border border-cyan-500/30">
        <div class="flex items-center justify-between mb-3">
          <h4 class="text-lg font-bold text-cyan-300">${pm.title || testLabel}</h4>
          <span class="px-3 py-1 text-xs font-bold rounded ${
            pm.severityLevel === 'CRITICAL' ? 'bg-red-900 text-red-300' : 
            pm.severityLevel === 'HIGH' ? 'bg-orange-900 text-orange-300' :
            pm.severityLevel === 'MEDIUM' ? 'bg-yellow-900 text-yellow-300' :
            'bg-green-900 text-green-300'
          }">${pm.severityLevel || 'Unknown'}</span>
        </div>
        <p class="text-sm text-gray-400 mb-3">OWASP: ${pm.owasp || 'N/A'}</p>
      </div>
    `;
    
    const measures = pm.measures || [];
    if (measures.length > 0) {
      html += '<div class="space-y-3">';
      measures.forEach((measure, idx) => {
        html += `
          <div class="bg-gray-800/30 rounded-lg p-4 border border-cyan-900/30">
            <div class="flex justify-between items-start mb-2">
              <span class="font-bold text-cyan-300">${idx + 1}. ${measure.category}</span>
              <span class="px-2 py-1 text-xs rounded ${
                measure.priority === 'HIGHEST' ? 'bg-red-900 text-red-300' : 
                measure.priority === 'HIGH' ? 'bg-orange-900 text-orange-300' :
                measure.priority === 'MEDIUM' ? 'bg-yellow-900 text-yellow-300' :
                'bg-green-900 text-green-300'
              }">${measure.priority}</span>
            </div>
            <p class="text-sm text-gray-300 mb-2">${measure.description}</p>
            ${measure.implementation ? `
            <div class="text-xs text-gray-400">
              <span class="text-cyan-400 font-semibold">Implementation:</span>
              <ul class="list-disc list-inside ml-2 mt-1 space-y-1">
                ${measure.implementation.map(i => `<li>${i}</li>`).join('')}
              </ul>
            </div>
            ` : ''}
            ${measure.codeExample ? `
            <div class="mt-2">
              <span class="text-xs text-cyan-400 font-semibold">Code Example:</span>
              <pre class="mt-1 p-2 bg-gray-900 rounded text-xs text-green-400 overflow-x-auto"><code>${measure.codeExample.replace(/</g,'<').replace(/>/g,'>')}</code></pre>
            </div>
            ` : ''}
            ${measure.resources ? `
            <div class="mt-2 flex flex-wrap gap-2">
              ${measure.resources.map(r => `<a href="${r}" target="_blank" class="text-xs text-blue-400 hover:text-blue-300 underline">📚 Resource</a>`).join('')}
            </div>
            ` : ''}
          </div>
        `;
      });
      html += '</div>';
    } else {
      html += '<p class="text-gray-400 text-sm">No specific measures needed for this scan.</p>';
    }
  } else if (data.preventionTips) {
    html = '<ul class="space-y-2">' + data.preventionTips.map(tip => `<li class="text-gray-300">${tip}</li>`).join('') + '</ul>';
  }
  
  contentDiv.innerHTML = html;
}

function updateVulnChart(data, testType = 'ddos') {
  const canvas = document.getElementById('vulnChart');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  
  let score, severity, detectedTechniques, preventionTips;
  let chartData, chartColors, chartLabels;
  let metricsHtml = '';
  
  if (testType === 'sql' && data) {
    // SQL Injection test data
    score = data.score || 0;
    severity = data.severity || 'Unknown';
    detectedTechniques = data.detectedTechniques || [];
    preventionTips = data.preventionTips;
    
    // Chart data for SQL
    chartLabels = ['Safe', 'Error-based', 'Time-based', 'Boolean-based'];
    chartData = [
      Math.max(0, 100 - score),
      detectedTechniques.includes('error-based') ? Math.round(score * 0.4) : 0,
      detectedTechniques.includes('time-based') ? Math.round(score * 0.3) : 0,
      detectedTechniques.includes('boolean-based') ? Math.round(score * 0.3) : 0
    ];
    chartColors = ['#10b981', '#ef4444', '#f59e0b', '#3b82f6'];
    
    const testTypeLabel = document.getElementById('testTypeLabel');
    if (testTypeLabel) testTypeLabel.textContent = 'SQL Injection Test';
    
    // Build metrics HTML
    const testResults = data.results || [];
    const suspiciousCount = testResults.filter(r => r.suspicious).length;
    const totalTests = testResults.length;
    metricsHtml = `
      <div><span class="text-cyan-200">Tests Run:</span> ${totalTests}</div>
      <div><span class="text-cyan-200">Vulnerable:</span> ${suspiciousCount} payloads</div>
      <div><span class="text-cyan-200">Techniques:</span> ${detectedTechniques.length > 0 ? detectedTechniques.join(', ') : 'None detected'}</div>
      <div><span class="text-cyan-200">Status:</span> ${data.vulnerable ? 'VULNERABLE' : 'SECURE'}</div>
    `;
    
    const resultsSection = document.getElementById('test-results-section');
    if (resultsSection) {
      resultsSection.classList.remove('hidden');
      const metricsDiv = document.getElementById('test-results-metrics');
      if (metricsDiv) metricsDiv.innerHTML = metricsHtml;
    }
    
    // Display comprehensive preventive measures
    const preventionSection = document.getElementById('sql-prevention-section');
    if (preventionSection) {
      preventionSection.classList.remove('hidden');
      const list = document.getElementById('sql-prevention-list');
      if (list) {
        let html = '';
        
        // Use new preventive measures format
        if (data.preventiveMeasures) {
          const pm = data.preventiveMeasures;
          html = `
            <div class="mb-4 p-4 bg-gray-800/50 rounded-lg border border-cyan-900/30">
              <div class="flex items-center justify-between mb-2">
                <h4 class="text-lg font-bold text-cyan-300">${pm.title || 'Security Recommendations'}</h4>
                <span class="px-3 py-1 text-xs font-bold rounded ${
                  pm.severityLevel === 'CRITICAL' ? 'bg-red-900 text-red-300' : 
                  pm.severityLevel === 'HIGH' ? 'bg-orange-900 text-orange-300' :
                  pm.severityLevel === 'MEDIUM' ? 'bg-yellow-900 text-yellow-300' :
                  'bg-green-900 text-green-300'
                }">${pm.severityLevel || 'Unknown'}</span>
              </div>
              <p class="text-sm text-gray-400">OWASP: ${pm.owasp || 'N/A'}</p>
            </div>
          `;
          
          const measures = pm.measures || [];
          html += '<ul class="space-y-4">';
          measures.forEach(measure => {
            html += `
              <li class="bg-gray-800/50 rounded-lg p-4 border border-cyan-900/30">
                <div class="flex justify-between items-start mb-2">
                  <span class="font-bold text-cyan-300 text-lg">${measure.category}</span>
                  <span class="px-2 py-1 text-xs rounded ${
                    measure.priority === 'HIGHEST' ? 'bg-red-900 text-red-300' : 
                    measure.priority === 'HIGH' ? 'bg-orange-900 text-orange-300' :
                    measure.priority === 'MEDIUM' ? 'bg-yellow-900 text-yellow-300' :
                    'bg-green-900 text-green-300'
                  }">${measure.priority}</span>
                </div>
                <p class="text-sm text-gray-300 mb-3">${measure.description}</p>
                ${measure.implementation ? `
                <div class="text-xs text-gray-400">
                  <span class="text-cyan-400 font-semibold">Implementation:</span>
                  <ul class="list-disc list-inside ml-2 mt-1 space-y-1">
                    ${measure.implementation.map(i => `<li>${i}</li>`).join('')}
                  </ul>
                </div>
                ` : ''}
                ${measure.codeExample ? `
                <div class="mt-3">
                  <span class="text-xs text-cyan-400 font-semibold">Code Example:</span>
                  <pre class="mt-1 p-3 bg-gray-900 rounded text-xs text-green-400 overflow-x-auto"><code>${measure.codeExample.replace(/</g,'<').replace(/>/g,'>')}</code></pre>
                </div>
                ` : ''}
                ${measure.resources ? `
                <div class="mt-3 flex flex-wrap gap-2">
                  ${measure.resources.map(r => `<a href="${r}" target="_blank" class="text-xs text-blue-400 hover:text-blue-300 underline">📚 Resource</a>`).join('')}
                </div>
                ` : ''}
              </li>
            `;
          });
          html += '</ul>';
        } else if (preventionTips) {
          // Fallback to old format
          html = preventionTips.map(tip => `<li class="mb-2">${tip}</li>`).join('');
        }
        
        list.innerHTML = html;
      }
    }
  } else if ((testType === 'ddos' && data && data.tests) || (testType === 'ddos' && data && data.vulnerability)) {
    // DDoS test data
    if (data.tests) {
      score = data.score || 0;
      severity = data.severity || 'Unknown';
      const tests = data.tests || {};
      
      chartLabels = ['Protected', 'Rate Limit', 'Slowloris', 'HTTP Flood'];
      chartData = [
        Math.max(0, 100 - score),
        tests.rateLimiting?.hasRateLimiting ? 0 : 25,
        tests.slowLoris?.vulnerable ? 25 : 0,
        tests.httpFlood?.protectionDetected ? 0 : 25
      ];
      chartColors = ['#10b981', '#ef4444', '#f59e0b', '#3b82f6'];
      
      metricsHtml = `
        <div><span class="text-cyan-200">Rate Limiting:</span> ${tests.rateLimiting?.hasRateLimiting ? '✅ Protected' : '❌ Vulnerable'}</div>
        <div><span class="text-cyan-200">Resource Exhaustion:</span> ${tests.resourceExhaustion?.vulnerable ? '❌ Vulnerable' : '✅ Protected'}</div>
        <div><span class="text-cyan-200">Slowloris:</span> ${tests.slowLoris?.vulnerable ? '❌ Vulnerable' : '✅ Protected'}</div>
        <div><span class="text-cyan-200">HTTP Flood:</span> ${tests.httpFlood?.protectionDetected ? '✅ Protected' : '❌ Vulnerable'}</div>
        <div><span class="text-cyan-200">Server:</span> ${tests.serverResponse?.server || 'Unknown'}</div>
      `;
      
      // Display comprehensive preventive measures for DDoS
      const preventionSection = document.getElementById('sql-prevention-section');
      if (preventionSection) {
        preventionSection.classList.remove('hidden');
        const list = document.getElementById('sql-prevention-list');
        if (list) {
          let html = '';
          
          if (data.preventiveMeasures) {
            const pm = data.preventiveMeasures;
            html = `
              <div class="mb-4 p-4 bg-gray-800/50 rounded-lg border border-cyan-900/30">
                <div class="flex items-center justify-between mb-2">
                  <h4 class="text-lg font-bold text-cyan-300">${pm.title || 'DDoS Mitigation Recommendations'}</h4>
                  <span class="px-3 py-1 text-xs font-bold rounded ${
                    pm.severityLevel === 'CRITICAL' ? 'bg-red-900 text-red-300' : 
                    pm.severityLevel === 'HIGH' ? 'bg-orange-900 text-orange-300' :
                    'bg-green-900 text-green-300'
                  }">${pm.severityLevel || 'Unknown'}</span>
                </div>
                <p class="text-sm text-gray-400">OWASP: ${pm.owasp || 'N/A'}</p>
              </div>
            `;
            
            const measures = pm.measures || [];
            html += '<ul class="space-y-4">';
            measures.forEach(measure => {
              html += `
                <li class="bg-gray-800/50 rounded-lg p-4 border border-cyan-900/30">
                  <div class="flex justify-between items-start mb-2">
                    <span class="font-bold text-cyan-300 text-lg">${measure.category}</span>
                    <span class="px-2 py-1 text-xs rounded ${
                      measure.priority === 'HIGHEST' ? 'bg-red-900 text-red-300' : 
                      measure.priority === 'HIGH' ? 'bg-orange-900 text-orange-300' :
                      'bg-yellow-900 text-yellow-300'
                    }">${measure.priority}</span>
                  </div>
                  <p class="text-sm text-gray-300 mb-3">${measure.description}</p>
                  ${measure.implementation ? `
                  <div class="text-xs text-gray-400">
                    <span class="text-cyan-400 font-semibold">Implementation:</span>
                    <ul class="list-disc list-inside ml-2 mt-1 space-y-1">
                      ${measure.implementation.map(i => `<li>${i}</li>`).join('')}
                    </ul>
                  </div>
                  ` : ''}
                  ${measure.codeExample ? `
                  <div class="mt-3">
                    <span class="text-xs text-cyan-400 font-semibold">Code Example:</span>
                    <pre class="mt-1 p-3 bg-gray-900 rounded text-xs text-green-400 overflow-x-auto"><code>${measure.codeExample.replace(/</g,'<').replace(/>/g,'>')}</code></pre>
                  </div>
                  ` : ''}
                  ${measure.resources ? `
                  <div class="mt-3 flex flex-wrap gap-2">
                    ${measure.resources.map(r => `<a href="${r}" target="_blank" class="text-xs text-blue-400 hover:text-blue-300 underline">📚 Resource</a>`).join('')}
                  </div>
                  ` : ''}
                </li>
              `;
            });
            html += '</ul>';
          } else if (data.preventionTips) {
            html = data.preventionTips.map(tip => `<li class="mb-2">${tip}</li>`).join('');
          }
          
          list.innerHTML = html;
        }
      }
    } else {
      score = data.vulnerability?.score || 0;
      severity = data.vulnerability?.level || 'Unknown';
      const components = data.vulnerability?.components || {};
      
      chartLabels = ['Safe', 'Error Rate', 'Latency', 'Instability'];
      chartData = [
        Math.max(0, 100 - score),
        Math.round((components.errorScore || 0) / 40 * 30),
        Math.round((components.latencyScore || 0) / 30 * 30),
        Math.round((components.stabilityScore || 0) / 20 * 20)
      ];
      chartColors = ['#10b981', '#ef4444', '#f59e0b', '#3b82f6'];
      
      const preventionSection = document.getElementById('sql-prevention-section');
      if (preventionSection) preventionSection.classList.add('hidden');
    }
    
    const testTypeLabel = document.getElementById('testTypeLabel');
    if (testTypeLabel) testTypeLabel.textContent = 'DDoS Vulnerability Test';
    
    const resultsSection = document.getElementById('test-results-section');
    if (resultsSection) {
      resultsSection.classList.remove('hidden');
      const metricsDiv = document.getElementById('test-results-metrics');
      if (metricsDiv) metricsDiv.innerHTML = metricsHtml;
    }
  } else {
    chartLabels = ['Safe', 'Unsafe'];
    chartData = [100, 0];
    chartColors = ['#10b981', '#ef4444'];
    
    const testTypeLabel = document.getElementById('testTypeLabel');
    if (testTypeLabel) testTypeLabel.textContent = '-';
    
    const resultsSection = document.getElementById('test-results-section');
    if (resultsSection) resultsSection.classList.add('hidden');
    const preventionSection = document.getElementById('sql-prevention-section');
    if (preventionSection) preventionSection.classList.add('hidden');
  }
  
  const vulnPercent = document.getElementById('vulnPercent');
  const severityLabel = document.getElementById('severityLabel');
  
  if (vulnPercent) vulnPercent.textContent = score + '%';
  if (severityLabel) {
    severityLabel.textContent = severity;
    severityLabel.className = 'text-xs font-bold mt-1 ' + 
      (severity === 'CRITICAL' || severity === 'Critical' ? 'text-red-500' : 
       severity === 'HIGH' || severity === 'High' ? 'text-orange-500' :
       severity === 'MEDIUM' || severity === 'Medium' ? 'text-yellow-500' :
       severity === 'LOW' || severity === 'Low' ? 'text-green-500' : 'text-gray-400');
  }
  
  if (vulnChart) {
    vulnChart.destroy();
  }
  
  vulnChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: chartLabels,
      datasets: [{
        data: chartData,
        backgroundColor: chartColors,
        borderWidth: 2,
        borderColor: '#1e293b'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '50%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#94a3b8',
            font: { size: 10 },
            boxWidth: 12
          }
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              return context.label + ': ' + context.raw + '%';
            }
          }
        }
      }
    }
  });
}

function out(msg) {
  document.getElementById("output").textContent = JSON.stringify(msg, null, 2);
}
