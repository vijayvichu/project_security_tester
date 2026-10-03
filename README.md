 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ █████╗ ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝

A real-time web penetration testing dashboard for authorized security assessment

Python FastAPI OWASP License Show Image  [![OWASP](https://img.shields.io/badge/OWASP-Top%2010-FF0000?style=for-the-badge)](https://owasp.org)

⚠️ Authorized use only. This tool is designed for testing systems you own or have explicit written permission to test. Built and demonstrated on localhost for ethical compliance.

</div>
🧠 What Is This?

VulnAI is a final-year bachelor's research project — a locally-hosted penetration testing dashboard that performs real SQL injection detection and real HTTP stress testing against a target web application, with everything streamed live to a cyberpunk-styled dashboard.

No fake data. No simulated results. Every request, every payload, every timeout — live on screen as it happens.

⚡ Features
🔴 DDoS / HTTP Stress Tester
Fires real concurrent HTTP requests at your target using Python asyncio + aiohttp
Configurable concurrency (up to 150 parallel connections), request cap, and duration limit
Live response time chart — see exactly when and how much your server starts to degrade
Server Overwhelm Meter — visual gauge that rises as response times increase under load
Per-request live log: HTTP status code, latency in ms, timeouts, connection refusals
Auto-stops at your configured limits — no runaway attacks
🟣 SQL Injection Scanner
30 OWASP Top 10 SQL injection payloads tested against every form field on the target page
Automatically crawls the target for HTML forms — including login pages and admin panels
Tests all major SQLi classes:
🔴 Auth Bypass — ' OR '1'='1, admin'--, ') OR ('1'='1
🔴 Error-Based — extracts DB version via MySQL / MSSQL / PostgreSQL error messages
🟠 UNION-Based — column enumeration for data extraction (UNION SELECT NULL,NULL--)
🟡 Blind Boolean — detects true/false response differences
🟡 Time-Based Blind — measures SLEEP() and WAITFOR DELAY induced delays
🔴 Stacked Queries — multi-statement injection (; DROP TABLE, ; INSERT INTO)
🔴 File Read/Write — load_file('/etc/passwd'), INTO OUTFILE probes
Detects vulnerabilities via SQL error signatures, response length delta, and response time delay
Every payload tested appears instantly in the live log as it runs
Confirmed vulnerabilities populate a sortable results table with severity, field name, payload, and evidence
📡 Real-Time Dashboard
Server-Sent Events (SSE) stream — no page refresh needed, logs update as requests fire
Chart.js response time graph — dual-axis showing avg response time and requests/sec live
Split-panel layout: stress test on the left, SQLi scanner on the right
Cyberpunk aesthetic with live status indicators, overwhelm meter, and per-module badges
🖥️ Dashboard
┌──────────────────────────────────┬────────────────────────────────┐
│  ⚡ DDoS STRESS TEST             │  🔍 SQL INJECTION SCANNER      │
│                                  │                                │
│  Sent   OK    Failed   Req/s     │  Payloads: 87  Vulns: 2       │
│  3,241  3,198   43     187/s     │  Forms Found: 2               │
│                                  │                                │
│  Overwhelm [████████░░] 76%      │  🚨 CRITICAL · Auth Bypass    │
│                                  │  Field: password              │
│  Response time ↗ (ms)  Req/s ↗  │  Payload: ' OR '1'='1        │
│  ▁▂▃▄▆▇████████ | ──────────    │  Evidence: MySQL error found  │
│                                  │                                │
│  [0.4s] #242 ✅ HTTP 200 · 11ms │  [23/30] Time-Based · 4012ms  │
│  [0.4s] #243 ⏱️ TIMEOUT          │  > baseline — VULNERABLE      │
│  [0.4s] #244 🔴 CONN REFUSED    │  [24/30] UNION · HTTP 200...  │
└──────────────────────────────────┴────────────────────────────────┘
🚀 Getting Started
Prerequisites
Python 3.10 or higher
pip
Install & Run
bash
# 1. Clone the repo
git clone https://github.com/vijayvichu/project_security_tester.git
cd project_security_tester/pentest_tool

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the dashboard
uvicorn app:app --host 0.0.0.0 --port 9000 --reload

Open your browser → http://localhost:9000

Make sure your target web app is already running (e.g. on http://localhost:8000) before starting a scan.

📁 Project Structure
project_security_tester/
│
└── pentest_tool/
    ├── app.py              ← FastAPI backend — routes, SSE streaming, API endpoints
    ├── requirements.txt    ← Python dependencies
    │
    ├── attacker/
    │   ├── __init__.py
    │   ├── ddos.py         ← Async HTTP stress tester (asyncio + aiohttp)
    │   └── sqli.py         ← OWASP SQLi scanner (30 payloads, form crawler)
    │
    └── templates/
        └── index.html      ← Live dashboard UI (Chart.js, SSE, cyberpunk theme)
🛠️ Tech Stack
Layer	Technology
Backend	Python 3.10+, FastAPI, Uvicorn
Async HTTP Flooding	aiohttp
Form Crawling & SQLi	requests, BeautifulSoup4
Real-Time Streaming	Server-Sent Events (SSE)
Charts	Chart.js
Frontend	Vanilla JS, CSS custom properties
Fonts	Orbitron, Share Tech Mono
⚙️ Configuration Options
Option	Default	Range	Description
Concurrency	50	1–150	Parallel HTTP connections
Max Requests	3,000	100–50,000	Auto-stop threshold
Duration Limit	60s	5–300s	Maximum attack runtime
SQLi Payloads	30	—	OWASP payload count per field
🔐 Ethical Design

This tool was built with responsible use as a core design requirement:

✅ Localhost / own-system focused — developed and demonstrated entirely on local infrastructure
✅ Hard concurrency cap — maximum 150 connections regardless of input
✅ Auto-stop enforcement — attacks terminate at configured request or time limits
✅ SQLi detection only — reads and analyses responses, does not modify or delete data
✅ Open codebase — every request sent is visible in the live log; nothing hidden

Do not use against any system you do not own or have explicit written authorization to test.

📄 License

MIT License — see LICENSE for details.

<div align="center">

Built for a Bachelor's Final Year Project in Cybersecurity

Real attacks. Real results. Ethical boundaries.

</div>
