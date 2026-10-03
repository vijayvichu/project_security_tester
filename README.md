<div align="center">

```
 ___      ___  ___  ___       ________   ________  ___     
|\  \    /  /||\  \|\  \     |\   ___  \|\   __  \|\  \    
\ \  \  /  / /\ \  \\\  \    \ \  \\ \  \ \  \|\  \ \  \   
 \ \  \/  / /  \ \  \\\  \    \ \  \\ \  \ \   __  \ \  \  
  \ \    / /    \ \  \\\  \    \ \  \\ \  \ \  \ \  \ \  \ 
   \ \__/ /      \ \_______\    \ \__\\ \__\ \__\ \__\ \__\
    \|__|/        \|_______|     \|__| \|__|\|__|\|__|\|__|
```

# VulnAI
### Web Penetration Testing Dashboard

**Real SQL Injection Detection · Real HTTP Stress Testing · Live Results**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Latest-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-FF0000?style=for-the-badge)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-00ffc8?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

> ⚠️ **Authorized use only. Built and demonstrated on localhost for ethical compliance. Only test systems you own or have explicit written permission to test.**

</div>

---

## 🧠 What Is VulnAI?

**VulnAI** is a final-year bachelor's research project — a locally-hosted penetration testing dashboard that performs **real SQL injection detection** and **real HTTP stress testing** against a target web application, with everything streamed live to a cyberpunk-styled real-time dashboard.

No fake data. No simulated results. Every request, every payload, every timeout — streamed live to your screen as it happens.

---

## ⚡ Features

### 🔴 DDoS / HTTP Stress Tester
- Fires **real concurrent HTTP requests** at your target using Python `asyncio` + `aiohttp`
- Configurable **concurrency** (up to 150 parallel connections), **request cap**, and **duration limit**
- **Live response time chart** — watch your server degrade in real time under load
- **Server Overwhelm Meter** — visual gauge that rises as response times increase
- Per-request live log: HTTP status code, latency in ms, timeouts, connection refusals
- **Auto-stops** at your configured limits — no runaway attacks

### 🟣 SQL Injection Scanner
- **30 OWASP Top 10 SQL injection payloads** tested against every input field discovered on the target
- Automatically **crawls the target** for HTML forms — including login pages and admin panels
- Covers all major SQLi classes:
  - 🔴 **Auth Bypass** — `' OR '1'='1`, `admin'--`, `') OR ('1'='1`
  - 🔴 **Error-Based** — triggers MySQL / MSSQL / PostgreSQL error messages
  - 🟠 **UNION-Based** — column enumeration for data extraction
  - 🟡 **Blind Boolean** — detects true/false response differences
  - 🟡 **Time-Based Blind** — measures `SLEEP()` and `WAITFOR DELAY` delays
  - 🔴 **Stacked Queries** — multi-statement injection attempts
  - 🔴 **File Read/Write** — `load_file('/etc/passwd')`, `INTO OUTFILE` probes
- Detects vulnerabilities via **SQL error signatures**, **response length delta**, and **time delay analysis**
- Every payload streamed live to the dashboard log as it fires
- Confirmed vulnerabilities populate a **results table** with severity, field, payload, and evidence

### 📡 Real-Time Dashboard
- **Server-Sent Events (SSE)** — logs update live with zero page refresh
- **Chart.js response time graph** — dual axis showing avg response time and requests/sec
- Split-panel layout: stress tester on the left, SQLi scanner on the right
- Cyberpunk aesthetic with live status indicators and per-module control

---

## 🖥️ Dashboard Preview

```
┌──────────────────────────────────┬────────────────────────────────┐
│  ⚡ DDoS STRESS TEST             │  🔍 SQL INJECTION SCANNER      │
│                                  │                                │
│  Sent   OK    Failed   Req/s     │  Payloads: 87   Vulns: 2      │
│  3,241  3,198   43     187/s     │  Forms Found: 2               │
│                                  │                                │
│  Overwhelm [████████░░] 76%      │  🚨 CRITICAL · Auth Bypass    │
│                                  │  Field: password              │
│  Response Time (ms) ↗            │  Payload: ' OR '1'='1        │
│  ▁▂▃▄▆▇████████                 │  Evidence: MySQL error found  │
│                                  │                                │
│  [0.4s] #242 ✅ HTTP 200 · 11ms │  [23/30] Time-Based · 4012ms  │
│  [0.4s] #243 ⏱️  TIMEOUT         │  > baseline — VULNERABLE      │
│  [0.4s] #244 🔴 CONN REFUSED    │  [24/30] UNION · HTTP 200...  │
└──────────────────────────────────┴────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip

### Install & Run

```bash
# 1. Clone the repo
git clone https://github.com/vijayvichu/project_security_tester.git
cd project_security_tester/pentest_tool

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the dashboard
uvicorn app:app --host 0.0.0.0 --port 9000 --reload
```

Open your browser → **`http://localhost:9000`**

> Make sure your target web app is already running (e.g. on `http://localhost:8000`) before starting a scan.

---

## 📁 Project Structure

```
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
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Async HTTP Flooding | aiohttp |
| Form Crawling & SQLi | requests, BeautifulSoup4 |
| Real-Time Streaming | Server-Sent Events (SSE) |
| Charts | Chart.js |
| Frontend | Vanilla JS, CSS |
| Fonts | Orbitron, Share Tech Mono |

---

## ⚙️ Configuration

| Option | Default | Range | Description |
|---|---|---|---|
| Concurrency | 50 | 1 – 150 | Parallel HTTP connections |
| Max Requests | 3,000 | 100 – 50,000 | Auto-stop threshold |
| Duration Limit | 60s | 5 – 300s | Maximum test runtime |
| SQLi Payloads | 30 | — | OWASP payload count per field |

---

## 🔐 Ethical Design

This tool was built with responsible use as a core design requirement:

- ✅ **Localhost focused** — developed and demonstrated entirely on local infrastructure
- ✅ **Hard concurrency cap** — maximum 150 connections regardless of input
- ✅ **Auto-stop enforcement** — tests terminate at configured request or time limits
- ✅ **SQLi detection only** — reads and analyses responses, does not modify or delete data
- ✅ **Fully transparent** — every request sent is visible in the live log

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for a Bachelor's Final Year Project in Cybersecurity**

*Real attacks. Real results. Ethical boundaries.*

</div>
