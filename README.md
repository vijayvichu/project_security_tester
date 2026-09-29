# Vuln AI Web Scanner

A **local security assessment dashboard** for authorized penetration testing and vulnerability scanning. This tool provides a user-friendly web interface to perform SQL Injection vulnerability detection and DDoS/stress testing on web applications.

## 🎯 What It Does

Project Security Tester enables authorized security professionals and developers to:

- **SQL Injection (SQLi) Detection**: Automatically scan web applications for SQL injection vulnerabilities by testing form inputs and URL parameters with crafted payloads
- **DDoS/Stress Testing**: Evaluate web server resilience and performance under high-concurrency load with configurable attack parameters
- **Real-Time Monitoring**: Watch scan progress and test results in real-time through a responsive web dashboard
- **Detailed Reporting**: Generate comprehensive logs and vulnerability reports from each security assessment

## ⚙️ Components

- **`pentest_tool/`** — FastAPI-based web dashboard and Python security scanning modules
  - `app.py` — Main FastAPI application serving the dashboard UI and API endpoints
  - `attacker/` — Core scanning engines (SQLi detector and DDoS simulator)
  - `templates/` — HTML/CSS/JavaScript frontend interface
- **`SECURITY.md`** — Vulnerability reporting and credential handling guidelines
- **`SECURITY_REPORT.md`** — Security review findings and remediation status

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Virtual environment (`.venv`)
- Windows (for PowerShell commands) or adapt to your shell

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vijayvichu/project_security_tester.git
   cd project_security_tester
