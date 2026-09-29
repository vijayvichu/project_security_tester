# Project Security Tester

Project Security Tester is a local security assessment toolkit for authorized testing. It combines a Node.js service with a FastAPI dashboard for controlled DDoS/load testing, SQL injection checks, IP logging, preventive guidance, and anomaly detection.

## Components

- `index.js`: Node.js/Express service with scanning routes, rate limiting, request validation, IP logging, and optional MySQL persistence.
- `pentest_tool/`: FastAPI dashboard and Python scanners.
- `ml/anomalydetector.py`: Optional anomaly-detection service.
- `utils/`: Node.js testing and reporting helpers.
- `SECURITY.md`: Vulnerability reporting and credential-handling policy.
- `SECURITY_REPORT.md`: Security review findings and remediation status.

## Run the FastAPI dashboard

From the repository root:

```powershell
cd pentest_tool
..\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 9000 --reload
```

Open <http://localhost:9000>.

Install Python dependencies with:

```powershell
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the Node.js service

Install JavaScript dependencies, configure `.env` from `.env.example`, and start the service:

```powershell
npm install
npm start
```

Set `REQUIRE_API_KEY=true` and provide randomly generated `API_KEYS` before exposing the service beyond a trusted local environment.

## Authorized use only

Run scanners only against systems you own or have explicit permission to test. Use conservative limits and isolated targets for load testing. Do not commit `.env`, credentials, private keys, or target-specific secrets. See [SECURITY.md](SECURITY.md) for the full policy.
