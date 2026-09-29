# VULN AI Web Scanner

Project Security Tester is a local security assessment dashboard for authorized testing. It provides controlled DDoS/load testing and SQL injection checks through a FastAPI web interface.

## Components

- `pentest_tool/`: FastAPI dashboard and Python scanners.
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

## Authorized use only

Run scanners only against systems you own or have explicit permission to test. Use conservative limits and isolated targets for load testing. Do not commit `.env`, credentials, private keys, or target-specific secrets. See [SECURITY.md](SECURITY.md) for the full policy.
