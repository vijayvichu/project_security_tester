#!/usr/bin/env python3
"""
anomalydetector.py

Anomaly detector for suspicious/malicious IPs based on recent access logs.

This version adds:
- CSV export of detected anomalies.
- Blocklist file export (one IP per line).
- A simple HTTP API (FastAPI) so your web app can call detection server-side.
  - POST /detect accepts JSON with `logs` (string) or `sample` (int) and detection options.
  - If the environment variable REQUIRE_API_KEY is set, requests must include header `x-api-key`.

Usage (CLI):
  - Run detection from log files (same as before):
      python anomalydetector.py --log access.log --window-minutes 10 --out report.json --csv-out report.csv --blocklist-out blocklist.txt

  - Scan a URL:
      python anomalydetector.py --url <target-url> --sample 50

  - Start the API server:
      REQUIRE_API_KEY=secret python anomalydetector.py --serve --host 127.0.0.1 --port 8000

API:
  POST /detect
    JSON body:
      {
        "logs": "raw log contents (CLF/combined)",       # OR
        "sample": 50,                                    # generate synthetic data (for testing)
        "window_minutes": 10,
        "contamination": 0.03,
        "csv_out": "/tmp/report.csv",                    # optional: server-side path to save CSV
        "blocklist_out": "/tmp/blocklist.txt",          # optional: server-side path to save blocklist
        "append_blocklist": false
      }
    Response: JSON report (same structure as CLI output). If CSV/blocklist saved, response will
    include the saved file paths.

Security:
  - Only run this on logs for systems you own or have explicit permission to analyze.
  - Prefer binding the API to localhost and use an API key (REQUIRE_API_KEY) when exposing to networks.

Dependencies:
  pip install numpy scikit-learn fastapi uvicorn requests

Author: (vijay)
"""
from __future__ import annotations
import argparse
import csv
import json
import logging
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean, stdev, median
from typing import Dict, List, Tuple, Any, Optional

# Optional ML imports
try:
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# Optional web deps (import lazily if --serve is used)
try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False

# Optional URL fetching
try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

# Regex to parse Common/Combined Log Format lines
LOG_RE = re.compile(
    r'(?P<ip>\S+) '                     # IP
    r'(?P<ident>\S+) '                  # ident
    r'(?P<authuser>\S+) '               # authuser
    r'\[(?P<time>[^\]]+)\] '            # time
    r'"(?P<request>[^"]*)" '            # request line
    r'(?P<status>\d{3}) '               # status
    r'(?P<size>\S+)'                    # size
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'  # optional referrer & agent
)
# Time format in logs: 10/Oct/2000:13:55:36 -0700
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

logger = logging.getLogger("anomalydetector")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_log_line(line: str) -> dict | None:
    m = LOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()

    # parse timestamp
    ts = None
    ts_str = d.get("time", "")
    try:
        ts = datetime.strptime(ts_str, TIME_FMT)
    except Exception:
        # try without timezone, assume UTC
        try:
            ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            ts = None

    request = d.get("request") or ""
    parts = request.split()
    method = parts[0] if len(parts) >= 1 else ""
    path = parts[1] if len(parts) >= 2 else ""
    status = int(d.get("status") or 0)
    size = d.get("size")
    size = int(size) if size and size.isdigit() else 0

    return {
        "ip": d.get("ip"),
        "time": ts,
        "method": method,
        "path": path,
        "status": status,
        "size": size,
        "referrer": d.get("referrer") or "",
        "agent": d.get("agent") or "",
        "raw": line.rstrip("\n"),
    }


def read_log_lines(paths: List[str]) -> List[dict]:
    entries = []
    if not paths or paths == ["-"]:
        it = sys.stdin
        logger.info("Reading logs from STDIN...")
        for line in it:
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
        return entries

    for p in paths:
        if p == "-":
            logger.info("Reading logs from STDIN...")
            for line in sys.stdin:
                parsed = parse_log_line(line)
                if parsed:
                    entries.append(parsed)
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parsed = parse_log_line(line)
                    if parsed:
                        entries.append(parsed)
        except FileNotFoundError:
            logger.warning("Log file not found: %s", p)
        except PermissionError:
            logger.warning("Permission denied reading: %s", p)
    return entries


def aggregate_per_ip(entries: List[dict], window_minutes: int, now: datetime | None = None) -> Dict[str, dict]:
    """
    Aggregate metrics per IP for entries within the last `window_minutes`.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)

    per_ip = defaultdict(lambda: {
        "count": 0,
        "paths": Counter(),
        "statuses": Counter(),
        "agents": Counter(),
        "first_seen": None,
        "last_seen": None,
        "timestamps": [],
        "bytes": 0,
        "samples": [],
    })

    for e in entries:
        ts = e.get("time")
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue

        ip = e["ip"]
        d = per_ip[ip]
        d["count"] += 1
        d["paths"][e.get("path") or ""] += 1
        d["statuses"][str(e.get("status"))] += 1
        if e.get("agent"):
            d["agents"][e["agent"]] += 1
        if d["first_seen"] is None or ts < d["first_seen"]:
            d["first_seen"] = ts
        if d["last_seen"] is None or ts > d["last_seen"]:
            d["last_seen"] = ts
        d["timestamps"].append(ts.timestamp())
        d["bytes"] += e.get("size", 0)
        if len(d["samples"]) < 5:
            d["samples"].append(e["raw"])

    # Build summary metrics per IP
    summary = {}
    for ip, d in per_ip.items():
        count = d["count"]
        first = d["first_seen"]
        last = d["last_seen"]
        duration = (last - first).total_seconds() if first and last and last > first else 0.0
        rpm = (count / (duration / 60.0)) if duration > 0 else float("inf") if count > 0 else 0.0
        timestamps_sorted = sorted(d["timestamps"])
        inter_arrivals = [t2 - t1 for t1, t2 in zip(timestamps_sorted, timestamps_sorted[1:])] if len(timestamps_sorted) > 1 else []
        avg_ia = mean(inter_arrivals) if inter_arrivals else None
        std_ia = stdev(inter_arrivals) if len(inter_arrivals) > 1 else None

        status_total = sum(d["statuses"].values()) or 1
        pct_4xx = sum(v for k, v in d["statuses"].items() if k.startswith("4")) / status_total
        pct_5xx = sum(v for k, v in d["statuses"].items() if k.startswith("5")) / status_total

        unique_paths = len(d["paths"])
        unique_agents = len(d["agents"])

        # simple path "entropy" (proxy for scanning many different endpoints)
        path_counts = list(d["paths"].values())
        total_paths = sum(path_counts) or 1
        entropy = -sum((c / total_paths) * math.log((c / total_paths) + 1e-12) for c in path_counts)

        summary[ip] = {
            "count": count,
            "rpm": rpm if math.isfinite(rpm) else None,
            "duration_seconds": duration,
            "avg_interarrival": avg_ia,
            "std_interarrival": std_ia,
            "pct_4xx": pct_4xx,
            "pct_5xx": pct_5xx,
            "unique_paths": unique_paths,
            "unique_agents": unique_agents,
            "avg_bytes": (d["bytes"] / count) if count else 0,
            "path_entropy": entropy,
            "samples": d["samples"],
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
        }
    return summary


def build_feature_matrix(summary: Dict[str, dict]) -> Tuple[List[str], List[List[float]]]:
    """
    Build a feature matrix (rows correspond to IPs) and a list of IP keys.
    Features chosen (scaled later by the model implicitly):
        - log(count + 1)
        - log(rpm + 1)  (use 0 for None)
        - pct_4xx
        - pct_5xx
        - unique_paths
        - unique_agents
        - avg_bytes
        - path_entropy
        - avg_interarrival (seconds) -> use inverse (requests/sec) to prefer higher rate
        - std_interarrival (seconds)
    """
    keys = []
    rows = []
    for ip, m in summary.items():
        keys.append(ip)
        count = m["count"]
        rpm = m["rpm"] if m["rpm"] is not None else 0.0
        pct_4xx = m["pct_4xx"]
        pct_5xx = m["pct_5xx"]
        unique_paths = m["unique_paths"]
        unique_agents = m["unique_agents"]
        avg_bytes = m["avg_bytes"]
        entropy = m["path_entropy"]
        avg_ia = m["avg_interarrival"] if m["avg_interarrival"] is not None else None
        std_ia = m["std_interarrival"] if m["std_interarrival"] is not None else 0.0

        # defensively transform features
        f_count = math.log1p(count)
        f_rpm = math.log1p(rpm) if rpm and math.isfinite(rpm) else 0.0
        f_unique_paths = math.log1p(unique_paths)
        f_unique_agents = math.log1p(unique_agents)
        f_avg_bytes = math.log1p(avg_bytes) if avg_bytes is not None else 0.0
        f_entropy = entropy if entropy is not None else 0.0
        # use inverse IA: higher frequency -> larger number
        f_freq = 1.0 / avg_ia if avg_ia and avg_ia > 0 else 0.0
        f_std_ia = std_ia if std_ia is not None else 0.0

        row = [
            f_count,
            f_rpm,
            pct_4xx,
            pct_5xx,
            f_unique_paths,
            f_unique_agents,
            f_avg_bytes,
            f_entropy,
            f_freq,
            f_std_ia,
        ]
        rows.append(row)
    return keys, rows


def detect_with_isolation_forest(rows: List[List[float]], contamination: float, random_state: int = 42) -> Tuple[List[int], List[float]]:
    """
    Run IsolationForest on the provided feature rows.
    Returns:
        - preds: list where -1 is anomaly, 1 is normal
        - scores: anomaly scores (the lower -> more anomalous)
    """
    import numpy as _np  # local import for optional dependency
    if len(rows) == 0:
        return [], []

    X = _np.asarray(rows, dtype=float)
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(X)
    preds = model.predict(X).tolist()  # 1 (normal) or -1 (anomaly)
    scores = model.decision_function(X).tolist()  # larger means more normal; lower -> more anomalous
    return preds, scores


def heuristic_detector(summary: Dict[str, dict]) -> Tuple[List[int], List[float]]:
    """
    Simple heuristic: compute a score per-IP (0..1) and mark top contamination fraction as anomalies.
    Score combines rpm (or count), error rates, path entropy, and unique paths.
    Returns preds and scores (higher score = more anomalous).
    """
    names = list(summary.keys())
    scores = []
    for ip in names:
        m = summary[ip]
        s = 0.0
        # weight rpm/count heavily
        rpm = m.get("rpm") or 0.0
        s += min(10.0, (rpm / 10.0)) * 2.0  # scaled
        s += m.get("pct_4xx", 0.0) * 10.0
        s += m.get("pct_5xx", 0.0) * 15.0
        s += math.log1p(m.get("unique_paths", 0)) * 2.0
        s += m.get("path_entropy", 0.0)
        scores.append(s)
    # normalize scores to 0..1
    maxs = max(scores) if scores else 1.0
    norm = [s / maxs for s in scores]
    # create preds: mark any above 0.7 as anomaly (this is tunable)
    preds = [ -1 if n >= 0.7 else 1 for n in norm ]
    # output "decision" scores in sklearn style (higher=more normal), so invert normalized here
    decision_scores = [1.0 - n for n in norm]
    return preds, decision_scores


def build_report(keys: List[str], rows: List[List[float]], preds: List[int], scores: List[float], summary: Dict[str, dict], contamination: float) -> dict:
    """
    Build a JSON-serializable report combining ML results and human readable reasons.
    """
    anomalies = []
    for idx, ip in enumerate(keys):
        is_anom = preds[idx] == -1
        score = scores[idx] if idx < len(scores) else None
        ip_summary = summary[ip]
        reasons = []
        # heuristics for human readable reasons
        if (ip_summary.get("rpm") or 0) > 100:
            reasons.append("Very high request rate (rpm)")
        if ip_summary.get("pct_5xx", 0) > 0.2:
            reasons.append("High 5xx ratio")
        if ip_summary.get("pct_4xx", 0) > 0.5:
            reasons.append("Many 4xx responses (scanning/brute force?)")
        if ip_summary.get("unique_paths", 0) > 20:
            reasons.append("Accessing many distinct paths (possible scanner)")

        if is_anom:
            anomalies.append({
                "ip": ip,
                "score": score,
                "count": ip_summary.get("count"),
                "rpm": ip_summary.get("rpm"),
                "pct_4xx": ip_summary.get("pct_4xx"),
                "pct_5xx": ip_summary.get("pct_5xx"),
                "unique_paths": ip_summary.get("unique_paths"),
                "unique_agents": ip_summary.get("unique_agents"),
                "avg_bytes": ip_summary.get("avg_bytes"),
                "first_seen": ip_summary.get("first_seen"),
                "last_seen": ip_summary.get("last_seen"),
                "reasons": reasons,
                "samples": ip_summary.get("samples", []),
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_ips_analyzed": len(keys),
        "anomalies_detected": len(anomalies),
        "contamination": contamination,
        "ml_enabled": ML_AVAILABLE,
        "anomalies": anomalies,
    }
    return report


def generate_sample_entries(n_ips: int = 50, requests_per_ip: int = 20) -> List[dict]:
    """
    Generate synthetic log-like entries for quick testing.
    A few IPs will be injected with anomalous behavior.
    """
    import random
    entries = []
    base_time = datetime.now(timezone.utc)
    for i in range(n_ips):
        ip = f"192.0.2.{i%255}"
        # make a couple of IPs explosive/anomalous
        anomalous = (i % 17 == 0)
        cnt = requests_per_ip * (10 if anomalous else 1)
        for j in range(cnt):
            ts = base_time - timedelta(seconds=random.randint(0, 60*10))
            status = random.choices([200, 200, 200, 404, 403, 500], weights=[70,10,5,5,5,5])[0] if not anomalous else random.choices([200,404,403,500], [50,20,10,20])[0]
            size = random.randint(200, 5000)
            path = random.choice(["/", "/login", "/api/data", "/admin", "/wp-login.php", "/search", f"/item/{random.randint(1,1000)}"])
            agent = random.choice(["curl/7.68.0", "Mozilla/5.0", "python-requests/2.25.1", "scanner-bot"])
            line = f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
    return entries


def generate_url_scan_entries(target_url: str, n_ips: int = 50) -> List[dict]:
    """
    Generate synthetic log entries simulating a scan against a target URL.
    Creates entries with various IP addresses attempting different paths and techniques.
    """
    import random
    entries = []
    base_time = datetime.now(timezone.utc)
    
    # Define malicious patterns to simulate scanning activity
    scan_paths = [
        "/", "/admin", "/login", "/wp-login.php", "/wp-admin", 
        "/phpmyadmin", "/config.php", "/web.config", "/.env",
        "/api/users", "/api/admin", "/api/config", "/database.sql",
        "/test.php", "/debug.php", "/shell.php", "/upload.php",
        "/../../../etc/passwd", "/xmlrpc.php", "/?id=1", "/?id=1'",
        "/search.php?q=<script>", "/comments.php?id=1 OR 1=1"
    ]
    
    user_agents = [
        "curl/7.68.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "python-requests/2.25.1", "sqlmap/1.5.2", "nikto/2.1.6",
        "nmap/7.92", "masscan", "MetaSploit", "Nessus", "OpenVAS"
    ]
    
    logger.info(f"Generating URL scan simulation against {target_url}")
    
    for i in range(n_ips):
        # Vary behavior: some IPs are "normal", others are "malicious"
        is_malicious = (i % 5 == 0) or (i % 7 == 0)
        
        if is_malicious:
            # Malicious IPs make many requests with suspicious patterns
            request_count = random.randint(50, 200)
            error_rate = random.choice([0.3, 0.5, 0.7, 0.9])  # High 4xx/5xx rates
            status_codes = [200, 400, 401, 403, 404, 500, 503]
            weights = [10, 15, 10, 20, 25, 15, 5]
        else:
            # Normal IPs make few requests with normal patterns
            request_count = random.randint(1, 10)
            error_rate = 0.05
            status_codes = [200, 304]
            weights = [95, 5]
        
        ip = f"203.0.113.{i % 255}"
        
        for j in range(request_count):
            ts = base_time - timedelta(seconds=random.randint(0, 60*10))
            
            if is_malicious and random.random() > 0.7:
                # Occasionally use suspicious user agent
                agent = random.choice([a for a in user_agents if any(x in a for x in ['sqlmap', 'nikto', 'nmap', 'MetaSploit'])])
            else:
                agent = random.choice(user_agents[:4])
            
            path = random.choice(scan_paths) if is_malicious else "/index.php"
            status = random.choices(status_codes, weights=weights)[0] if is_malicious else 200
            size = random.randint(500, 10000)
            
            line = f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
    
    logger.info(f"Generated {len(entries)} scan simulation entries")
    return entries


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(description="Detect anomalous/malicious IPs from access logs.")
    parser.add_argument("--log", "-l", nargs="*", help="Path(s) to access log file(s). Use '-' or omit to read stdin.")
    parser.add_argument("--url", "-u", help="Target URL to simulate scanning against (generates synthetic log entries).")
    parser.add_argument("--window-minutes", type=int, default=10, help="Time window (minutes) of recent logs to analyze.")
    parser.add_argument("--contamination", type=float, default=0.03, help="Estimated proportion of anomalies (used by IsolationForest).")
    parser.add_argument("--out", "-o", help="Write JSON report to this file (default stdout).")
    parser.add_argument("--sample", type=int, default=0, help="Generate synthetic sample data with N IPs (for testing).")
    parser.add_argument("--verbosity", "-v", action="count", default=0, help="Increase verbosity (use -v for INFO, -vv for DEBUG).")
    args = parser.parse_args(argv)

    # logging verbosity
    if args.verbosity >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbosity >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # Read or generate entries
    if args.url:
        logger.info("Generating URL scan simulation for %s", args.url)
        sample_ips = args.sample if args.sample > 0 else 50
        entries = generate_url_scan_entries(target_url=args.url, n_ips=sample_ips)
    elif args.sample and args.sample > 0:
        logger.info("Generating sample entries (%d IPs)...", args.sample)
        entries = generate_sample_entries(n_ips=args.sample, requests_per_ip=10)
    else:
        paths = args.log if args.log is not None else ["-"]
        entries = read_log_lines(paths)

    if not entries:
        logger.error("No log entries found. Exiting.")
        sys.exit(2)

    now = datetime.now(timezone.utc)
    summary = aggregate_per_ip(entries, window_minutes=args.window_minutes, now=now)
    keys, rows = build_feature_matrix(summary)

    if not keys:
        logger.error("No IPs found after aggregation. Exiting.")
        sys.exit(2)

    if ML_AVAILABLE:
        try:
            preds, scores = detect_with_isolation_forest(rows, contamination=args.contamination)
            # convert sklearn scores so that lower => more anomalous (we keep as-is)
            logger.info("IsolationForest used for detection.")
        except Exception as e:
            logger.warning("IsolationForest failed (%s). Falling back to heuristic detector.", e)
            preds, scores = heuristic_detector(summary)
    else:
        logger.info("ML libs not available; using heuristic detector.")
        preds, scores = heuristic_detector(summary)

    report = build_report(keys, rows, preds, scores, summary, contamination=args.contamination)

    out_json = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_json)
        logger.info("Report written to %s", args.out)
    else:
        print(out_json)


if __name__ == "__main__":
    main()