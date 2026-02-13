#!/usr/bin/env python3
"""
anomalydetector.py

Anomaly detector for suspicious/malicious IPs based on recent access logs.

This version adds:
- CSV export of detected anomalies.
- Blocklist file export (one IP per line).
- Suspicious pattern detection (SQLi, XSS, directory traversal, etc.)
- Known malicious user agent detection
- Enhanced feature engineering for better accuracy
- Improved heuristic scoring with adaptive thresholds
- Better error handling and edge case fixes

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
from statistics import mean, stdev
from typing import Dict, List, Tuple, Optional

# Optional ML imports
try:
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore
    from sklearn.preprocessing import StandardScaler  # type: ignore
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# Known malicious user agents (common scanning/exploitation tools)
KNOWN_MALICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "metasploit", "nessus", "openvas",
    "havij", "webscarab", "burp", "zap", "w3af", "skipfish", "wfuzz",
    "gobuster", "dirb", "dirbuster", "ffuf", "john", "hydra", "medusa",
    "python-urllib", "curl", "wget", "lwp", "libwww-perl", "scanner",
    "bot", "crawler", "spider", "curl", "httpclient"
]

# Suspicious path patterns (regex-based attack signatures)
SUSPICIOUS_PATTERNS = [
    (r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)", "SQL Injection pattern"),
    (r"(?i)(<script|javascript:|vbscript:|onload|onerror|onmouseover)", "XSS pattern"),
    (r"(?i)(\.\./|\.\.\\|%2e%2e|/\.\./|/\.\.\\)", "Directory traversal pattern"),
    (r"(?i)(/etc/passwd|/boot.ini|/win.ini|/proc/self|/proc/sys|/proc/cmdline)", "File access pattern"),
    (r"(?i)(eval\(|system\(|exec\(|shell_exec\(|passthru\(|popen\(|proc_open\()", "Code injection pattern"),
    (r"(?i)(base64_decode|gzuncompress|str_rot13|assert\()", "PHP obfuscated code pattern"),
    (r"(?i)(or 1=1|and 1=1|' or '|' --|; --|/\*|\*/)", "SQL injection bypass pattern"),
    (r"(?i)(wp-login|wp-admin|phpmyadmin|admin|login|signin|auth)", "Admin panel access pattern"),
    (r"(?i)(\.env|\.git|\.svn|config\.php|settings\.py|Dockerfile)", "Sensitive file access pattern"),
    (r"(?i)(whoami|id|uname|cat|ls|wget|curl|nc|netcat)", "System command pattern"),
    (r"(?i)(ping|nslookup|dig|host)", "DNS reconnaissance pattern"),
]

# HTTP methods that are suspicious when overused
SUSPICIOUS_METHODS = ["POST", "PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "CONNECT"]

# Optional web deps (import lazily if --serve is used)
FASTAPI_AVAILABLE = False
def _import_fastapi():
    global FASTAPI_AVAILABLE
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import JSONResponse
        import uvicorn
        FASTAPI_AVAILABLE = True
        return FastAPI, HTTPException, Request, JSONResponse, uvicorn
    except Exception:
        FASTAPI_AVAILABLE = False
        return None, None, None, None, None

# Optional URL fetching
REQUESTS_AVAILABLE = False
def _import_requests():
    global REQUESTS_AVAILABLE
    try:
        import requests
        REQUESTS_AVAILABLE = True
        return requests
    except Exception:
        REQUESTS_AVAILABLE = False
        return None

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


def check_suspicious_patterns(path: str, agent: str) -> List[str]:
    """
    Check if a request path or user agent matches known suspicious patterns.
    Returns a list of detected pattern names.
    """
    detected = []
    
    # Check path patterns
    for pattern, name in SUSPICIOUS_PATTERNS:
        if re.search(pattern, path):
            detected.append(name)
            break  # Only report one pattern per category
    
    # Check user agent
    agent_lower = agent.lower() if agent else ""
    for malicious_agent in KNOWN_MALICIOUS_AGENTS:
        if malicious_agent.lower() in agent_lower:
            detected.append(f"Known malicious user agent: {malicious_agent}")
            break
    
    return detected


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
    if size and size.isdigit():
        size = int(size)
    elif size and size == "-":
        size = 0
    else:
        try:
            size = int(size)
        except (ValueError, TypeError):
            size = 0

    # Check for suspicious patterns
    agent = d.get("agent") or ""
    suspicious = check_suspicious_patterns(path, agent)
    
    return {
        "ip": d.get("ip"),
        "time": ts,
        "method": method,
        "path": path,
        "status": status,
        "size": size,
        "referrer": d.get("referrer") or "",
        "agent": agent,
        "raw": line.rstrip("\n"),
        "suspicious_patterns": suspicious,
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
        "methods": Counter(),
        "first_seen": None,
        "last_seen": None,
        "timestamps": [],
        "bytes": 0,
        "samples": [],
        "suspicious_patterns": Counter(),
        "unique_agents": set(),
        "rapid_requests": 0,
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
        d["methods"][e.get("method") or ""] += 1
        if e.get("agent"):
            d["agents"][e["agent"]] += 1
            d["unique_agents"].add(e["agent"])
        if d["first_seen"] is None or ts < d["first_seen"]:
            d["first_seen"] = ts
        if d["last_seen"] is None or ts > d["last_seen"]:
            d["last_seen"] = ts
        d["timestamps"].append(ts.timestamp())
        d["bytes"] += e.get("size", 0)
        if len(d["samples"]) < 5:
            d["samples"].append(e["raw"])
        
        # Track suspicious patterns
        for pattern in e.get("suspicious_patterns", []):
            d["suspicious_patterns"][pattern] += 1
    
    # Calculate rapid requests
    for ip, d in per_ip.items():
        timestamps_sorted = sorted(d["timestamps"])
        for i in range(1, len(timestamps_sorted)):
            if timestamps_sorted[i] - timestamps_sorted[i-1] < 1.0:
                d["rapid_requests"] += 1

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
        pct_3xx = sum(v for k, v in d["statuses"].items() if k.startswith("3")) / status_total
        
        unique_paths = len(d["paths"])
        unique_agents_count = len(d["unique_agents"])
        
        # Suspicious method usage
        suspicious_method_count = sum(d["methods"].get(m, 0) for m in SUSPICIOUS_METHODS)
        pct_suspicious_methods = suspicious_method_count / count if count > 0 else 0.0
        
        # Suspicious pattern count
        suspicious_count = sum(d["suspicious_patterns"].values())
        
        avg_bytes = d["bytes"] / count if count else 0

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
            "unique_agents": unique_agents_count,
            "avg_bytes": avg_bytes,
            "pct_3xx": pct_3xx,
            "suspicious_patterns": dict(d["suspicious_patterns"]),
            "suspicious_count": suspicious_count,
            "pct_suspicious_methods": pct_suspicious_methods,
            "rapid_requests": d["rapid_requests"],
            "rapid_request_ratio": d["rapid_requests"] / count if count > 0 else 0.0,
            "path_entropy": entropy,
            "samples": d["samples"],
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
        }
    return summary


def build_feature_matrix(summary: Dict[str, dict]) -> Tuple[List[str], List[List[float]]]:
    """
    Build a feature matrix (rows correspond to IPs) and a list of IP keys.
    Enhanced features for better anomaly detection accuracy.
    """
    keys = []
    rows = []
    
    # Collect values for normalization
    all_counts = []
    all_rpms = []
    all_unique_paths = []
    all_suspicious_counts = []
    all_rapid_ratios = []
    
    for ip, m in summary.items():
        all_counts.append(m["count"])
        all_rpms.append(m["rpm"] or 0)
        all_unique_paths.append(m["unique_paths"])
        all_suspicious_counts.append(m["suspicious_count"])
        all_rapid_ratios.append(m["rapid_request_ratio"])
    
    # Calculate max values for normalization
    max_count = max(all_counts) if all_counts else 1
    max_rpm = max(all_rpms) if all_rpms else 1
    max_paths = max(all_unique_paths) if all_unique_paths else 1
    max_suspicious = max(all_suspicious_counts) if all_suspicious_counts else 1
    max_rapid = max(all_rapid_ratios) if all_rapid_ratios else 1

    for ip, m in summary.items():
        keys.append(ip)
        count = m["count"]
        rpm = m["rpm"] if m["rpm"] is not None else 0.0
        pct_4xx = m["pct_4xx"]
        pct_5xx = m["pct_5xx"]
        pct_3xx = m["pct_3xx"]
        unique_paths = m["unique_paths"]
        unique_agents = m["unique_agents"]
        avg_bytes = m["avg_bytes"]
        entropy = m["path_entropy"]
        avg_ia = m["avg_interarrival"] if m["avg_interarrival"] is not None else None
        std_ia = m["std_interarrival"] if m["std_interarrival"] is not None else 0.0
        suspicious_count = m["suspicious_count"]
        pct_suspicious_methods = m["pct_suspicious_methods"]
        rapid_ratio = m["rapid_request_ratio"]

        # Transform features
        f_count = math.log1p(count)
        f_rpm = math.log1p(rpm) if rpm and math.isfinite(rpm) else 0.0
        f_unique_paths = math.log1p(unique_paths)
        f_unique_agents = math.log1p(unique_agents)
        f_avg_bytes = math.log1p(avg_bytes) if avg_bytes is not None else 0.0
        f_entropy = entropy if entropy is not None else 0.0
        f_freq = 1.0 / avg_ia if avg_ia and avg_ia > 0 else 0.0
        f_std_ia = std_ia if std_ia is not None else 0.0
        f_suspicious = math.log1p(suspicious_count)
        f_suspicious_norm = suspicious_count / max_suspicious if max_suspicious > 0 else 0.0
        f_pct_suspicious_methods = pct_suspicious_methods
        f_rapid_ratio = rapid_ratio
        f_rapid_norm = rapid_ratio / max_rapid if max_rapid > 0 else 0.0
        f_count_norm = count / max_count if max_count > 0 else 0.0
        f_rpm_norm = rpm / max_rpm if max_rpm > 0 else 0.0
        f_paths_norm = unique_paths / max_paths if max_paths > 0 else 0.0
        
        row = [
            f_count,
            f_rpm,
            pct_4xx,
            pct_5xx,
            pct_3xx,
            f_unique_paths,
            f_unique_agents,
            f_avg_bytes,
            f_entropy,
            f_freq,
            f_std_ia,
            f_suspicious,
            f_suspicious_norm,
            f_pct_suspicious_methods,
            f_rapid_ratio,
            f_rapid_norm,
            f_count_norm,
            f_rpm_norm,
            f_paths_norm,
        ]
        rows.append(row)
    return keys, rows


def detect_with_isolation_forest(rows: List[List[float]], contamination: float, random_state: int = 42) -> Tuple[List[int], List[float]]:
    """
    Run IsolationForest on the provided feature rows with improved preprocessing.
    Returns:
        - preds: list where -1 is anomaly, 1 is normal
        - scores: anomaly scores (the lower -> more anomalous)
    """
    import numpy as _np  # local import for optional dependency
    if len(rows) == 0:
        return [], []
    
    X = _np.asarray(rows, dtype=float)
    
    # Handle edge case: single sample
    if len(X) == 1:
        return [1], [0.0]
    
    # Handle edge case: constant features
    X_var = _np.var(X, axis=0)
    X_var[X_var == 0] = 1.0
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Use more trees for better accuracy
    n_estimators = min(200, max(50, len(X) * 2))
    model = IsolationForest(
        contamination=contamination, 
        random_state=random_state,
        n_estimators=n_estimators,
        max_samples='auto',
        bootstrap=False
    )
    model.fit(X_scaled)
    preds = model.predict(X_scaled).tolist()
    scores = model.decision_function(X_scaled).tolist()
    return preds, scores


def heuristic_detector(summary: Dict[str, dict], contamination: float = 0.03) -> Tuple[List[int], List[float]]:
    """
    Enhanced heuristic detector with adaptive scoring.
    Returns preds and scores (higher score = more anomalous).
    """
    names = list(summary.keys())
    raw_scores = []
    
    # Collect all values for adaptive threshold calculation
    all_rpms = []
    all_suspicious_counts = []
    all_rapid_ratios = []
    all_pct_4xx = []
    all_pct_5xx = []
    all_path_entropies = []
    all_unique_paths = []
    
    for ip in names:
        m = summary[ip]
        all_rpms.append(m.get("rpm") or 0.0)
        all_suspicious_counts.append(m.get("suspicious_count") or 0)
        all_rapid_ratios.append(m.get("rapid_request_ratio") or 0.0)
        all_pct_4xx.append(m.get("pct_4xx") or 0.0)
        all_pct_5xx.append(m.get("pct_5xx") or 0.0)
        all_path_entropies.append(m.get("path_entropy") or 0.0)
        all_unique_paths.append(m.get("unique_paths") or 0)
    
    # Calculate percentiles for adaptive thresholds
    rpm_75 = _percentile(all_rpms, 75) if all_rpms else 0
    suspicious_75 = _percentile(all_suspicious_counts, 75) if all_suspicious_counts else 0
    rapid_75 = _percentile(all_rapid_ratios, 75) if all_rapid_ratios else 0
    pct_4xx_75 = _percentile(all_pct_4xx, 75) if all_pct_4xx else 0
    pct_5xx_75 = _percentile(all_pct_5xx, 75) if all_pct_5xx else 0
    entropy_75 = _percentile(all_path_entropies, 75) if all_path_entropies else 0
    paths_75 = _percentile(all_unique_paths, 75) if all_unique_paths else 0
    
    for ip in names:
        m = summary[ip]
        s = 0.0
        
        # Request rate (rpm) - weighted heavily for high rates
        rpm = m.get("rpm") or 0.0
        if rpm > rpm_75:
            s += min(10.0, (rpm / max(rpm_75, 1)) * 3.0)
        else:
            s += min(5.0, (rpm / max(rpm_75, 1)) * 1.0)
        
        # Error rates - 5xx is more severe
        pct_4xx = m.get("pct_4xx", 0.0)
        pct_5xx = m.get("pct_5xx", 0.0)
        if pct_4xx > pct_4xx_75:
            s += pct_4xx * 8.0
        if pct_5xx > pct_5xx_75:
            s += pct_5xx * 12.0
        
        # Suspicious patterns - very high weight
        suspicious_count = m.get("suspicious_count") or 0
        if suspicious_count > 0:
            s += min(15.0, suspicious_count * 5.0)
        
        # Path diversity (scanning indicator)
        unique_paths = m.get("unique_paths", 0)
        if unique_paths > paths_75:
            s += min(8.0, unique_paths * 0.5)
        
        # Path entropy
        entropy = m.get("path_entropy", 0.0)
        if entropy > entropy_75:
            s += min(5.0, entropy * 3.0)
        
        # Rapid request ratio (DDoS/flooding indicator)
        rapid_ratio = m.get("rapid_request_ratio") or 0.0
        if rapid_ratio > rapid_75:
            s += min(10.0, rapid_ratio * 8.0)
        
        # Suspicious HTTP methods
        pct_suspicious_methods = m.get("pct_suspicious_methods") or 0.0
        s += pct_suspicious_methods * 10.0
        
        raw_scores.append(s)
    
    # Normalize scores to 0..1
    max_score = max(raw_scores) if raw_scores else 1.0
    min_score = min(raw_scores) if raw_scores else 0.0
    score_range = max_score - min_score if max_score != min_score else 1.0
    norm = [(s - min_score) / score_range for s in raw_scores]
    
    # Adaptive threshold
    threshold = max(0.5, _percentile(norm, int((1 - min(contamination, 0.5)) * 100)) if norm else 0.7)
    
    preds = [-1 if n >= threshold else 1 for n in norm]
    decision_scores = [1.0 - n for n in norm]
    return preds, decision_scores


def _percentile(data: List[float], percentile: float) -> float:
    """Calculate percentile of data."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * percentile / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


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
        
        # Suspicious patterns
        suspicious_patterns = ip_summary.get("suspicious_patterns", {})
        if suspicious_patterns:
            for pattern, count in suspicious_patterns.items():
                if count > 0:
                    reasons.append(f"Detected {pattern}")
        
        # Rapid requests
        if ip_summary.get("rapid_request_ratio", 0) > 0.5:
            reasons.append("High rate of rapid requests (possible flooding)")
        
        # Suspicious methods
        if ip_summary.get("pct_suspicious_methods", 0) > 0.3:
            reasons.append("High usage of unusual HTTP methods")

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
                "suspicious_patterns": suspicious_patterns,
                "rapid_request_ratio": ip_summary.get("rapid_request_ratio"),
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


def write_csv_report(report: dict, csv_path: str) -> None:
    """Write anomalies to a CSV file."""
    anomalies = report.get("anomalies", [])
    if not anomalies:
        logger.info("No anomalies to write to CSV.")
        return
    
    fieldnames = ["ip", "score", "count", "rpm", "pct_4xx", "pct_5xx", "unique_paths", "unique_agents", "avg_bytes", "first_seen", "last_seen", "reasons"]
    
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for anomaly in anomalies:
            row = {k: v for k, v in anomaly.items() if k in fieldnames}
            row["reasons"] = "; ".join(anomaly.get("reasons", []))
            writer.writerow(row)
    
    logger.info("CSV report written to %s", csv_path)


def write_blocklist(report: dict, blocklist_path: str, append: bool = False) -> None:
    """Write anomalous IPs to a blocklist file (one IP per line)."""
    anomalies = report.get("anomalies", [])
    if not anomalies:
        logger.info("No anomalies to write to blocklist.")
        return
    
    mode = "a" if append else "w"
    with open(blocklist_path, mode, encoding="utf-8") as f:
        for anomaly in anomalies:
            f.write(anomaly["ip"] + "\n")
    
    logger.info("Blocklist %s to %s (%d IPs)", "appended" if append else "written", blocklist_path, len(anomalies))


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
            status_codes = [200, 400, 401, 403, 404, 500, 503]
            weights = [10, 15, 10, 20, 25, 15, 5]
        else:
            # Normal IPs make few requests with normal patterns
            request_count = random.randint(1, 10)
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


def run_detection(entries: List[dict], window_minutes: int = 10, contamination: float = 0.03) -> dict:
    """Run anomaly detection on log entries and return report."""
    now = datetime.now(timezone.utc)
    summary = aggregate_per_ip(entries, window_minutes=window_minutes, now=now)
    keys, rows = build_feature_matrix(summary)
    
    if not keys:
        return {"error": "No IPs found after aggregation", "anomalies": []}
    
    if ML_AVAILABLE:
        try:
            preds, scores = detect_with_isolation_forest(rows, contamination=contamination)
            logger.info("IsolationForest used for detection.")
        except Exception as e:
            logger.warning("IsolationForest failed (%s). Falling back to heuristic detector.", e)
            preds, scores = heuristic_detector(summary, contamination=contamination)
    else:
        logger.info("ML libs not available; using heuristic detector.")
        preds, scores = heuristic_detector(summary, contamination=contamination)
    
    report = build_report(keys, rows, preds, scores, summary, contamination=contamination)
    return report


def create_app() -> "FastAPI":
    """Create and configure FastAPI application."""
    FastAPI, HTTPException, Request, JSONResponse, uvicorn = _import_fastapi()
    if FastAPI is None:
        raise ImportError("FastAPI is not installed. Install with: pip install fastapi uvicorn")
    
    app = FastAPI(title="Anomaly Detector API", description="Detect malicious IPs from access logs")
    
    @app.get("/health")
    async def health():
        return {"status": "healthy", "ml_available": ML_AVAILABLE}
    
    @app.post("/detect")
    async def detect(request: Request):
        """Detect anomalies from log data."""
        body = await request.json()
        
        # Check API key if required
        api_key = os.environ.get("REQUIRE_API_KEY")
        if api_key:
            provided_key = request.headers.get("x-api-key")
            if provided_key != api_key:
                raise HTTPException(status_code=401, detail="Invalid or missing API key")
        
        # Parse parameters
        logs = body.get("logs", "")
        sample = body.get("sample", 0)
        window_minutes = body.get("window_minutes", 10)
        contamination = body.get("contamination", 0.03)
        csv_out = body.get("csv_out")
        blocklist_out = body.get("blocklist_out")
        append_blocklist = body.get("append_blocklist", False)
        
        # Get entries
        if logs:
            lines = logs.strip().split("\n")
            entries = [parse_log_line(line) for line in lines if line.strip()]
            entries = [e for e in entries if e is not None]
        elif sample and sample > 0:
            entries = generate_sample_entries(n_ips=sample, requests_per_ip=10)
        else:
            raise HTTPException(status_code=400, detail="Either 'logs' or 'sample' must be provided")
        
        # Run detection
        report = run_detection(entries, window_minutes=window_minutes, contamination=contamination)
        
        # Save outputs if requested
        if csv_out:
            write_csv_report(report, csv_out)
            report["csv_saved_to"] = csv_out
        
        if blocklist_out:
            write_blocklist(report, blocklist_out, append=append_blocklist)
            report["blocklist_saved_to"] = blocklist_out
        
        return report
    
    @app.get("/anomalies")
    async def get_anomalies():
        """Get list of detected anomalous IPs."""
        # Generate sample data for demo
        entries = generate_sample_entries(n_ips=50, requests_per_ip=10)
        report = run_detection(entries)
        return report
    
    return app


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(description="Detect anomalous/malicious IPs from access logs.")
    parser.add_argument("--log", "-l", nargs="*", help="Path(s) to access log file(s). Use '-' or omit to read stdin.")
    parser.add_argument("--url", "-u", help="Target URL to simulate scanning against (generates synthetic log entries).")
    parser.add_argument("--window-minutes", type=int, default=10, help="Time window (minutes) of recent logs to analyze.")
    parser.add_argument("--contamination", type=float, default=0.03, help="Estimated proportion of anomalies (used by IsolationForest).")
    parser.add_argument("--out", "-o", help="Write JSON report to this file (default stdout).")
    parser.add_argument("--csv-out", help="Write CSV report to this file.")
    parser.add_argument("--blocklist-out", help="Write blocklist (one IP per line) to this file.")
    parser.add_argument("--sample", type=int, default=0, help="Generate synthetic sample data with N IPs (for testing).")
    parser.add_argument("--serve", action="store_true", help="Start FastAPI server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for FastAPI server.")
    parser.add_argument("--port", type=int, default=8000, help="Port for FastAPI server.")
    parser.add_argument("--verbosity", "-v", action="count", default=0, help="Increase verbosity (use -v for INFO, -vv for DEBUG).")
    args = parser.parse_args(argv)

    # logging verbosity
    if args.verbosity >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbosity >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # Start FastAPI server if requested
    if args.serve:
        FastAPI, HTTPException, Request, JSONResponse, uvicorn = _import_fastapi()
        if FastAPI is None:
            logger.error("FastAPI is not installed. Install with: pip install fastapi uvicorn")
            sys.exit(1)
        
        app = create_app()
        
        # Check for API key
        api_key = os.environ.get("REQUIRE_API_KEY")
        if api_key:
            logger.info("API key authentication is enabled")
        
        logger.info(f"Starting FastAPI server on {args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
        return

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

    # Run detection
    report = run_detection(entries, window_minutes=args.window_minutes, contamination=args.contamination)

    # Save outputs if requested
    if args.csv_out:
        write_csv_report(report, args.csv_out)
    
    if args.blocklist_out:
        write_blocklist(report, args.blocklist_out)

    out_json = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_json)
        logger.info("Report written to %s", args.out)
    else:
        print(out_json)


if __name__ == "__main__":
    main()
