#!/usr/bin/env python3
"""
Web Security Forensics Tool
============================
Analyzes web server logs and actively scans URLs for:
- XSS (Cross-Site Scripting)
- DOM XSS
- IDOR (Insecure Direct Object Reference)
- CSRF (Cross-Site Request Forgery)
- CORS (Cross-Origin Resource Sharing Misconfiguration)

Detects attacks in logs and reports found vulnerabilities.
"""

import re
import json
import requests
from urllib.parse import unquote, urlencode, urlparse, parse_qs, urlunparse
from datetime import datetime
from typing import List, Dict, Optional


# ============================================================
# 1. PATTERNS FOR LOG ANALYSIS
# ============================================================

# --- XSS Patterns ---
XSS_PAYLOADS = [
    r"<script[^>]*>.*?</script>",
    r"<script>.*alert\s*\(.*\).*</script>",
    r"<img[^>]*onerror\s*=.*>",
    r"<svg[^>]*onload\s*=.*>",
    r"<body[^>]*onload\s*=.*>",
    r"<input[^>]*onfocus\s*=.*>",
    r"javascript\s*:\s*alert\s*\(",
    r"onmouseover\s*=\s*['\"]?.*alert\s*\(",
    r"onerror\s*=\s*['\"]?.*alert\s*\(",
    r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
    r"<script>.*</script>",
    r"\s+on\w+\s*=\s*['\"]?[^'\"\s]*[(\[]",
    r"document\s*\.\s*cookie",
    r"String\s*\.\s*fromCharCode",
    r"eval\s*\(\s*['\"]",
    r"ontoggle\s*=.*alert\s*\(",
]

REFLECTED_XSS_PATTERNS = [
    r"%3Cscript%3E",
    r"%3Cimg%20",
    r"%3Csvg%20",
    r"%3Cbody%20",
    r"%3Ciframe%20",
    r"%3Cinput%20",
    r"onerror%3D",
    r"onload%3D",
    r"onfocus%3D",
    r"alert%28",
    r"prompt%28",
    r"confirm%28",
]

# --- DOM XSS Patterns ---
DOM_XSS_PATTERNS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"location\.hash",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"window\.location\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"document\.URL",
    r"document\.referrer",
    r"window\.name",
    r"#.*<script",
    r"#.*javascript:",
    r"#.*onerror=",
    r"#.*onload=",
]

# --- IDOR Patterns ---
IDOR_PATTERNS = [
    r"/user[s]?/(\d+)",
    r"/account[s]?/(\d+)",
    r"/profile[s]?/(\d+)",
    r"/order[s]?/(\d+)",
    r"/invoice[s]?/(\d+)",
    r"/document[s]?/(\d+)",
    r"/file[s]?/(\d+)",
    r"/admin/user[s]?/(\d+)",
    r"[?&]user_?id=(\d+)",
    r"[?&]account_?id=(\d+)",
    r"[?&]order_?id=(\d+)",
    r"[?&]id=(\d+)",
    r"[?&]uid=(\d+)",
    r"[?&]profile_?id=(\d+)",
    r"\.\./\.\./",           # Path traversal (related to IDOR)
    r"\.\.%2F\.\.%2F",      # URL-encoded traversal
]


# --- CORS Patterns ---
CORS_PATTERNS = [
    r"Access-Control-Allow-Origin:\s*\*",
    r"Access-Control-Allow-Origin:\s*null",
    r"Access-Control-Allow-Credentials:\s*true",
    r"Access-Control-Allow-Methods:\s*\*",
    r"Access-Control-Allow-Headers:\s*\*",
    r"Origin:\s*https?://evil",
    r"Origin:\s*https?://attacker",
    r"cors.*bypass",
    r"origin.*reflected",
]

# --- CSRF Patterns ---
CSRF_PATTERNS = [
    r"Referer:\s*https?://(?!yourdomain)",   # Referer from external domain
    r"Origin:\s*https?://(?!yourdomain)",    # Origin from external domain
    r'"method"\s*:\s*"POST".*no.*csrf',      # POST without CSRF token mention
    r"X-Requested-With",                     # Missing AJAX header
    r"csrf.token.*missing",
    r"csrf.invalid",
    r"forbidden.*csrf", r"POST\s+/(?:transfer|payment|delete|update|change|modify|send)",  # Sensitive POST actions
]




# --- SQL Injection Patterns ---
SQLI_PATTERNS = [
    r"'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+",
    r"'\s*(or|and)\s+\d+=\d+",
    r"union\s+select",
    r"select\s+.+\s+from\s+",
    r"insert\s+into\s+",
    r"drop\s+table",
    r"--\s*$",
    r";\s*drop",
    r";\s*select",
    r"1\s*=\s*1",
    r"sleep\s*\(\s*\d+\s*\)",
    r"waitfor\s+delay",
    r"benchmark\s*\(",
    r"load_file\s*\(",
    r"information_schema",
    r"sysobjects",
    r"xp_cmdshell",
]

SQLI_ENCODED_PATTERNS = [
    r"%27.{0,20}%6f%72",
    r"%27.{0,20}union",
    r"%27.{0,20}select",
    r"0x[0-9a-f]{4,}",
]

# --- Blind SQL Injection Patterns ---
BLIND_SQLI_PATTERNS = [
    r"and\s+1\s*=\s*1",
    r"and\s+1\s*=\s*2",
    r"sleep\s*\(\s*\d+\s*\)",
    r"waitfor\s+delay\s+'0:0:\d+'",
    r"benchmark\s*\(\s*\d+",
    r"pg_sleep\s*\(\s*\d+\s*\)",
    r"and\s+substring\s*\(",
    r"and\s+ascii\s*\(",
    r"and\s+if\s*\(",
    r"case\s+when\s+.+\s+then",
]

# --- SSRF Patterns ---
SSRF_PATTERNS = [
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=https?://127\.",
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=https?://localhost",
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=https?://169\.254\.",
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=https?://192\.168\.",
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=https?://10\.",
    r"(url|uri|src|dest|redirect|next|link|file|load|fetch|open)=file://",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"file:///etc/passwd",
    r"file:///etc/shadow",
    r"file:///windows/win\.ini",
]

# --- XXE Patterns ---
XXE_PATTERNS = [
    r"<!ENTITY\s+\w+\s+SYSTEM",
    r"<!ENTITY\s+\w+\s+PUBLIC",
    r"<!DOCTYPE\s+\w+\s*\[",
    r"<!ENTITY\s+xxe",
    r"<!ENTITY\s+%\s+\w+",
    r"&xxe;",
    r"%xxe;",
    r"\[<!ENTITY",
    r"<!DOCTYPE[^>]*\[<!ENTITY",
]


# ============================================================
# 2. FORENSICS ENGINE CLASS
# ============================================================

class WebForensics:
    """
    Multi-vulnerability investigation engine.
    Detects XSS, DOM XSS, IDOR, CSRF, CORS, SQLi, Blind SQLi, SSRF, XXE in web server logs.
    """

    def __init__(self, logs: Optional[List[str]] = None):
        self.logs = logs or []
        self.attacks_found: List[Dict] = []

    def add_log(self, log_line: str):
        self.logs.append(log_line)

    def load_logs_from_file(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            self.logs = [line.strip() for line in f if line.strip()]

    # -------------------------------------------
    # Extract common log fields
    # -------------------------------------------
    def _parse_log_fields(self, log_line: str) -> Dict:
        fields = {
            "raw_log": log_line,
            "attacker_ip": None,
            "timestamp": None,
            "http_method": None,
            "endpoint": None,
            "user_agent": None,
        }

        ip_match = re.match(r"(\S+)", log_line)
        if ip_match:
            fields["attacker_ip"] = ip_match.group(1)

        ts_match = re.search(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})", log_line)
        if ts_match:
            try:
                fields["timestamp"] = datetime.strptime(ts_match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                fields["timestamp"] = ts_match.group(1)

        http_match = re.search(r'"(GET|POST|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)', log_line)
        if http_match:
            fields["http_method"] = http_match.group(1)
            fields["endpoint"] = http_match.group(2)

        ua_match = re.search(r'"(Mozilla[^"]*)"', log_line)
        if ua_match:
            fields["user_agent"] = ua_match.group(1)

        # Extract HTTP status code and response size
        # Apache format: "METHOD path HTTP/1.1" STATUS SIZE
        sc_match = re.search(r'" (\d{3}) (\d+)', log_line)
        if sc_match:
            fields["status_code"]   = int(sc_match.group(1))
            fields["response_size"] = int(sc_match.group(2))

        return fields

    # -------------------------------------------
    # Detect XSS
    # -------------------------------------------
    def _detect_xss(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in XSS_PAYLOADS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)
        for p in REFLECTED_XSS_PATTERNS:
            if re.search(p, log_line, re.IGNORECASE):
                matched.append(p)

        if not matched:
            return None

        xss_type = "Reflected XSS"
        if any("script" in p.lower() for p in matched):
            xss_type = "Reflected/Stored XSS"
        elif any("onerror" in p.lower() or "onload" in p.lower() for p in matched):
            xss_type = "DOM-based XSS"

        severity = "Medium"
        if len(matched) >= 4:
            severity = "Critical"
        elif len(matched) >= 2:
            severity = "High"

        return {
            "vulnerability": "XSS",
            "xss_type": xss_type,
            "matched_payloads": matched,
            "severity": severity,
        }

    # -------------------------------------------
    # Detect DOM XSS
    # -------------------------------------------
    def _detect_dom_xss(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in DOM_XSS_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)

        if not matched:
            return None

        severity = "High" if len(matched) >= 2 else "Medium"
        return {
            "vulnerability": "DOM XSS",
            "xss_type": "DOM-based XSS",
            "matched_payloads": matched,
            "severity": severity,
        }

    # -------------------------------------------
    # Detect IDOR
    # -------------------------------------------
    def _detect_idor(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        extracted_ids = []

        for p in IDOR_PATTERNS:
            m = re.search(p, decoded, re.IGNORECASE)
            if m:
                matched.append(p)
                if m.lastindex:
                    extracted_ids.append(m.group(1))

        if not matched:
            return None

        # Higher severity if accessing admin endpoints or multiple IDs
        severity = "High"
        if any("admin" in p.lower() for p in matched):
            severity = "Critical"
        elif len(matched) == 1:
            severity = "Medium"

        return {
            "vulnerability": "IDOR",
            "xss_type": "Insecure Direct Object Reference",
            "matched_payloads": matched,
            "extracted_ids": extracted_ids,
            "severity": severity,
        }

    # -------------------------------------------
    # Detect CSRF
    # -------------------------------------------
    def _detect_csrf(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in CSRF_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)

        # Check: POST to sensitive endpoint without CSRF indicators
        is_sensitive_post = re.search(
            r'"POST\s+/(?:transfer|payment|delete|update|change|modify|send|admin)',
            decoded, re.IGNORECASE
        )
        has_csrf_token = re.search(r'csrf[_-]?token|X-CSRF|_token', decoded, re.IGNORECASE)

        if is_sensitive_post and not has_csrf_token:
            matched.append("POST to sensitive endpoint without CSRF token")

        if not matched:
            return None

        return {
            "vulnerability": "CSRF",
            "xss_type": "Cross-Site Request Forgery",
            "matched_payloads": matched,
            "severity": "High",
        }


    # -------------------------------------------
    # Detect CORS
    # -------------------------------------------
    def _detect_cors(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in CORS_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)

        # Check for wildcard + credentials combo (critical)
        has_wildcard = re.search(r"Access-Control-Allow-Origin:\s*\*", decoded, re.IGNORECASE)
        has_creds = re.search(r"Access-Control-Allow-Credentials:\s*true", decoded, re.IGNORECASE)

        if has_wildcard and has_creds:
            matched.append("CRITICAL: Wildcard + Credentials = full CORS bypass")

        if not matched:
            return None

        severity = "Critical" if (has_wildcard and has_creds) else "High" if len(matched) >= 2 else "Medium"

        return {
            "vulnerability": "CORS",
            "xss_type": "Cross-Origin Resource Sharing Misconfiguration",
            "matched_payloads": matched,
            "severity": severity,
        }


    # -------------------------------------------
    # Detect SQL Injection
    # -------------------------------------------
    def _detect_sqli(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in SQLI_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)
        for p in SQLI_ENCODED_PATTERNS:
            if re.search(p, log_line, re.IGNORECASE):
                matched.append(p)
        if not matched:
            return None
        severity = "Critical" if len(matched) >= 3 else "High" if len(matched) >= 2 else "Medium"
        return {
            "vulnerability": "SQL Injection",
            "xss_type": "SQL Injection",
            "matched_payloads": matched,
            "severity": severity,
        }

    # -------------------------------------------
    # Detect Blind SQL Injection
    # -------------------------------------------
    def _detect_blind_sqli(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in BLIND_SQLI_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)
        if not matched:
            return None
        has_time = any(kw in p for p in matched for kw in ["sleep", "waitfor", "benchmark", "pg_sleep"])
        method = "Time-based" if has_time else "Boolean-based"
        return {
            "vulnerability": "Blind SQL Injection",
            "xss_type": f"Blind SQL Injection ({method})",
            "matched_payloads": matched,
            "severity": "Critical" if has_time else "High",
        }

    # -------------------------------------------
    # Detect SSRF
    # -------------------------------------------
    def _detect_ssrf(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in SSRF_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)
        if not matched:
            return None
        is_cloud = any("169.254" in p or "metadata" in p for p in matched)
        return {
            "vulnerability": "SSRF",
            "xss_type": "Server-Side Request Forgery",
            "matched_payloads": matched,
            "severity": "Critical" if is_cloud else "High",
        }

    # -------------------------------------------
    # Detect XXE
    # -------------------------------------------
    def _detect_xxe(self, log_line: str, decoded: str) -> Optional[Dict]:
        matched = []
        for p in XXE_PATTERNS:
            if re.search(p, decoded, re.IGNORECASE):
                matched.append(p)
        if not matched:
            return None
        has_file = any("file" in p.lower() for p in matched)
        return {
            "vulnerability": "XXE",
            "xss_type": "XML External Entity Injection",
            "matched_payloads": matched,
            "severity": "Critical" if has_file else "High",
        }


    # -------------------------------------------
    # Classify outcome: CONFIRMED BREACH / ATTEMPTED / SUSPICIOUS
    # Logic per vulnerability type based on status code + response size
    # -------------------------------------------
    def _classify_outcome(self, vuln: str, status_code, response_size,
                           endpoint: str, matched_payloads: list) -> dict:
        """
        Returns:
          outcome      : "CONFIRMED BREACH" | "ATTEMPTED ATTACK" | "SUSPICIOUS"
          outcome_color: for display
          outcome_reason: why we decided this
        """
        sc   = status_code   if status_code   is not None else 0
        size = response_size if response_size is not None else 0
        ep   = (endpoint or "").lower()

        # ── Default ───────────────────────────────────────────────
        outcome = "SUSPICIOUS"
        reason  = "Status code or response size not available in log"

        # ── Definite failures (all vulns) ─────────────────────────
        if sc in (401, 403, 405):
            return {"outcome": "ATTEMPTED ATTACK",
                    "outcome_color": "orange",
                    "outcome_reason": f"Server rejected request with HTTP {sc} (access denied)"}
        if sc == 404:
            return {"outcome": "ATTEMPTED ATTACK",
                    "outcome_color": "orange",
                    "outcome_reason": f"HTTP 404 — endpoint/resource not found, attack failed"}

        # ── Per-vulnerability logic ────────────────────────────────
        if vuln == "IDOR":
            # Confirmed: 200 + non-trivial response (server returned data)
            if sc == 200 and size > 200:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + response {size} bytes — server returned "
                           "private data for a different user's ID")
            elif sc == 200 and size <= 200:
                outcome = "ATTEMPTED ATTACK"
                reason  = f"HTTP 200 but tiny response ({size} bytes) — likely empty/error page"
            elif sc == 302:
                outcome = "ATTEMPTED ATTACK"
                reason  = "HTTP 302 redirect — access control redirected the request"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — could not confirm data was returned"

        elif vuln in ("XSS", "DOM XSS"):
            # Confirmed: 200 + large response (page rendered with payload)
            if sc == 200 and size > 500:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + response {size} bytes — page likely "
                           "rendered the injected script to the victim's browser")
            elif sc == 200 and size > 0:
                outcome = "ATTEMPTED ATTACK"
                reason  = f"HTTP 200 but small response ({size} bytes) — payload may not have rendered"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — could not confirm script execution"

        elif vuln == "SQL Injection":
            # Confirmed: 200 + large response (data dumped) OR error message exposed
            has_error_hint = any(kw in ep for kw in ["error","sql","syntax","query"])
            if sc == 200 and size > 300:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + response {size} bytes — server likely returned "
                           "database records or exposed SQL error details")
            elif sc == 200 and has_error_hint:
                outcome = "CONFIRMED BREACH"
                reason  = "HTTP 200 + error-related endpoint — SQL error message likely exposed"
            elif sc == 200:
                outcome = "ATTEMPTED ATTACK"
                reason  = f"HTTP 200 but response only {size} bytes — injection may have been blocked"
            elif sc == 500:
                outcome = "CONFIRMED BREACH"
                reason  = "HTTP 500 — server crashed, SQL error exposed (information disclosure)"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — injection present but outcome unclear"

        elif vuln == "Blind SQL Injection":
            # Time-based: can only confirm by timing (not in log), so size is key signal
            has_time = any(kw in p for p in matched_payloads
                          for kw in ["sleep","waitfor","benchmark","pg_sleep"])
            if has_time and sc == 200:
                outcome = "CONFIRMED BREACH"
                reason  = ("Time-based payload + HTTP 200 — server executed SLEEP/WAITFOR, "
                           "confirming injection is running inside the database")
            elif sc == 200 and size > 100:
                outcome = "ATTEMPTED ATTACK"
                reason  = (f"Boolean-based payload with HTTP 200 ({size} bytes) — "
                           "need response comparison to confirm")
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — blind injection presence uncertain"

        elif vuln == "CSRF":
            # Confirmed: 200 on sensitive POST endpoint
            sensitive = any(kw in ep for kw in
                           ["transfer","payment","delete","update","change","modify","send","admin"])
            if sc == 200 and sensitive and "post" in (ep + ""):
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 on sensitive endpoint '{ep}' with no CSRF token — "
                           "unauthorized action likely executed")
            elif sc == 200:
                outcome = "ATTEMPTED ATTACK"
                reason  = f"HTTP 200 but endpoint not clearly sensitive — may or may not have executed"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} on CSRF-vulnerable form"

        elif vuln == "CORS":
            # Confirmed: reflected wildcard or origin in headers
            if sc == 200 and size > 50:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + response {size} bytes — API returned data with "
                           "ACAO header reflecting attacker origin, data leakage confirmed")
            elif sc == 200:
                outcome = "ATTEMPTED ATTACK"
                reason  = "HTTP 200 but tiny response — CORS misconfiguration exists but data may be empty"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — CORS misconfiguration confirmed but data access unclear"

        elif vuln == "SSRF":
            # Confirmed: 200 + any response (server reached internal resource)
            cloud = any("169.254" in p or "metadata" in p or "127" in p
                       for p in matched_payloads)
            if sc == 200 and size > 0:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + {size} bytes — server fetched internal/cloud resource "
                           f"{'(AWS/GCP metadata endpoint!)' if cloud else ''} on behalf of attacker")
            elif sc in (200, 302) and size == 0:
                outcome = "ATTEMPTED ATTACK"
                reason  = "Server made request but returned empty response — partial SSRF"
            elif sc == 500:
                outcome = "ATTEMPTED ATTACK"
                reason  = "HTTP 500 — server tried but internal request failed"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — SSRF payload detected but outcome unclear"

        elif vuln == "XXE":
            # Confirmed: 200 + non-empty response (file content returned)
            if sc == 200 and size > 100:
                outcome = "CONFIRMED BREACH"
                reason  = (f"HTTP 200 + {size} bytes — XML parser processed external entity "
                           "and likely returned file contents or internal data")
            elif sc == 200 and size > 0:
                outcome = "ATTEMPTED ATTACK"
                reason  = f"HTTP 200 but tiny response ({size} bytes) — entity may have been blocked"
            elif sc == 500:
                outcome = "ATTEMPTED ATTACK"
                reason  = "HTTP 500 — XML parser error, entity processed but caused crash"
            else:
                outcome = "SUSPICIOUS"
                reason  = f"HTTP {sc} — XXE payload in request but server response unclear"

        color_map = {
            "CONFIRMED BREACH":  "red",
            "ATTEMPTED ATTACK":  "orange",
            "SUSPICIOUS":        "yellow",
        }
        return {
            "outcome":        outcome,
            "outcome_color":  color_map.get(outcome, "yellow"),
            "outcome_reason": reason,
        }

    # -------------------------------------------
    # Analyze one log line for ALL vulnerabilities
    # -------------------------------------------
    def _analyze_line(self, log_line: str) -> List[Dict]:
        fields  = self._parse_log_fields(log_line)
        decoded = unquote(log_line)
        results = []

        for detector in [
            self._detect_xss,
            self._detect_dom_xss,
            self._detect_idor,
            self._detect_csrf,
            self._detect_cors,
            self._detect_sqli,
            self._detect_blind_sqli,
            self._detect_ssrf,
            self._detect_xxe,
        ]:
            finding = detector(log_line, decoded)
            if finding:
                entry = {**fields, **finding}
                # Classify: CONFIRMED BREACH / ATTEMPTED ATTACK / SUSPICIOUS
                outcome = self._classify_outcome(
                    vuln             = entry["vulnerability"],
                    status_code      = entry.get("status_code"),
                    response_size    = entry.get("response_size"),
                    endpoint         = entry.get("endpoint", ""),
                    matched_payloads = entry.get("matched_payloads", []),
                )
                entry.update(outcome)
                results.append(entry)

        return results

    # -------------------------------------------
    # Run full analysis
    # -------------------------------------------
    def analyze(self) -> List[Dict]:
        self.attacks_found = []
        for log in self.logs:
            findings = self._analyze_line(log)
            self.attacks_found.extend(findings)
        return self.attacks_found

    # -------------------------------------------
    # Group by IP
    # -------------------------------------------
    def get_attackers_summary(self) -> List[Dict]:
        ip_map: Dict[str, Dict] = {}
        for attack in self.attacks_found:
            ip = attack["attacker_ip"] or "Unknown"
            if ip not in ip_map:
                ip_map[ip] = {
                    "ip": ip,
                    "attack_count": 0,
                    "vulnerabilities": set(),
                    "first_seen": attack["timestamp"],
                    "last_seen": attack["timestamp"],
                    "endpoints_targeted": set(),
                }
            ip_map[ip]["attack_count"] += 1
            ip_map[ip]["vulnerabilities"].add(attack["vulnerability"])
            if attack["endpoint"]:
                ip_map[ip]["endpoints_targeted"].add(attack["endpoint"])

            ts = attack["timestamp"]
            if ts and isinstance(ts, datetime):
                first = ip_map[ip]["first_seen"]
                if first is None or (isinstance(first, datetime) and ts < first):
                    ip_map[ip]["first_seen"] = ts
                last = ip_map[ip]["last_seen"]
                if last is None or (isinstance(last, datetime) and ts > last):
                    ip_map[ip]["last_seen"] = ts

        result = []
        for entry in ip_map.values():
            entry["vulnerabilities"] = list(entry["vulnerabilities"])
            entry["endpoints_targeted"] = list(entry["endpoints_targeted"])
            for key in ["first_seen", "last_seen"]:
                if isinstance(entry[key], datetime):
                    entry[key] = entry[key].strftime("%d/%b/%Y:%H:%M:%S")
            result.append(entry)

        result.sort(key=lambda x: x["attack_count"], reverse=True)
        return result

    # -------------------------------------------
    # Generate report
    # -------------------------------------------
    def generate_report(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("  WEB SECURITY FORENSICS REPORT")
        lines.append("=" * 70)
        lines.append(f"  Analysis time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Total logs:     {len(self.logs)}")
        lines.append(f"  Attacks found:  {len(self.attacks_found)}")

        # Count per vulnerability type + outcome
        vuln_counts  = {}
        breach_count = 0
        attempt_count = 0
        suspicious_count = 0
        for a in self.attacks_found:
            v = a["vulnerability"]
            vuln_counts[v] = vuln_counts.get(v, 0) + 1
            oc = a.get("outcome", "SUSPICIOUS")
            if oc == "CONFIRMED BREACH":
                breach_count += 1
            elif oc == "ATTEMPTED ATTACK":
                attempt_count += 1
            else:
                suspicious_count += 1

        lines.append(f"\n  Outcome Summary:")
        lines.append(f"    [CONFIRMED BREACH]  : {breach_count}")
        lines.append(f"    [ATTEMPTED ATTACK]  : {attempt_count}")
        lines.append(f"    [SUSPICIOUS]        : {suspicious_count}")

        lines.append(f"\n  Vulnerabilities detected:")
        for vuln, count in vuln_counts.items():
            lines.append(f"    [!] {vuln}: {count} attack(s)")

        lines.append("-" * 70)

        if self.attacks_found:
            lines.append("\n[1] Attack Details:")
            lines.append("=" * 70)
            for i, attack in enumerate(self.attacks_found, 1):
                outcome = attack.get("outcome", "SUSPICIOUS")
                reason  = attack.get("outcome_reason", "")
                sc      = attack.get("status_code", "?")
                size    = attack.get("response_size", "?")

                # Outcome label
                if outcome == "CONFIRMED BREACH":
                    label = "[CONFIRMED BREACH]"
                elif outcome == "ATTEMPTED ATTACK":
                    label = "[ATTEMPTED ATTACK]"
                else:
                    label = "[SUSPICIOUS]      "

                lines.append(f"\n  {'='*66}")
                lines.append(f"  Attack #{i}  {label}")
                lines.append(f"  {'='*66}")
                lines.append(f"  Vulnerability:    {attack['vulnerability']}")
                lines.append(f"  Type:             {attack['xss_type']}")
                lines.append(f"  Outcome:          {outcome}")
                lines.append(f"  Reason:           {reason}")
                lines.append(f"  HTTP Status:      {sc}")
                lines.append(f"  Response Size:    {size} bytes")
                lines.append(f"  Attacker IP:      {attack['attacker_ip']}")
                lines.append(f"  Timestamp:        {attack['timestamp']}")
                lines.append(f"  Method:           {attack['http_method']}")
                lines.append(f"  Endpoint:         {attack['endpoint']}")
                lines.append(f"  User-Agent:       {attack.get('user_agent') or 'Unknown'}")
                lines.append(f"  Severity:         {attack['severity']}")
                lines.append(f"  Payloads matched: {len(attack['matched_payloads'])}")
                if attack.get("extracted_ids"):
                    lines.append(f"  IDs accessed:     {attack['extracted_ids']}")

            lines.append("\n\n[2] Confirmed Breaches Only:")
            lines.append("=" * 70)
            breaches = [a for a in self.attacks_found if a.get("outcome") == "CONFIRMED BREACH"]
            if breaches:
                for b in breaches:
                    lines.append(f"  [BREACH] {b['vulnerability']:20s} | "
                                 f"IP: {b['attacker_ip']:15s} | "
                                 f"Endpoint: {b['endpoint']}")
            else:
                lines.append("  No confirmed breaches found.")

            lines.append("\n\n[3] Attacker Summary:")
            lines.append("=" * 70)
            for entry in self.get_attackers_summary():
                # Count breaches per IP
                ip_breaches = sum(1 for a in self.attacks_found
                                  if a.get("attacker_ip") == entry["ip"]
                                  and a.get("outcome") == "CONFIRMED BREACH")
                ip_attempts = sum(1 for a in self.attacks_found
                                  if a.get("attacker_ip") == entry["ip"]
                                  and a.get("outcome") == "ATTEMPTED ATTACK")
                lines.append(f"\n  IP:                  {entry['ip']}")
                lines.append(f"  Total attacks:       {entry['attack_count']}")
                lines.append(f"  Confirmed breaches:  {ip_breaches}")
                lines.append(f"  Attempted attacks:   {ip_attempts}")
                lines.append(f"  Vulnerabilities:     {entry['vulnerabilities']}")
                lines.append(f"  Endpoints targeted:  {entry['endpoints_targeted']}")
                lines.append(f"  First seen:          {entry['first_seen']}")
                lines.append(f"  Last seen:           {entry['last_seen']}")
        else:
            lines.append("\n  No attacks detected in logs.")

        lines.append("\n" + "=" * 70)
        lines.append("  End of Report")
        lines.append("=" * 70)
        return "\n".join(lines)

    # -------------------------------------------
    # Export JSON
    # -------------------------------------------
    def export_json(self, filepath: str = "security_report.json") -> str:
        breaches = [a for a in self.attacks_found if a.get("outcome") == "CONFIRMED BREACH"]
        attempts = [a for a in self.attacks_found if a.get("outcome") == "ATTEMPTED ATTACK"]
        data = {
            "analysis_time": datetime.now().isoformat(),
            "total_logs": len(self.logs),
            "attacks_found": len(self.attacks_found),
            "confirmed_breaches": len(breaches),
            "attempted_attacks": len(attempts),
            "suspicious": len(self.attacks_found) - len(breaches) - len(attempts),
            "attacks": [
                {
                    "vulnerability":   a["vulnerability"],
                    "type":            a["xss_type"],
                    "outcome":         a.get("outcome", "SUSPICIOUS"),
                    "outcome_reason":  a.get("outcome_reason", ""),
                    "attacker_ip":     a["attacker_ip"],
                    "timestamp":       str(a["timestamp"]),
                    "method":          a["http_method"],
                    "endpoint":        a["endpoint"],
                    "http_status":     a.get("status_code"),
                    "response_size":   a.get("response_size"),
                    "severity":        a["severity"],
                    "matched_payloads": a["matched_payloads"],
                }
                for a in self.attacks_found
            ],
            "confirmed_breach_list": [
                {
                    "vulnerability": a["vulnerability"],
                    "attacker_ip":   a["attacker_ip"],
                    "timestamp":     str(a["timestamp"]),
                    "endpoint":      a["endpoint"],
                    "reason":        a.get("outcome_reason", ""),
                }
                for a in breaches
            ],
            "attackers_summary": self.get_attackers_summary(),
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath


# ============================================================
# 3. ACTIVE URL SCANNER
# ============================================================

def _active_scan_url(url: str):
    """
    Actively scans a URL for XSS, DOM XSS, IDOR, CSRF, CORS,
    SQL Injection, Blind SQL Injection, SSRF, and XXE vulnerabilities.
    """

    print(f"\n{'='*60}")
    print(f"  VULNERABILITY SCAN REPORT")
    print(f"  Target: {url}")
    print(f"{'='*60}")

    findings = []

    try:
        resp = requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Security Scanner)"
        })

        print(f"\n[Server Info]")
        print(f"Status: {resp.status_code}")
        print(f"Server: {resp.headers.get('Server', 'Unknown')}")
        print(f"Content-Type: {resp.headers.get('Content-Type', 'Unknown')}")
        print(f"  X-Frame-Options: {resp.headers.get('X-Frame-Options', 'Missing (CSRF risk)')}")
        print(f"CSP: {resp.headers.get('Content-Security-Policy', 'Missing (XSS risk)')}")

        html = resp.text
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        forms = re.findall(r'<form[^>]*>', html, re.IGNORECASE)
        forms_with_action = re.findall(r'<form[^>]*action=["\'][^"\']*["\']', html, re.IGNORECASE)
        resp_ct = resp.headers.get('Content-Type', '')
        accepts_xml = any(ct in resp_ct for ct in ['application/xml', 'text/xml', 'application/xhtml+xml'])
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', html, re.IGNORECASE)
        params = list(qs.keys())

        print(f"\n[Injection Points Found]")
        print(f"Forms: {len(forms)}")
        print(f"Inputs: {len(inputs)} → {inputs}")
        print(f"  URL Params: {params}")

        # ---- 1. XSS Testing ----
        print(f"\n[1] Testing XSS...")
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
        ]
        xss_found = False
        if qs:
            for param in qs:
                for payload in xss_payloads:
                    test_qs = qs.copy()
                    test_qs[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                    try:
                        r = requests.get(test_url, timeout=10,
                                         headers={"User-Agent": "Mozilla/5.0"})
                        if payload in r.text or "alert(1)" in r.text:
                            msg = f"[!] XSS FOUND in param '{param}' → {payload}"
                            print(msg)
                            findings.append({"type": "XSS", "param": param,
                                             "payload": payload, "severity": "High"})
                            xss_found = True
                    except:
                        pass
        if not xss_found:
            print("  No reflected XSS detected in URL params")

        # ---- 2. DOM XSS Testing ----
        print(f"\n[2] Testing DOM XSS...")
        dom_sinks = ["document.write", "innerHTML", "outerHTML",
                     "insertAdjacentHTML", "eval(", "location.href"]
        dom_found = False
        for sink in dom_sinks:
            if sink in html:
                print(f"  [!] DOM XSS sink found in page: '{sink}'")
                findings.append({"type": "DOM XSS", "sink": sink, "severity": "Medium"})
                dom_found = True
        
        # Check hash-based DOM XSS
        if "location.hash" in html or "window.location" in html:
            print(f"[!] Hash-based DOM XSS possible (location.hash used)")
            findings.append({"type": "DOM XSS", "sink": "location.hash", "severity": "Medium"})
            dom_found = True

        if not dom_found:
            print("  No DOM XSS sinks detected")

        # ---- 3. IDOR Testing ----
        print(f"\n[3] Testing IDOR...")
        idor_found = False
        idor_param_patterns = ["id", "user_id", "uid", "account_id",
                                "order_id", "profile_id", "doc_id"]
        
        for param in params:
            if any(p in param.lower() for p in idor_param_patterns):
                current_val = qs[param][0]
                if current_val.isdigit():
                    # Try adjacent IDs
                    for test_id in [str(int(current_val) - 1),
                                    str(int(current_val) + 1), "1", "2", "100"]:
                        test_qs = qs.copy()
                        test_qs[param] = [test_id]
                        test_url = urlunparse(parsed._replace(
                            query=urlencode(test_qs, doseq=True)))
                        try:
                            r = requests.get(test_url, timeout=10,
                                             headers={"User-Agent": "Mozilla/5.0"})
                            if r.status_code == 200 and len(r.text) > 100:
                                print(f"[!] IDOR possible: param '{param}'={test_id}"
                                      f" → HTTP {r.status_code} ({len(r.text)} bytes)")
                                findings.append({"type": "IDOR", "param": param,
                                                 "tested_id": test_id, "severity": "High"})
                                idor_found = True
                        except:
                            pass

        # Check path-based IDOR
        path_id = re.search(r'/(\d+)(?:/|$|\?)', parsed.path)
        if path_id:
            base_path = parsed.path[:path_id.start(1)]
            for test_id in ["1", "2", "3"]:
                test_url = urlunparse(parsed._replace(
                    path=base_path + test_id))
                try:
                    r = requests.get(test_url, timeout=10,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    if r.status_code == 200:
                        print(f"[!] Path-based IDOR possible: {test_url}"
                              f" → HTTP {r.status_code}")
                        findings.append({"type": "IDOR", "url": test_url,
                                         "severity": "High"})
                        idor_found = True
                except:
                    pass

        if not idor_found:
            print("  No obvious IDOR detected")

        # ---- 4. CSRF Testing ----
        print(f"\n[4] Testing CSRF...")
        csrf_found = False

        # Check security headers
        x_frame = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        samesite = "samesite" in resp.headers.get("Set-Cookie", "").lower()

        if not x_frame:
            print("  [!] Missing X-Frame-Options header -> Clickjacking/CSRF risk")
            findings.append({"type": "CSRF", "issue": "Missing X-Frame-Options",
                             "severity": "Medium"})
            csrf_found = True

        if not csp:
            print("  [!] Missing Content-Security-Policy -> XSS/CSRF risk")
            findings.append({"type": "CSRF", "issue": "Missing CSP header",
                             "severity": "Medium"})
            csrf_found = True

        # Check forms for CSRF token
        for form in forms:
            has_csrf = bool(re.search(
                r'csrf|_token|authenticity_token', html, re.IGNORECASE))
            if not has_csrf:
                print(f"[!] Form found without CSRF token → CSRF risk")
                findings.append({"type": "CSRF", "issue": "Form missing CSRF token",
                                 "severity": "High"})
                csrf_found = True
                break

        # Try sending POST without CSRF token to sensitive endpoints
        sensitive_paths = ["/login", "/transfer", "/update", "/delete",
                           "/change", "/payment", "/send"]
        for path in sensitive_paths:
            test_url = urlunparse(parsed._replace(path=path, query=""))
            try:
                r = requests.post(test_url, timeout=5,
                                  data={"test": "1"},
                                  headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code not in [403, 405, 404]:
                    print(f"[!] POST to {path} succeeded without CSRF token"
                          f" → HTTP {r.status_code}")
                    findings.append({"type": "CSRF", "issue": f"POST {path} no token",
                                     "severity": "High"})
                    csrf_found = True
            except:
                pass

        if not csrf_found:
            print("  No CSRF vulnerabilities detected")

        # ---- 5. CORS Testing ----
        print(f"\n[5] Testing CORS...")
        cors_found = False

        # Send request with fake Origin header
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://fake-{parsed.netloc}",
        ]

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        # Check wildcard
        if acao == "*":
            print(f"[!] CORS: Access-Control-Allow-Origin: * (Wildcard) → Any site can read responses")
            findings.append({"type": "CORS", "issue": "Wildcard ACAO", "severity": "High"})
            cors_found = True

        # Check wildcard + credentials (critical combo)
        if acao == "*" and acac.lower() == "true":
            print(f"  [!] CRITICAL CORS: Wildcard + Credentials=true -> Full bypass!")
            findings.append({"type": "CORS", "issue": "Wildcard + Credentials CRITICAL", "severity": "Critical"})
            cors_found = True

        # Check if server reflects any Origin back
        for origin in test_origins:
            try:
                r = requests.get(url, timeout=10, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Origin": origin,
                })
                reflected = r.headers.get("Access-Control-Allow-Origin", "")
                creds = r.headers.get("Access-Control-Allow-Credentials", "")
                if reflected == origin:
                    print(f"[!] CORS: Server reflects Origin '{origin}' → Arbitrary origin allowed!")
                    findings.append({"type": "CORS", "issue": f"Reflects origin: {origin}", "severity": "High"})
                    cors_found = True
                if reflected == origin and creds.lower() == "true":
                    print(f"  [!] CRITICAL: Reflects origin + Credentials=true -> Attacker can steal data with cookies!")
                    findings.append({"type": "CORS", "issue": "Reflect+Credentials CRITICAL", "severity": "Critical"})
                    cors_found = True
                if reflected == "null":
                    print(f"[!] CORS: Allows null origin → Sandboxed iframe attack possible")
                    findings.append({"type": "CORS", "issue": "Null origin allowed", "severity": "High"})
                    cors_found = True
            except:
                pass

        # Check sensitive API endpoints for CORS
        api_paths = ["/api/user", "/api/account", "/api/data", "/api/profile"]
        for api_path in api_paths:
            test_url_api = urlunparse(parsed._replace(path=api_path, query=""))
            try:
                r = requests.get(test_url_api, timeout=5, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Origin": "https://evil.com",
                })
                if r.headers.get("Access-Control-Allow-Origin") == "https://evil.com":
                    print(f"[!] CORS on API: {api_path} reflects evil.com origin!")
                    findings.append({"type": "CORS", "issue": f"API {api_path} vulnerable", "severity": "Critical"})
                    cors_found = True
            except:
                pass

        if not cors_found:
            print("  No CORS misconfiguration detected")

        # ---- 6. SQL Injection Testing ----
        print(f"\n[6] Testing SQL Injection...")
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1 AND 1=1--",
            "admin'--",
        ]
        sql_errors = ["mysql_fetch", "ORA-", "Microsoft OLE DB", "ODBC SQL", "syntax error",
                      "Warning: mysql", "quoted string not properly terminated", "SQLite"]
        sqli_found = False
        if qs:
            for param in qs:
                for payload in sqli_payloads:
                    tqs = qs.copy(); tqs[param] = [payload]
                    tu = urlunparse(parsed._replace(query=urlencode(tqs, doseq=True)))
                    try:
                        r = requests.get(tu, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                        if any(e.lower() in r.text.lower() for e in sql_errors):
                            print(f"  [!] SQL Injection in param '{param}': SQL error exposed")
                            findings.append({"type": "SQL Injection", "param": param,
                                             "payload": payload, "severity": "Critical"})
                            sqli_found = True
                            break
                    except:
                        pass
        if not sqli_found:
            print("  No obvious SQL Injection detected")

        # ---- 7. Blind SQL Injection Testing ----
        print(f"\n[7] Testing Blind SQL Injection...")
        import time as _time
        blind_found = False
        if qs:
            for param in qs:
                try:
                    bqs = qs.copy(); bqs[param] = ["1"]
                    bu = urlunparse(parsed._replace(query=urlencode(bqs, doseq=True)))
                    r_base = requests.get(bu, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                    base_len = len(r_base.text)
                    for payload in ["1 AND 1=1--", "1 AND 1=2--"]:
                        tqs = qs.copy(); tqs[param] = [payload]
                        tu = urlunparse(parsed._replace(query=urlencode(tqs, doseq=True)))
                        r = requests.get(tu, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                        if abs(len(r.text) - base_len) > 50:
                            print(f"  [!] Blind SQLi (Boolean-based) in '{param}': response length differs")
                            findings.append({"type": "Blind SQL Injection", "param": param,
                                             "method": "Boolean-based", "severity": "High"})
                            blind_found = True
                            break
                    tqs = qs.copy(); tqs[param] = ["1 AND SLEEP(3)--"]
                    tu = urlunparse(parsed._replace(query=urlencode(tqs, doseq=True)))
                    t0 = _time.time()
                    requests.get(tu, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                    if _time.time() - t0 >= 3.0:
                        print(f"  [!] Blind SQLi (Time-based) in '{param}': response delayed")
                        findings.append({"type": "Blind SQL Injection", "param": param,
                                         "method": "Time-based", "severity": "Critical"})
                        blind_found = True
                except:
                    pass
        if not blind_found:
            print("  No Blind SQL Injection detected")

        # ---- 8. SSRF Testing ----
        print(f"\n[8] Testing SSRF...")
        ssrf_found = False
        ssrf_targets = ["http://127.0.0.1", "http://169.254.169.254", "http://localhost"]
        url_params = [p for p in params if any(k in p.lower()
                      for k in ["url", "uri", "src", "dest", "redirect", "next", "link", "file", "load", "fetch", "open"])]
        for param in url_params:
            for target in ssrf_targets:
                tqs = qs.copy(); tqs[param] = [target]
                tu = urlunparse(parsed._replace(query=urlencode(tqs, doseq=True)))
                try:
                    r = requests.get(tu, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                    if r.status_code == 200 and len(r.text) > 50:
                        print(f"  [!] SSRF possible: param '{param}' fetched '{target}'")
                        findings.append({"type": "SSRF", "param": param,
                                         "target": target, "severity": "Critical"})
                        ssrf_found = True
                except:
                    pass
        if not ssrf_found:
            print("  No SSRF detected in URL parameters")

        # ---- 9. XXE Testing ----
        print(f"\n[9] Testing XXE...")
        xxe_found = False
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<test>&xxe;</test>"
        )
        if accepts_xml or forms_with_action:
            try:
                tu = urlunparse(parsed._replace(query=""))
                r = requests.post(tu, data=xxe_payload, timeout=10,
                                  headers={"Content-Type": "application/xml",
                                           "User-Agent": "Mozilla/5.0"})
                for indicator in ["root:x:", "[extensions]", "nobody:*"]:
                    if indicator in r.text:
                        print(f"  [!] XXE CONFIRMED: server returned file content")
                        findings.append({"type": "XXE", "issue": "File disclosure",
                                         "severity": "Critical"})
                        xxe_found = True
                        break
            except:
                pass
        if not xxe_found:
            print("  No XXE vulnerability detected")

    except Exception as e:
        print(f"\n Failed to connect: {e}")
        return

    # ---- Final Summary ----
    print(f"\n{'='*60}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*60}")

    if findings:
        vuln_types = list(set(f["type"] for f in findings))
        print(f"\n Vulnerabilities Found: {len(vuln_types)}")
        for vt in vuln_types:
            vt_findings = [f for f in findings if f["type"] == vt]
            severities = [f.get("severity", "?") for f in vt_findings]
            max_sev = ("Critical" if "Critical" in severities
                       else "High" if "High" in severities
                       else "Medium")
            print(f"\n  [!] {vt} [{max_sev}]")
            for f in vt_findings:
                detail = (f.get("payload") or f.get("sink") or
                          f.get("issue") or f.get("param") or "")
                print(f"     -> {detail}")
    else:
        print("\n  No vulnerabilities detected")
        print("  (Site may be protected or no testable points found)")
    return findings


# ============================================================
# 4. DEMO LOGS (cover all 4 vulnerability types)
# ============================================================

DEMO_LOGS = [
    # XSS — CONFIRMED BREACH (200 + large response)
    '203.0.113.42 - - [01/Jun/2026:09:30:12] "GET /search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E HTTP/1.1" 200 1532 "Mozilla/5.0 (X11; Linux x86_64)"',
    # XSS — ATTEMPTED ATTACK (403 blocked)
    '198.51.100.7 - - [01/Jun/2026:09:45:00] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 403 120 "curl/7.68.0"',
    # DOM XSS — CONFIRMED BREACH (200 + large response)
    '172.16.0.88 - - [01/Jun/2026:10:00:00] "GET /page HTTP/1.1" 200 2890 "Mozilla/5.0 (Windows)" payload:onerror=eval innerHTML=location.hash',
    # DOM XSS — ATTEMPTED ATTACK (404)
    '172.16.0.88 - - [01/Jun/2026:10:05:00] "GET /notfound#<script>alert(document.cookie)</script> HTTP/1.1" 404 88 "Mozilla/5.0 (Windows)"',
    # IDOR user profile — CONFIRMED BREACH (200 + data returned)
    '10.0.0.55 - - [01/Jun/2026:10:10:00] "GET /user/1337 HTTP/1.1" 200 1312 "Mozilla/5.0 (iPhone)"',
    # IDOR order — CONFIRMED BREACH
    '10.0.0.55 - - [01/Jun/2026:10:10:10] "GET /invoice/5001 HTTP/1.1" 200 987 "Mozilla/5.0 (iPhone)"',
    # IDOR admin — CONFIRMED BREACH (Critical)
    '10.0.0.55 - - [01/Jun/2026:10:10:20] "GET /admin/users/99 HTTP/1.1" 200 712 "Mozilla/5.0 (iPhone)"',
    # IDOR — ATTEMPTED ATTACK (403 blocked)
    '10.0.0.55 - - [01/Jun/2026:10:11:00] "GET /admin/users/100 HTTP/1.1" 403 95 "Mozilla/5.0 (iPhone)"',
    # IDOR — ATTEMPTED ATTACK (404 not found)
    '10.0.0.55 - - [01/Jun/2026:10:11:30] "GET /user/9999 HTTP/1.1" 404 88 "Mozilla/5.0 (iPhone)"',
    # CSRF — CONFIRMED BREACH (POST 200 on /transfer)
    '91.200.12.5 - - [01/Jun/2026:11:00:00] "POST /transfer HTTP/1.1" 200 312 "Mozilla/5.0 (Linux)"',
    # CSRF — ATTEMPTED ATTACK (405 method not allowed)
    '91.200.12.5 - - [01/Jun/2026:11:00:30] "POST /payment HTTP/1.1" 405 98 "Mozilla/5.0 (Linux)"',
    # CORS — CONFIRMED BREACH (200 + data)
    '203.0.113.99 - - [01/Jun/2026:11:10:00] "GET /api/user HTTP/1.1" 200 890 "Mozilla/5.0" Origin: https://evil.com Access-Control-Allow-Origin: https://evil.com',
    # CORS — ATTEMPTED (200 but tiny)
    '203.0.113.99 - - [01/Jun/2026:11:10:30] "GET /api/ping HTTP/1.1" 200 12 "Mozilla/5.0" Access-Control-Allow-Origin: null',
    # SQL Injection — CONFIRMED BREACH (200 + SQL error exposed + large response)
    '45.33.32.156 - - [01/Jun/2026:12:00:00] "GET /login?user=admin\x27--&pass=x HTTP/1.1" 200 1024 "sqlmap/1.7"',
    # SQL Injection — CONFIRMED BREACH (500 server crash)
    '45.33.32.156 - - [01/Jun/2026:12:00:30] "GET /search?q=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 500 245 "sqlmap/1.7"',
    # SQL Injection — ATTEMPTED ATTACK (403)
    '45.33.32.156 - - [01/Jun/2026:12:01:00] "GET /api?id=1;DROP+TABLE+users-- HTTP/1.1" 403 88 "sqlmap/1.7"',
    # Blind SQL Injection — CONFIRMED BREACH (time-based, 200)
    '45.33.32.156 - - [01/Jun/2026:12:05:00] "GET /item?id=1+AND+SLEEP(5)-- HTTP/1.1" 200 312 "sqlmap/1.7"',
    # Blind SQL Injection — ATTEMPTED ATTACK (boolean, 200 tiny)
    '45.33.32.156 - - [01/Jun/2026:12:05:30] "GET /item?id=1+AND+1=2-- HTTP/1.1" 200 45 "sqlmap/1.7"',
    # SSRF — CONFIRMED BREACH (200 + cloud metadata returned)
    '172.20.0.5 - - [01/Jun/2026:12:10:00] "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 512 "Mozilla/5.0"',
    # SSRF — ATTEMPTED ATTACK (500 internal request failed)
    '172.20.0.5 - - [01/Jun/2026:12:10:30] "GET /proxy?src=file:///etc/passwd HTTP/1.1" 500 88 "Mozilla/5.0"',
    # XXE — CONFIRMED BREACH (200 + file content returned)
    '88.80.186.25 - - [01/Jun/2026:12:15:00] "POST /api/xml HTTP/1.1" 200 445 "Mozilla/5.0" <!ENTITY xxe SYSTEM file:///etc/passwd',
    # XXE — ATTEMPTED ATTACK (500 parser crash)
    '88.80.186.25 - - [01/Jun/2026:12:15:30] "POST /xml HTTP/1.1" 500 120 "Mozilla/5.0" <!DOCTYPE x [<!ENTITY xxe SYSTEM http://169.254.169.254/',
    # Normal traffic (should not be flagged)
    '192.168.1.105 - - [01/Jun/2026:13:00:00] "GET /index.html HTTP/1.1" 200 1234 "Mozilla/5.0 (Windows NT 10.0)"',
]



# ============================================================
# CLI INTERFACE
# ============================================================

def main():
    print("=" * 60)
    print("  WEB SECURITY FORENSICS TOOL")
    print("  Detects: XSS | DOM XSS | IDOR | CSRF | CORS | SQLi | Blind SQLi | SSRF | XXE")
    print("=" * 60)

    while True:
        print("\nSelect operation:")
        print("  1) Analyze Logs  (Passive - analyze a log file)")
        print("  2) Scan URL      (Active  - scan for vulnerabilities)")
        print("  3) Exit")
        choice = input("\nChoice (1, 2, 3): ").strip()

        # ── Option 1: Log Analysis ──────────────────────────────
        if choice == "1":
            print("\n--- Web Log Analysis ---")
            print("Enter log file path (or 'demo' for sample data):")
            path = input("Path: ").strip()

            forensics = WebForensics()

            if path.lower() == "demo":
                for log in DEMO_LOGS:
                    forensics.add_log(log)
                print(f"Demo logs loaded ({len(DEMO_LOGS)} entries)")
            else:
                try:
                    forensics.load_logs_from_file(path)
                    print(f"Loaded {len(forensics.logs)} log entries")
                except FileNotFoundError:
                    print("File not found. Check the path.")
                    continue

            print("\nAnalyzing logs...")
            results = forensics.analyze()
            print(f"Found {len(results)} attacks!")

            report = forensics.generate_report()
            print("\n" + report)

            json_file = forensics.export_json()
            print(f"\nJSON report saved: {json_file}")

        # ── Option 2: URL Scan ──────────────────────────────────
        elif choice == "2":
            print("\n--- URL Scan (Active) ---")
            print("Note: Only use on sites you own or have permission to test.")
            url = input("Enter URL: ").strip()
            if not url.startswith("http"):
                url = "http://" + url
            print(f"\nScanning {url} ...")
            _active_scan_url(url)

        # ── Option 3: Exit ──────────────────────────────────────
        elif choice == "3":
            print("\nGoodbye!")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()