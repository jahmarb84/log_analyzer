"""
threat_detector.py - Analyzes parsed log entries for suspicious patterns.

Detections:
  - Brute force (many failed logins from same IP)
  - Port / directory scanning (many 404s from same IP)
  - SQL injection attempts in URLs
  - XSS attempts in URLs
  - Suspicious user agents (scanners, exploit kits)
  - Privilege escalation via sudo
  - Multiple accounts from same IP
  - High request rate (DDoS indicator)
"""

import re
from collections import defaultdict, Counter


class ThreatDetector:

    # ── Thresholds ────────────────────────────────────────────────────────
    BRUTE_FORCE_THRESHOLD   = 5   # failed logins from same IP
    SCAN_THRESHOLD          = 10  # 404s from same IP
    RATE_THRESHOLD          = 100 # total requests from same IP

    # ── Signatures ────────────────────────────────────────────────────────
    SQLI_PATTERNS = [
        r"union.*select", r"select.*from", r"insert.*into",
        r"drop\s+table", r"'--", r"or\s+1=1", r";\s*exec",
        r"xp_cmdshell", r"information_schema",
    ]
    XSS_PATTERNS = [
        r"<script", r"javascript:", r"onerror=", r"onload=",
        r"alert\(", r"document\.cookie",
    ]
    SUSPICIOUS_AGENTS = [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab",
        "gobuster", "dirb", "dirbuster", "hydra", "medusa",
        "burpsuite", "metasploit", "havij", "acunetix", "nessus",
        "openvas", "w3af", "wfuzz", "nuclei",
    ]

    # ── Public API ────────────────────────────────────────────────────────
    def analyze(self, entries: list) -> list:
        threats = []
        threats += self._detect_brute_force(entries)
        threats += self._detect_scanning(entries)
        threats += self._detect_sqli(entries)
        threats += self._detect_xss(entries)
        threats += self._detect_suspicious_agents(entries)
        threats += self._detect_privilege_escalation(entries)
        threats += self._detect_high_rate(entries)
        threats += self._detect_multi_account(entries)
        # Sort: critical first, then high, medium, low
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        threats.sort(key=lambda t: order.get(t.get('severity', 'low'), 3))
        return threats

    def get_summary(self, entries: list, threats: list) -> dict:
        severity_counts = Counter(t['severity'] for t in threats)
        ip_counts = Counter(e.get('ip', '') for e in entries if e.get('ip'))
        status_counts = Counter(
            str(e.get('status', '')) for e in entries if e.get('status')
        )
        top_ips = [
            {'ip': ip, 'count': count}
            for ip, count in ip_counts.most_common(10)
            if ip
        ]
        return {
            'total_entries':   len(entries),
            'total_threats':   len(threats),
            'critical':        severity_counts.get('critical', 0),
            'high':            severity_counts.get('high', 0),
            'medium':          severity_counts.get('medium', 0),
            'low':             severity_counts.get('low', 0),
            'top_ips':         top_ips,
            'status_breakdown': dict(status_counts.most_common(10)),
        }

    # ── Detections ────────────────────────────────────────────────────────
    def _detect_brute_force(self, entries: list) -> list:
        threats = []
        failed_by_ip = defaultdict(list)
        fail_keywords = ['failed', 'failure', 'invalid', 'authentication failure']

        for e in entries:
            msg = (e.get('message', '') + e.get('raw', '')).lower()
            ip  = e.get('ip', '')
            if ip and any(k in msg for k in fail_keywords):
                failed_by_ip[ip].append(e.get('timestamp', ''))

        for ip, timestamps in failed_by_ip.items():
            if len(timestamps) >= self.BRUTE_FORCE_THRESHOLD:
                severity = 'critical' if len(timestamps) >= 20 else 'high'
                threats.append({
                    'type':        'Brute Force Attack',
                    'severity':    severity,
                    'ip':          ip,
                    'count':       len(timestamps),
                    'description': f"IP {ip} made {len(timestamps)} failed login attempts.",
                    'first_seen':  timestamps[0],
                    'last_seen':   timestamps[-1],
                    'recommendation': 'Block IP, enable account lockout policies, consider MFA.',
                })
        return threats

    def _detect_scanning(self, entries: list) -> list:
        threats = []
        notfound_by_ip = defaultdict(int)

        for e in entries:
            if e.get('type') == 'apache' and e.get('status') == 404:
                ip = e.get('ip', '')
                if ip:
                    notfound_by_ip[ip] += 1

        for ip, count in notfound_by_ip.items():
            if count >= self.SCAN_THRESHOLD:
                severity = 'high' if count >= 50 else 'medium'
                threats.append({
                    'type':        'Directory/Port Scanning',
                    'severity':    severity,
                    'ip':          ip,
                    'count':       count,
                    'description': f"IP {ip} triggered {count} HTTP 404 errors — likely scanning for vulnerabilities.",
                    'recommendation': 'Review IP reputation; consider rate limiting or WAF rules.',
                })
        return threats

    def _detect_sqli(self, entries: list) -> list:
        threats = []
        combined = '|'.join(self.SQLI_PATTERNS)
        pattern  = re.compile(combined, re.IGNORECASE)

        for e in entries:
            path = e.get('path', '') or e.get('message', '') or e.get('raw', '')
            if pattern.search(path):
                threats.append({
                    'type':           'SQL Injection Attempt',
                    'severity':       'critical',
                    'ip':             e.get('ip', 'unknown'),
                    'description':    f"SQL injection pattern detected in: {path[:120]}",
                    'timestamp':      e.get('timestamp', ''),
                    'recommendation': 'Ensure parameterized queries; review WAF rules; check DB logs.',
                })
        return threats

    def _detect_xss(self, entries: list) -> list:
        threats = []
        combined = '|'.join(self.XSS_PATTERNS)
        pattern  = re.compile(combined, re.IGNORECASE)

        for e in entries:
            path = e.get('path', '') or e.get('message', '') or e.get('raw', '')
            if pattern.search(path):
                threats.append({
                    'type':           'XSS Attempt',
                    'severity':       'high',
                    'ip':             e.get('ip', 'unknown'),
                    'description':    f"XSS pattern detected in: {path[:120]}",
                    'timestamp':      e.get('timestamp', ''),
                    'recommendation': 'Sanitize all user inputs; implement Content Security Policy headers.',
                })
        return threats

    def _detect_suspicious_agents(self, entries: list) -> list:
        threats = []
        for e in entries:
            agent = e.get('user_agent', '').lower()
            for tool in self.SUSPICIOUS_AGENTS:
                if tool in agent:
                    threats.append({
                        'type':           'Known Attack Tool Detected',
                        'severity':       'high',
                        'ip':             e.get('ip', 'unknown'),
                        'description':    f"User-agent matches known security tool: '{tool}' — {agent[:80]}",
                        'timestamp':      e.get('timestamp', ''),
                        'recommendation': 'Block user-agent string; investigate what was accessed.',
                    })
                    break
        return threats

    def _detect_privilege_escalation(self, entries: list) -> list:
        threats = []
        sudo_fail = re.compile(r'sudo.*NOT in sudoers|incorrect password|sudo.*authentication failure', re.IGNORECASE)
        sudo_ok   = re.compile(r'sudo:.*COMMAND=', re.IGNORECASE)

        for e in entries:
            msg = e.get('message', '') + e.get('raw', '')
            if sudo_fail.search(msg):
                threats.append({
                    'type':           'Failed Privilege Escalation',
                    'severity':       'high',
                    'ip':             e.get('ip', 'local'),
                    'description':    f"Unauthorized sudo attempt: {msg[:100]}",
                    'timestamp':      e.get('timestamp', ''),
                    'recommendation': 'Investigate user account; review sudo configuration.',
                })
            elif sudo_ok.search(msg):
                threats.append({
                    'type':           'Privilege Escalation (sudo)',
                    'severity':       'low',
                    'ip':             e.get('ip', 'local'),
                    'description':    f"Successful sudo command executed: {msg[:100]}",
                    'timestamp':      e.get('timestamp', ''),
                    'recommendation': 'Verify this was an authorized action.',
                })
        return threats

    def _detect_high_rate(self, entries: list) -> list:
        threats = []
        ip_counts = Counter(e.get('ip', '') for e in entries if e.get('ip'))
        for ip, count in ip_counts.items():
            if count >= self.RATE_THRESHOLD:
                threats.append({
                    'type':           'High Request Rate (Possible DDoS)',
                    'severity':       'medium',
                    'ip':             ip,
                    'count':          count,
                    'description':    f"IP {ip} made {count} total requests — possible flood/DDoS.",
                    'recommendation': 'Implement rate limiting; consider IP-based throttling.',
                })
        return threats

    def _detect_multi_account(self, entries: list) -> list:
        threats = []
        accounts_by_ip = defaultdict(set)
        for e in entries:
            ip   = e.get('ip', '')
            user = e.get('user', '')
            if ip and user and user not in ('root', ''):
                accounts_by_ip[ip].add(user)
        for ip, users in accounts_by_ip.items():
            if len(users) >= 3:
                threats.append({
                    'type':           'Multiple Account Access from Single IP',
                    'severity':       'medium',
                    'ip':             ip,
                    'count':          len(users),
                    'description':    f"IP {ip} attempted access with {len(users)} different accounts: {', '.join(list(users)[:5])}",
                    'recommendation': 'Investigate credential stuffing; check for shared NAT or VPN.',
                })
        return threats
