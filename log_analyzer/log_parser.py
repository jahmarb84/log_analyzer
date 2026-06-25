"""
log_parser.py - Parses Apache, auth.log, and Windows Event log formats.
"""

import re
from datetime import datetime


class LogParser:
    """Detects log format and parses each line into structured entries."""

    # ── Regex patterns ──────────────────────────────────────────────────────
    APACHE_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)?\s*(?P<path>\S+)?\s*(?P<protocol>[^"]+)?"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    AUTH_PATTERN = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+(?P<service>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.+)'
    )

    WINDOWS_PATTERN = re.compile(
        r'(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>\w+)\s+(?P<source>[^\s]+)\s+(?P<event_id>\d+)\s+'
        r'(?P<message>.+)'
    )

    # ── Public API ───────────────────────────────────────────────────────────
    def detect_log_type(self, content: str) -> str:
        """Guess log type from the first non-empty line."""
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if self.APACHE_PATTERN.match(line):
                return 'apache'
            if self.AUTH_PATTERN.match(line):
                return 'auth'
            if self.WINDOWS_PATTERN.match(line):
                return 'windows'
        return 'unknown'

    def parse(self, lines: list, log_type: str) -> list:
        parsers = {
            'apache':  self._parse_apache,
            'auth':    self._parse_auth,
            'windows': self._parse_windows,
        }
        fn = parsers.get(log_type, self._parse_generic)
        entries = []
        for line in lines:
            line = line.strip()
            if line:
                entry = fn(line)
                if entry:
                    entries.append(entry)
        return entries

    # ── Per-format parsers ───────────────────────────────────────────────────
    def _parse_apache(self, line: str) -> dict | None:
        m = self.APACHE_PATTERN.match(line)
        if not m:
            return self._parse_generic(line)
        d = m.groupdict()
        return {
            'type':       'apache',
            'ip':         d.get('ip', ''),
            'timestamp':  d.get('time', ''),
            'method':     d.get('method', ''),
            'path':       d.get('path', ''),
            'status':     int(d.get('status', 0)),
            'size':       d.get('size', '0'),
            'user_agent': d.get('user_agent', ''),
            'raw':        line,
        }

    def _parse_auth(self, line: str) -> dict | None:
        m = self.AUTH_PATTERN.match(line)
        if not m:
            return self._parse_generic(line)
        d = m.groupdict()
        msg = d.get('message', '')
        ip  = self._extract_ip(msg)
        user = self._extract_user(msg)
        return {
            'type':      'auth',
            'timestamp': f"{d.get('month','')} {d.get('day','')} {d.get('time','')}",
            'host':      d.get('host', ''),
            'service':   d.get('service', ''),
            'message':   msg,
            'ip':        ip,
            'user':      user,
            'raw':       line,
        }

    def _parse_windows(self, line: str) -> dict | None:
        m = self.WINDOWS_PATTERN.match(line)
        if not m:
            return self._parse_generic(line)
        d = m.groupdict()
        return {
            'type':      'windows',
            'timestamp': f"{d.get('date','')} {d.get('time','')}",
            'level':     d.get('level', ''),
            'source':    d.get('source', ''),
            'event_id':  d.get('event_id', ''),
            'message':   d.get('message', ''),
            'ip':        self._extract_ip(d.get('message', '')),
            'raw':       line,
        }

    def _parse_generic(self, line: str) -> dict:
        return {
            'type':      'generic',
            'timestamp': '',
            'message':   line,
            'ip':        self._extract_ip(line),
            'raw':       line,
        }

    # ── Helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _extract_ip(text: str) -> str:
        m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        return m.group(0) if m else ''

    @staticmethod
    def _extract_user(text: str) -> str:
        for pattern in [
            r'for (?:invalid user )?(\S+)',
            r'user=(\S+)',
            r'Accepted \w+ for (\S+)',
        ]:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return ''
