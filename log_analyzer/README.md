# LogSentinel — Log Parser & Threat Analyzer

A cybersecurity portfolio project. Parses Apache, Linux auth, and Windows Event
logs and detects threats like brute-force attacks, directory scanning, SQL injection,
XSS, and more — all displayed in a dark-themed web dashboard.

---

## Project Structure

```
log_analyzer/
├── app.py               ← Flask application (run this)
├── log_parser.py        ← Parses Apache / auth.log / Windows Event logs
├── threat_detector.py   ← Detects 8 threat categories
├── requirements.txt     ← Python dependencies
├── templates/
│   └── index.html       ← Dashboard UI
├── static/
│   ├── css/style.css    ← Styling
│   └── js/dashboard.js  ← Frontend logic
└── sample_logs/
    ├── apache_sample.log
    ├── auth_sample.log
    └── windows_sample.log
```

---

## Setup in PyCharm

1. **Open the project**
   - File → Open → select the `log_analyzer` folder

2. **Create a virtual environment**
   - PyCharm will usually prompt you. If not:
     Settings → Project → Python Interpreter → Add Interpreter → Virtualenv

3. **Install dependencies**
   - Open the built-in terminal (bottom of PyCharm)
   - Run: `pip install -r requirements.txt`

4. **Run the app**
   - Open `app.py` and click the green ▶ Run button
   - Or in terminal: `python app.py`

5. **Open in browser**
   - Go to: http://127.0.0.1:5000

---

## Features

- Upload `.log`, `.txt`, or `.csv` log files
- Auto-detects Apache, auth.log, and Windows Event log formats
- Built-in sample logs to demo without uploading anything
- Detects 8 threat types:
  - Brute Force Attacks
  - Directory / Port Scanning
  - SQL Injection Attempts
  - XSS Attempts
  - Known Attack Tools (Nikto, sqlmap, Nmap, etc.)
  - Privilege Escalation (sudo)
  - High Request Rate / DDoS indicators
  - Multi-Account Access from Single IP
- Severity levels: Critical / High / Medium / Low
- Top source IPs with visual bar chart
- HTTP status code breakdown
- Filterable raw log entry table

---

## Extending This Project

Ideas to make it more impressive on your portfolio:
- Add GeoIP lookup (ip2location or MaxMind free DB) to show attacker countries
- Export results to PDF report
- Add email alerts when critical threats are found
- Store results in SQLite for historical comparisons
- Add support for more log formats (nginx, Cisco, Palo Alto)
- Add MITRE ATT&CK framework mapping to each threat type
