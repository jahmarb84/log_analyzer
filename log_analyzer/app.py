"""
Log Parser & Analyzer - Main Flask Application
A cybersecurity portfolio project for analyzing system and web server logs.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
from log_parser import LogParser
from threat_detector import ThreatDetector

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle log file upload and analysis."""
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['logfile']
    log_type = request.form.get('log_type', 'auto')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Use .log, .txt, or .csv'}), 400

    # Read file content
    content = file.read().decode('utf-8', errors='ignore')
    lines = content.splitlines()

    # Parse logs
    parser = LogParser()
    if log_type == 'auto':
        log_type = parser.detect_log_type(content)

    parsed_entries = parser.parse(lines, log_type)

    # Run threat detection
    detector = ThreatDetector()
    threats = detector.analyze(parsed_entries)
    summary = detector.get_summary(parsed_entries, threats)

    return jsonify({
        'log_type': log_type,
        'total_entries': len(parsed_entries),
        'threats': threats,
        'summary': summary,
        'entries': parsed_entries[:500]  # Cap at 500 for display
    })


@app.route('/analyze_sample', methods=['POST'])
def analyze_sample():
    """Analyze one of the built-in sample log files."""
    sample = request.json.get('sample')
    sample_files = {
        'apache': 'sample_logs/apache_sample.log',
        'auth': 'sample_logs/auth_sample.log',
        'windows': 'sample_logs/windows_sample.log',
    }

    if sample not in sample_files:
        return jsonify({'error': 'Unknown sample'}), 400

    path = os.path.join(os.path.dirname(__file__), sample_files[sample])
    with open(path, 'r') as f:
        lines = f.read().splitlines()

    parser = LogParser()
    log_type = sample  # We know the type
    parsed_entries = parser.parse(lines, log_type)

    detector = ThreatDetector()
    threats = detector.analyze(parsed_entries)
    summary = detector.get_summary(parsed_entries, threats)

    return jsonify({
        'log_type': log_type,
        'total_entries': len(parsed_entries),
        'threats': threats,
        'summary': summary,
        'entries': parsed_entries[:500]
    })


@app.route('/analyze_live_windows', methods=['POST'])
def analyze_live_windows():
    """
    Analyze real Windows Security Event Log entries (logon events) directly
    from this machine. Requires running as Administrator to read the log.
    """
    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        return jsonify({'error': 'pywin32 not installed. Run: pip install pywin32'}), 500

    server = 'localhost'
    log_type = 'Security'
    RELEVANT_EVENT_IDS = {4624: 'Successful logon', 4625: 'Failed logon'}

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        return jsonify({'error': f'Could not open Security event log (run as Administrator): {e}'}), 403

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    lines = []
    max_events = 2000
    read_count = 0

    while read_count < max_events:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            event_id = event.EventID & 0xFFFF
            if event_id not in RELEVANT_EVENT_IDS:
                continue
            try:
                msg = win32evtlogutil.SafeFormatMessage(event, log_type)
            except Exception:
                msg = ' '.join(str(s) for s in (event.StringInserts or []))
            ts = event.TimeGenerated
            date_str = ts.strftime('%Y-%m-%d')
            time_str = ts.strftime('%H:%M:%S')
            level = 'ERROR' if event_id == 4625 else 'INFO'
            msg_oneline = ' '.join(msg.split())
            lines.append(f"{date_str} {time_str} {level} Security {event_id} {msg_oneline}")
            read_count += 1
            if read_count >= max_events:
                break

    win32evtlog.CloseEventLog(hand)

    parser = LogParser()
    parsed_entries = parser.parse(lines, 'windows')

    detector = ThreatDetector()
    threats = detector.analyze(parsed_entries)
    summary = detector.get_summary(parsed_entries, threats)

    return jsonify({
        'log_type': 'windows (live Security event log)',
        'total_entries': len(parsed_entries),
        'threats': threats,
        'summary': summary,
        'entries': parsed_entries[-500:]
    })


if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True, port=5000, host='0.0.0.0')


