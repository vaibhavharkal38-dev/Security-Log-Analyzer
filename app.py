
from flask import Flask, render_template, request, send_file, jsonify
from analyzer.log_analyzer import analyze_logs
from werkzeug.utils import secure_filename
import os
import csv
import io
import re
import threading
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "logs")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Live monitoring state
live_offsets = {}
live_events = []
live_event_id = 0
live_lock = threading.Lock()
MAX_LIVE_EVENTS = 200


# -----------------------------------------
# Calculate Threat Severity
# -----------------------------------------

def get_severity(failed_attempts):
    if failed_attempts >= 10:
        return "CRITICAL"
    elif failed_attempts >= 5:
        return "HIGH"
    elif failed_attempts >= 3:
        return "MEDIUM"
    else:
        return "LOW"


# -----------------------------------------
# Calculate Security Risk Score
# -----------------------------------------

def calculate_risk_score(result):
    failed_logins = result["failed_logins"]
    suspicious_ips = len(result["suspicious_ips"])
    threats_detected = result["threats_detected"]

    risk_score = 0

    if failed_logins >= 10:
        risk_score += 40
    elif failed_logins >= 5:
        risk_score += 30
    elif failed_logins >= 3:
        risk_score += 20
    elif failed_logins >= 1:
        risk_score += 10

    risk_score += suspicious_ips * 20
    risk_score += threats_detected * 10

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level


# -----------------------------------------
# Live Event Helpers
# -----------------------------------------

def get_log_path(filename):
    """Return a safe path for a log file inside logs/."""
    safe_name = os.path.basename(filename or "sample.log")

    if not safe_name.lower().endswith(".log"):
        safe_name = "sample.log"

    path = os.path.join(UPLOAD_FOLDER, safe_name)

    if not os.path.isfile(path):
        path = os.path.join(UPLOAD_FOLDER, "sample.log")
        safe_name = "sample.log"

    return safe_name, path


def parse_live_event(line):
    """Convert a new log line into a dashboard event."""
    line = line.strip()

    if not line:
        return None

    timestamp_match = re.search(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
        line
    )

    ip_match = re.search(
        r"\bIP:\s*(\d{1,3}(?:\.\d{1,3}){3})\b",
        line
    )

    timestamp = (
        timestamp_match.group(1)
        if timestamp_match
        else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    ip = ip_match.group(1) if ip_match else "Unknown"

    if "FAILED" in line.upper():
        status = "FAILED"
        severity = "HIGH"
    elif "login successful" in line.lower():
        status = "SUCCESS"
        severity = "LOW"
    else:
        status = "UNKNOWN"
        severity = "LOW"

    return {
        "timestamp": timestamp,
        "status": status,
        "ip": ip,
        "severity": severity,
        "message": line
    }


# -----------------------------------------
# Home / Dashboard
# -----------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    filename = request.args.get("file", "sample.log")

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        if uploaded_file and uploaded_file.filename:
            safe_filename = secure_filename(uploaded_file.filename)

            if safe_filename.lower().endswith(".log"):
                filename = safe_filename
                file_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    filename
                )

                uploaded_file.save(file_path)

                # Start monitoring this file from its current end.
                with live_lock:
                    live_offsets[filename] = os.path.getsize(file_path)

    filename, file_path = get_log_path(filename)

    result = analyze_logs(file_path)
    risk_score, risk_level = calculate_risk_score(result)

    top_attacking_ips = sorted(
        [
            (ip, count)
            for ip, count in result["failed_ip_counts"].items()
            if ip != "Unknown"
        ],
        key=lambda item: item[1],
        reverse=True
    )

    return render_template(
        "index.html",

        total_logs=result["total_logs"],
        failed_logins=result["failed_logins"],
        suspicious_ips=len(result["suspicious_ips"]),
        threats_detected=result["threats_detected"],

        suspicious_ip_list=result["suspicious_ips"],
        threat_types=result["threat_types"],
        failed_ip_counts=result["failed_ip_counts"],
        top_attacking_ips=top_attacking_ips,
        login_activity=result["login_activity"],

        risk_score=risk_score,
        risk_level=risk_level,

        failed_by_hour=result["failed_by_hour"],
        failed_by_date=result["failed_by_date"],
        successful_by_hour=result["successful_by_hour"],
        successful_by_date=result["successful_by_date"],

        peak_failed_hour=result["peak_failed_hour"],
        peak_failed_attempts=result["peak_failed_attempts"],
        peak_failed_date=result["peak_failed_date"],
        peak_failed_date_attempts=result["peak_failed_date_attempts"],

        filename=filename
    )


# -----------------------------------------
# Live Monitoring API
# Browser polls this endpoint for new entries.
# -----------------------------------------

@app.route("/api/live-events")
def api_live_events():
    global live_event_id

    filename, file_path = get_log_path(
        request.args.get("file", "sample.log")
    )

    if not os.path.isfile(file_path):
        return jsonify({
            "status": "error",
            "message": "Log file not found.",
            "events": []
        }), 404

    new_events = []

    with live_lock:
        current_size = os.path.getsize(file_path)

        if filename not in live_offsets:
            # Begin at the current end so old entries are not replayed.
            live_offsets[filename] = current_size

        offset = live_offsets[filename]

        # Handle a truncated or replaced log file.
        if current_size < offset:
            offset = 0

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as log_file:
            log_file.seek(offset)

            for line in log_file:
                event = parse_live_event(line)

                if event is None:
                    continue

                live_event_id += 1
                event["id"] = live_event_id

                live_events.append(event)
                new_events.append(event)

            live_offsets[filename] = log_file.tell()

        # Keep memory use bounded.
        if len(live_events) > MAX_LIVE_EVENTS:
            del live_events[:-MAX_LIVE_EVENTS]

    return jsonify({
        "status": "ok",
        "monitoring": True,
        "file": filename,
        "events": new_events
    })


# -----------------------------------------
# Export Security Report
# -----------------------------------------

@app.route("/export")
def export_report():
    filename, file_path = get_log_path(
        request.args.get("file", "sample.log")
    )

    result = analyze_logs(file_path)
    risk_score, risk_level = calculate_risk_score(result)
    suspicious_ips = set(result["suspicious_ips"])

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["SECURITY LOG ANALYZER REPORT"])
    writer.writerow([])
    writer.writerow(["Analyzed File", filename])
    writer.writerow([])

    writer.writerow(["SECURITY SUMMARY"])
    writer.writerow(["Total Logs", result["total_logs"]])
    writer.writerow(["Failed Logins", result["failed_logins"]])
    writer.writerow(["Suspicious IPs", len(result["suspicious_ips"])])
    writer.writerow(["Threats Detected", result["threats_detected"]])
    writer.writerow(["Risk Score", f"{risk_score}/100"])
    writer.writerow(["Risk Level", risk_level])
    writer.writerow([])

    writer.writerow([
        "TIMESTAMP",
        "STATUS",
        "IP ADDRESS",
        "SUSPICIOUS IP",
        "FAILED ATTEMPTS",
        "THREAT TYPE",
        "SEVERITY"
    ])

    for activity in result["login_activity"]:
        ip = activity["ip"]
        failed_attempts = result["failed_ip_counts"].get(ip, 0)
        threat_type = result["threat_types"].get(ip, "Normal")
        suspicious = "YES" if ip in suspicious_ips else "NO"
        severity = get_severity(failed_attempts)

        writer.writerow([
            activity["timestamp"],
            activity["status"],
            ip,
            suspicious,
            failed_attempts,
            threat_type,
            severity
        ])

    writer.writerow([])
    writer.writerow(["TOP ATTACKING IPS"])
    writer.writerow(["IP ADDRESS", "FAILED ATTEMPTS"])

    top_attacking_ips = sorted(
        [
            (ip, count)
            for ip, count in result["failed_ip_counts"].items()
            if ip != "Unknown"
        ],
        key=lambda item: item[1],
        reverse=True
    )

    for ip, count in top_attacking_ips:
        writer.writerow([ip, count])

    writer.writerow([])
    writer.writerow(["DATE / TIME ANALYSIS"])
    writer.writerow([
        "Peak Failed Login Hour",
        result["peak_failed_hour"]
    ])
    writer.writerow([
        "Peak Failed Attempts in Hour",
        result["peak_failed_attempts"]
    ])
    writer.writerow([
        "Peak Failed Login Date",
        result["peak_failed_date"]
    ])
    writer.writerow([
        "Peak Failed Attempts on Date",
        result["peak_failed_date_attempts"]
    ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="security_report.csv"
    )


# -----------------------------------------
# Run Flask Application
# -----------------------------------------

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
