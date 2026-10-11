
import re
from collections import Counter


def analyze_logs(file_path):
    total_logs = 0
    failed_logins = 0

    failed_ip_counts = {}
    login_activity = []

    # Date / Time Analysis
    failed_by_hour = Counter()
    failed_by_date = Counter()
    successful_by_hour = Counter()
    successful_by_date = Counter()

    # Read Log File
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            total_logs += 1

            # Extract Timestamp
            timestamp_match = re.search(
                r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
                line
            )

            # Extract IP Address
            ip_match = re.search(
                r"\bIP:\s*(\d{1,3}(?:\.\d{1,3}){3})\b",
                line
            )

            timestamp = (
                timestamp_match.group(1)
                if timestamp_match
                else "Unknown"
            )

            ip = ip_match.group(1) if ip_match else "Unknown"

            # Extract Date and Hour
            date = "Unknown"
            hour = "Unknown"

            if timestamp != "Unknown":
                date, time_part = timestamp.split()
                hour = time_part.split(":")[0]

            # Detect Login Status
            if "FAILED" in line.upper():
                status = "FAILED"
                failed_logins += 1

                failed_ip_counts[ip] = (
                    failed_ip_counts.get(ip, 0) + 1
                )

                failed_by_hour[hour] += 1
                failed_by_date[date] += 1

            elif "login successful" in line.lower():
                status = "SUCCESS"

                successful_by_hour[hour] += 1
                successful_by_date[date] += 1

            else:
                status = "UNKNOWN"

            # Store Login Activity
            login_activity.append({
                "timestamp": timestamp,
                "status": status,
                "ip": ip
            })

    # Detect Suspicious IPs
    suspicious_ips = [
        ip
        for ip, count in failed_ip_counts.items()
        if ip != "Unknown" and count >= 3
    ]

    # Detect Threat Types
    threat_types = {}

    for ip, count in failed_ip_counts.items():
        if count >= 10:
            threat_types[ip] = "Brute Force Attack"
        elif count >= 5:
            threat_types[ip] = "High Login Failure"
        elif count >= 3:
            threat_types[ip] = "Suspicious Login Activity"
        else:
            threat_types[ip] = "Normal"

    # Threat Count
    threats_detected = len(suspicious_ips)

    # Top Attacking IPs
    top_attacking_ips = sorted(
        [
            (ip, count)
            for ip, count in failed_ip_counts.items()
            if ip != "Unknown"
        ],
        key=lambda item: item[1],
        reverse=True
    )

    # Find Peak Failed Login Hour
    if failed_by_hour:
        peak_failed_hour = max(
            failed_by_hour,
            key=failed_by_hour.get
        )
        peak_failed_attempts = failed_by_hour[peak_failed_hour]
    else:
        peak_failed_hour = "N/A"
        peak_failed_attempts = 0

    # Find Peak Failed Login Date
    if failed_by_date:
        peak_failed_date = max(
            failed_by_date,
            key=failed_by_date.get
        )
        peak_failed_date_attempts = failed_by_date[peak_failed_date]
    else:
        peak_failed_date = "N/A"
        peak_failed_date_attempts = 0

    # Return Analysis Result
    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "suspicious_ips": suspicious_ips,
        "threats_detected": threats_detected,
        "failed_ip_counts": failed_ip_counts,
        "threat_types": threat_types,
        "login_activity": login_activity,
        "top_attacking_ips": top_attacking_ips,

        # Date / Time Analysis Data
        "failed_by_hour": dict(failed_by_hour),
        "failed_by_date": dict(failed_by_date),
        "successful_by_hour": dict(successful_by_hour),
        "successful_by_date": dict(successful_by_date),
        "peak_failed_hour": peak_failed_hour,
        "peak_failed_attempts": peak_failed_attempts,
        "peak_failed_date": peak_failed_date,
        "peak_failed_date_attempts": peak_failed_date_attempts
    }
