import os
import time


def monitor_log_file(file_path, callback, interval_seconds=2):
    """
    Monitor a log file for newly appended entries.

    Args:
        file_path: Path to the log file.
        callback: Function called for every new non-empty line.
        interval_seconds: Time between file checks.
    """
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    # Start from the current end of the file.
    with open(
        file_path, "r", encoding="utf-8", errors="replace"
    ) as log_file:
        log_file.seek(0, os.SEEK_END)

        print(f"[LIVE MONITOR] Watching: {file_path}")
        print("[LIVE MONITOR] Press Ctrl+C to stop.")

        try:
            while True:
                current_size = os.path.getsize(file_path)

                # Handle truncation or log file reset.
                if current_size < log_file.tell():
                    log_file.seek(0)

                line = log_file.readline()

                if line:
                    line = line.strip()

                    if line:
                        event = {
                            "timestamp": time.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "message": line,
                            "status": (
                                "FAILED"
                                if "FAILED" in line.upper()
                                else (
                                    "SUCCESS"
                                    if "login successful" in line.lower()
                                    else "UNKNOWN"
                                )
                            ),
                        }

                        callback(event)
                else:
                    time.sleep(interval_seconds)

        except KeyboardInterrupt:
            print("\n[LIVE MONITOR] Monitoring stopped.")


def print_event(event):
    """Display a newly detected log entry."""
    print(
        f"[{event['timestamp']}] "
        f"{event['status']}: {event['message']}"
    )


if __name__ == "__main__":
    sample_log = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "logs",
        "sample.log"
    )

    monitor_log_file(sample_log, print_event)