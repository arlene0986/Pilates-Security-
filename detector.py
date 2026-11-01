
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "security_events.jsonl"
REPORT_FILE = BASE_DIR / "reports" / "security_alerts.json"

THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def load_events():
    events = []

    if not LOG_FILE.exists():
        return events

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                event["timestamp"] = datetime.fromisoformat(
                    event["timestamp"]
                )

                if event["timestamp"].tzinfo is None:
                    raise ValueError("Timestamp must include timezone")

                events.append(event)

            except (ValueError, KeyError, TypeError) as error:
                print(f"Skipping line {line_number}: {error}")

    return sorted(events, key=lambda e: e["timestamp"])


def detect_threats(events):
    alerts = []
    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") == "login":
            key = (
                event.get("username"),
                event.get("source_ip")
            )
            grouped[key].append(event)

    for (username, source_ip), user_events in grouped.items():
        failures = []
        threshold_alerted = False

        for event in sorted(
            user_events, key=lambda e: e["timestamp"]
        ):
            timestamp = event["timestamp"]

            failures = [
                t for t in failures
                if timedelta(0) <= timestamp - t <= WINDOW
            ]

            if len(failures) < THRESHOLD:
                threshold_alerted = False

            if event.get("status") == "failed":
                failures.append(timestamp)

                if (
                    len(failures) >= THRESHOLD
                    and not threshold_alerted
                ):
                    alerts.append({
                        "alert_type": "Repeated Failed Logins",
                        "severity": "Medium",
                        "username": username,
                        "source_ip": source_ip,
                        "timestamp": timestamp.isoformat(),
                        "failed_attempts": len(failures),
                        "recommendation": (
                            "Review authentication activity and "
                            "verify whether attempts are legitimate."
                        )
                    })
                    threshold_alerted = True

            elif event.get("status") == "success":
                if len(failures) >= THRESHOLD:
                    alerts.append({
                        "alert_type": (
                            "Successful Login After Repeated Failures"
                        ),
                        "severity": "High",
                        "username": username,
                        "source_ip": source_ip,
                        "timestamp": timestamp.isoformat(),
                        "failed_attempts": len(failures),
                        "recommendation": (
                            "Investigate the session and confirm "
                            "the login with the account owner. "
                            "Consider session revocation or a "
                            "credential reset if compromise "
                            "is suspected."
                        )
                    })

                failures.clear()
                threshold_alerted = False

    return sorted(alerts, key=lambda a: a["timestamp"], reverse=True)


def save_alerts(alerts):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"Detected {len(alerts)} security alerts.")
    print(f"Saved report to: {REPORT_FILE}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['alert_type']} | "
            f"{alert['username']} | "
            f"{alert['source_ip']}"
        )


if __name__ == "__main__":
    events = load_events()
    alerts = detect_threats(events)
    save_alerts(alerts)
