
from datetime import datetime, timezone, timedelta
from pathlib import Path
from detector import load_events, detect_threats

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_report():
    events = load_events()
    alerts = detect_threats(events)

    generated_at = datetime.now(timezone.utc)

    lines = [
        "# Security Incident Investigation Report",
        "",
        f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        "**Application:** Pilates Studio Security Monitoring Lab",
        "**Environment:** Local demonstration",
        "**Status:** Requires analyst review",
        "",
        "## 1. Executive Summary",
        "",
        f"The monitoring system analysed {len(events)} security events "
        f"and generated {len(alerts)} security alerts.",
        "",
        "The detection rules identify repeated authentication failures "
        "and successful logins following repeated failures. "
        "The patterns can indicate a password guessing attemppt, but does not "
        "independently establish that an account was compromised.",
        "",
        "## 2. Detection Methodology",
        "",
        "- Source: Application authentication logs (JSONL)",
        "- Detection threshold: 5 failed attempts within 5 minutes",
        "- Correlation: Username and source IP address",
        "- Severity: Medium for repeated failures; High for a "
        "successful login following repeated failures",
        "",
        "## 3. Detected Alerts",
        ""
    ]

    if not alerts:
        lines.extend([
            "No alerts matched the configured detection rules.",
            ""
        ])

    for index, alert in enumerate(alerts, start=1):
        alert_time = datetime.fromisoformat(alert["timestamp"])

        lines.extend([
            f"### Alert {index}: {alert['alert_type']}",
            "",
            f"- **Severity:** {alert['severity']}",
            f"- **Time:** {alert['timestamp']}",
            f"- **Account:** `{alert['username']}`",
            f"- **Source IP:** `{alert['source_ip']}`",
            f"- **Failed attempts:** {alert['failed_attempts']}",
            "",
            "**Supporting evidence:**",
            "",
            "| Timestamp (UTC) | Event | Status |",
            "|---|---|---|"
        ])

        related = [
            event for event in events
            if event.get("username") == alert["username"]
            and event.get("source_ip") == alert["source_ip"]
            and event.get("event_type") == "login"
            and alert_time - timedelta(minutes=5)
            <= event["timestamp"] <= alert_time
        ]

        for event in related:
            lines.append(
                f"| {event['timestamp'].isoformat()} "
                f"| {event['event_type']} "
                f"| {event['status']} |"
            )

        lines.extend([
            "",
            "**Recommended response:**",
            "",
            alert["recommendation"],
            "",
            "**Analyst assessment:**",
            "",
            "REQUIRES FURTHER INVESTIGATION"
            "Repeated failures could reflect password guessing, "
            "a forgotten password, or an automated client. "
            "Review additional session and account activity"
             "before confirming malicious activity.",
            ""
        ])

    lines.extend([
        "## 4. Limitations",
        "",
        "- The application uses a local demonstration account.",
        "- The detector relies on predefined thresholds.",
        "- Source IP addresses alone do not identify individuals.",
        "- The monitoring system does not confirm account compromise.",
        "- Alerts are recalculated from the log history.",
        "",
        "## 5. Recommended Improvements",
        "",
        "1. Introduce persistent user accounts and role-based access.",
        "2. Implement authentication rate limiting.",
        "3. Add alert deduplication and investigation status tracking.",
        "4. Monitor additional events such as password changes.",
        "5. Integrate a SIEM for centralised event analysis.",
        "",
        "## 6. Conclusion",
        "",
        "This prototype demonstrates authentication event collection, "
        "rule-based threat detection, event correlation, "
        "incident triage and automated security reporting.",
        ""
    ])

    report_path = REPORT_DIR / "incident_investigation.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Report generated: {report_path}")
    print(f"Events analysed: {len(events)}")
    print(f"Alerts detected: {len(alerts)}")


if __name__ == "__main__":
    generate_report()
