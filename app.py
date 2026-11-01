
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from pathlib import Path
from detector import load_events, detect_threats
import json
import os

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

LOG_FILE = BASE_DIR / "logs" / "security_events.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Local demonstration account only
USERS = {
    "student": generate_password_hash("PilatesDemo2026!")
}

CLASSES = [
    {"name": "Reformer Pilates", "time": "Monday 9:00 AM"},
    {"name": "Mat Pilates", "time": "Tuesday 11:00 AM"},
    {"name": "Strength & Core", "time": "Friday 4:00 PM"}
]


def log_event(username, status):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "source_ip": request.remote_addr,
        "event_type": "login",
        "status": status
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        stored_hash = USERS.get(username)

        if stored_hash and check_password_hash(stored_hash, password):
            session.clear()
            session["username"] = username
            log_event(username, "success")
            return redirect(url_for("dashboard"))

        log_event(username, "failed")
        return render_template(
            "login.html", error="Invalid credentials"
        ), 401

    if "username" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"],
        classes=CLASSES
    )


@app.route("/security")
def security_dashboard():
    if session.get("username") != "student":
        return redirect(url_for("login"))

    events = load_events()
    alerts = detect_threats(events)

    total_logins = sum(
        e.get("event_type") == "login" for e in events
    )
    successful_logins = sum(
        e.get("event_type") == "login"
        and e.get("status") == "success"
        for e in events
    )
    failed_logins = sum(
        e.get("event_type") == "login"
        and e.get("status") == "failed"
        for e in events
    )
    high_alerts = sum(
        a["severity"] == "High" for a in alerts
    )

    return render_template(
        "security.html",
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        high_alerts=high_alerts,
        alerts=alerts
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
