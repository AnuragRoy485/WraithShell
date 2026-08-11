from flask import Flask, render_template, jsonify
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import threading
import time
import requests
from pathlib import Path

app = Flask(__name__)

LOG_PATH = Path("/logs/cowrie.json")
CACHE = {
    "events": [],
    "last_size": 0,
    "stats": {},
    "last_update": None
}

# Simple in-memory GeoIP cache
GEO_CACHE = {}

def get_country(ip: str) -> str:
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        # Free & no API key needed for low volume
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=3)
        if r.status_code == 200:
            data = r.json()
            country = data.get("country", "Unknown")
            GEO_CACHE[ip] = country
            return country
    except Exception:
        pass
    GEO_CACHE[ip] = "Unknown"
    return "Unknown"

def parse_logs():
    """Tail and parse cowrie.json"""
    if not LOG_PATH.exists():
        return

    current_size = LOG_PATH.stat().st_size
    if current_size == CACHE["last_size"]:
        return

    events = []
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            # Read only new data if possible, otherwise full file
            if CACHE["last_size"] > 0 and current_size > CACHE["last_size"]:
                f.seek(CACHE["last_size"])
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading log: {e}")
        return

    CACHE["last_size"] = current_size
    CACHE["events"].extend(events)

    # Keep only last 5000 events in memory
    if len(CACHE["events"]) > 5000:
        CACHE["events"] = CACHE["events"][-5000:]

    process_stats()

def process_stats():
    events = CACHE["events"]
    now = datetime.utcnow()

    failed_logins = []
    success_logins = []
    commands = []
    sessions = set()
    ips = set()
    countries = Counter()
    usernames = Counter()
    passwords = Counter()
    timeline = defaultdict(int)

    for e in events:
        eventid = e.get("eventid", "")
        src_ip = e.get("src_ip")
        ts = e.get("timestamp", "")[:19]  # YYYY-MM-DDTHH:MM:SS

        if src_ip:
            ips.add(src_ip)
            country = get_country(src_ip)
            countries[country] += 1

        if eventid == "cowrie.login.failed":
            failed_logins.append(e)
            usernames[e.get("username", "")] += 1
            passwords[e.get("password", "")] += 1
        elif eventid == "cowrie.login.success":
            success_logins.append(e)
            usernames[e.get("username", "")] += 1
            passwords[e.get("password", "")] += 1
        elif eventid == "cowrie.command.input":
            commands.append(e.get("input", ""))
        elif eventid in ("cowrie.session.connect", "cowrie.session.closed"):
            sessions.add(e.get("session"))

        if ts:
            try:
                hour = ts[:13]  # group by hour
                timeline[hour] += 1
            except:
                pass

    # Build recent feed (last 50 interesting events)
    feed = []
    for e in reversed(events[-300:]):
        eid = e.get("eventid")
        if eid in ("cowrie.login.failed", "cowrie.login.success", "cowrie.command.input", "cowrie.session.connect"):
            feed.append({
                "time": e.get("timestamp", "")[:19].replace("T", " "),
                "event": eid.replace("cowrie.", ""),
                "ip": e.get("src_ip", "-"),
                "country": get_country(e.get("src_ip", "")) if e.get("src_ip") else "-",
                "user": e.get("username", "-"),
                "password": e.get("password", "-"),
                "cmd": e.get("input", "-")[:80] if e.get("input") else "-",
                "protocol": e.get("protocol", "ssh")
            })
            if len(feed) >= 40:
                break

    CACHE["stats"] = {
        "total_events": len(events),
        "unique_ips": len(ips),
        "failed_logins": len(failed_logins),
        "success_logins": len(success_logins),
        "commands": len(commands),
        "sessions": len(sessions),
        "top_usernames": usernames.most_common(10),
        "top_passwords": passwords.most_common(10),
        "top_commands": Counter(commands).most_common(12),
        "top_countries": countries.most_common(10),
        "timeline": dict(sorted(timeline.items())[-24:]),  # last 24 hours
        "feed": feed,
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def background_parser():
    while True:
        parse_logs()
        time.sleep(4)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    return jsonify(CACHE["stats"])

if __name__ == "__main__":
    # Initial parse
    parse_logs()
    # Start background thread
    t = threading.Thread(target=background_parser, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8080, debug=False)
