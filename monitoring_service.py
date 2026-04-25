from flask import Flask, request, jsonify
import json
import datetime
import os

app = Flask(__name__)

LOG_FILE = "logs.json"

# -------------------------------
# Required log fields
# -------------------------------
REQUIRED_FIELDS = ["component", "event", "decision"]


# -------------------------------
# Validate log format
# -------------------------------
def validate_log(entry):
    for field in REQUIRED_FIELDS:
        if field not in entry:
            return False
    return True


# -------------------------------
#  Write log safely
# -------------------------------
def write_log(entry):
    # Add timestamp automatically
    entry["timestamp"] = datetime.datetime.utcnow().isoformat()

    # Create file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

    # Read existing logs safely
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    # Append new log
    logs.append(entry)

    # Save logs
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


# -------------------------------
# Receive log
# -------------------------------
@app.route("/log", methods=["POST"])
def log_event():
    data = request.get_json()

    if not data or not validate_log(data):
        return jsonify({"error": "Invalid log format"}), 400

    write_log(data)

    return jsonify({"status": "logged"}), 200


# -------------------------------
# Get all logs
# -------------------------------
@app.route("/logs", methods=["GET"])
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])

    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    return jsonify(logs), 200


# -------------------------------
# Filter logs by user
# -------------------------------
@app.route("/logs/user/<username>", methods=["GET"])
def get_logs_by_user(username):
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    filtered = [log for log in logs if log.get("user") == username]

    return jsonify(filtered), 200


# -------------------------------
# Filter logs by event type
# -------------------------------
@app.route("/logs/event/<event>", methods=["GET"])
def get_logs_by_event(event):
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    filtered = [log for log in logs if log.get("event") == event.upper()]

    return jsonify(filtered), 200


# -------------------------------
# Run service
# -------------------------------
if __name__ == "__main__":
    app.run(port=6000, debug=True)