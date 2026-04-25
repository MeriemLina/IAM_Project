from flask import Flask, request, jsonify
import json
import jwt
import datetime
import uuid
import requests

app = Flask(__name__)

KDC_SECRET = "kdc_projet_iam_s8"
SERVICE_SECRET = "service_projet_iam_s8"

def load_users():
    with open("users.json", "r") as f:
        data = json.load(f)
    return data["users"]



@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    username = body.get("username")
    password = body.get("password")

    # Look for the user in users.json
    users = load_users()
    user = next((u for u in users if u["username"] == username), None)

    # If user not found or password wrong, deny
    if not user or user["password"] != password:
        requests.post("http://localhost:6000/log", json={
            "component": "KDC",
            "event": "LOGIN",
            "user": username,
            "action": "login",
            "decision": "DENY",
            "reason": "Invalid credentials"
        })
        return jsonify({"error": "Invalid credentials"}), 401

    # Build the TGT payload
    # This is what gets encoded inside the ticket
    tgt_payload = {
        "type": "TGT",
        "username": user["username"],
        "role": user["role"],
        "department": user["department"],
        "clearance": user["clearance"],
        "location": user["location"],
        # Ticket expires in 1 hour
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        # Unique session key for this user session
        "session_key": str(uuid.uuid4())
    }

    # Encode the TGT using JWT signed with KDC_SECRET
    # JWT handles encryption + tamper resistance for us
    tgt = jwt.encode(tgt_payload, KDC_SECRET, algorithm="HS256")

    requests.post("http://localhost:6000/log", json={
        "component": "KDC",
        "event": "LOGIN",
        "user": username,
        "action": "login",
        "decision": "ALLOW",
        "reason": "Valid credentials"
    })

    return jsonify({"tgt": tgt}), 200




@app.route("/request-ticket", methods=["POST"])
def request_ticket():
    body = request.get_json()
    tgt = body.get("tgt")
    service = body.get("service")  # e.g. "HR"

    # Verify the TGT, this checks signature and expiration automatically
    try:
        tgt_data = jwt.decode(tgt, KDC_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        requests.post("http://localhost:6000/log", json={
            "component": "KDC",
            "event": "TICKET_REQUEST",
            "user": "unknown",
            "service": service,
            "decision": "DENY",
            "reason": "TGT expired"
        })
        return jsonify({"error": "TGT has expired, please login again"}), 401
    except jwt.InvalidTokenError:
        requests.post("http://localhost:6000/log", json={
            "component": "KDC",
            "event": "TICKET_REQUEST",
            "user": "unknown",
            "service": service,
            "decision": "DENY",
            "reason": "Invalid or tampered TGT"
        })
        return jsonify({"error": "Invalid TGT"}), 401

    # Make sure it's actually a TGT and not some other token
    if tgt_data.get("type") != "TGT":
        return jsonify({"error": "Invalid ticket type"}), 401

    # Build the Service Ticket
    # Similar to TGT but scoped to a specific service and shorter expiration
    service_ticket_payload = {
        "type": "SERVICE_TICKET",
        "username": tgt_data["username"],
        "role": tgt_data["role"],
        "department": tgt_data["department"],
        "clearance": tgt_data["clearance"],
        "location": tgt_data["location"],
        "service": service,
        # Service ticket expires in 10 minutes
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
        "session_key": tgt_data["session_key"]
    }

    # Sign the service ticket with SERVICE_SECRET
    # The resource server will use this same secret to verify it
    service_ticket = jwt.encode(service_ticket_payload, SERVICE_SECRET, algorithm="HS256")

    requests.post("http://localhost:6000/log", json={
        "component": "KDC",
        "event": "TICKET_REQUEST",
        "user": tgt_data["username"],
        "service": service,
        "action": "request_ticket",
        "decision": "ALLOW",
        "reason": "Service ticket issued"
    })
    return jsonify({"service_ticket": service_ticket}), 200



if __name__ == "__main__":
    app.run(port=5000, debug=True)