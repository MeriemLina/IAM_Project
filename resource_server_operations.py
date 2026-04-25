from flask import Flask, request, jsonify
import json
import jwt
import uuid
import requests

app = Flask(__name__)

# Same secret as KDC for service ticket verification
SERVICE_SECRET = "service_projet_iam_s8"

# Store used authenticators to prevent replay attacks
used_authenticators = set()

# Load Operations data
def load_data():
    with open("operations_data.json", "r") as f:
        data = json.load(f)
    return data["resources"]


@app.route("/resource/<resource_id>", methods=["GET"])
def get_resource(resource_id):

    service_ticket = request.headers.get("Service-Ticket")
    authenticator = request.headers.get("Authenticator")

    # Check presence of headers
    if not service_ticket or not authenticator:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": "unknown",
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Missing ticket or authenticator"
        })
        return jsonify({"error": "Missing ticket or authenticator"}), 401

    # -------------------------------
    # 🔒 Replay attack protection
    # -------------------------------
    if authenticator in used_authenticators:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ATTACK",
            "user": "unknown",
            "service": "Operations",
            "resource": resource_id,
            "action": "replay",
            "decision": "DENY",
            "reason": "Replay attack detected"
        })
        return jsonify({"error": "Replay attack detected"}), 401

    used_authenticators.add(authenticator)

    # -------------------------------
    # 🔒 Ticket validation
    # -------------------------------
    try:
        ticket_data = jwt.decode(service_ticket, SERVICE_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": "unknown",
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Expired service ticket"
        })
        return jsonify({"error": "Service ticket expired"}), 401
    except jwt.InvalidTokenError:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ATTACK",
            "user": "unknown",
            "service": "Operations",
            "resource": resource_id,
            "action": "tampering",
            "decision": "DENY",
            "reason": "Invalid or tampered service ticket"
        })
        return jsonify({"error": "Invalid service ticket"}), 401

    # Check ticket type
    if ticket_data.get("type") != "SERVICE_TICKET":
        return jsonify({"error": "Invalid ticket type"}), 401

    # Check service name
    if ticket_data.get("service") != "OPERATIONS":
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data.get("username", "unknown"),
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Ticket used for wrong service"
        })
        return jsonify({"error": "Ticket not valid for Operations service"}), 401

    # -------------------------------
    # 📦 Load resource
    # -------------------------------
    resources = load_data()
    resource = next((r for r in resources if r["id"] == resource_id), None)

    if not resource:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data.get("username", "unknown"),
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Resource not found"
        })
        return jsonify({"error": "Resource not found"}), 404

    # -------------------------------
    # 🧠 Send request to PDP
    # -------------------------------
    auth_request = {
        "user": {
            "username": ticket_data["username"],
            "role": ticket_data["role"],
            "department": ticket_data["department"],
            "clearance": ticket_data["clearance"],
            "location": ticket_data["location"]
        },
        "resource": {
            "id": resource["id"],
            "department": resource["department"],
            "classification": resource["classification"]
        },
        "action": "read"
    }

    pdp_response = requests.post("http://localhost:5001/authorize", json=auth_request)
    decision = pdp_response.json()

    # -------------------------------
    # ✅ Final decision
    # -------------------------------
    if decision["decision"] == "ALLOW":
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data["username"],
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "ALLOW",
            "reason": "Access granted"
        })
        return jsonify({
            "message": "Access granted",
            "resource": resource
        }), 200
    else:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data["username"],
            "service": "Operations",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": str(decision)
        })
        return jsonify({
            "message": "Access denied",
            "reason": decision
        }), 403


if __name__ == "__main__":
    app.run(port=5005, debug=True)