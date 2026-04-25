from flask import Flask, request, jsonify
import json
import jwt
import uuid
import requests

app = Flask(__name__)

# Same SERVICE_SECRET as in kdc.py
# This is how the resource server verifies the service ticket
SERVICE_SECRET = "service_projet_iam_s8"

# Stores used authenticators to prevent replay attacks
used_authenticators = set()

# Load HR data
def load_hr_data():
    with open("hr_data.json", "r") as f:
        data = json.load(f)
    return data["resources"]


# -------------------------------------------------------
# ENDPOINT: GET /resource/<id>
# Client presents service ticket + authenticator
# Resource server validates ticket, checks replay, queries PDP
# -------------------------------------------------------
@app.route("/resource/<resource_id>", methods=["GET"])
def get_resource(resource_id):
    # Get the service ticket and authenticator from the request headers
    service_ticket = request.headers.get("Service-Ticket")
    authenticator = request.headers.get("Authenticator")

    # Make sure both are present
    if not service_ticket or not authenticator:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": "unknown",
            "service": "HR",  # change per file
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Missing ticket or authenticator"
        })
        return jsonify({"error": "Missing ticket or authenticator"}), 401

    # ---- REPLAY ATTACK PREVENTION ----
    # If this authenticator was used before, reject the request
    if authenticator in used_authenticators:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ATTACK",
            "user": "unknown",
            "service": "HR",
            "resource": resource_id,
            "action": "replay",
            "decision": "DENY",
            "reason": "Replay attack detected"
        })
        return jsonify({"error": "Replay attack detected, authenticator already used"}), 401
    
    # Mark this authenticator as used
    used_authenticators.add(authenticator)

    # ---- TICKET VALIDATION ----
    # Verify the service ticket using SERVICE_SECRET
    try:
        ticket_data = jwt.decode(service_ticket, SERVICE_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": "unknown",
            "service": "HR",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Expired service ticket"
        })
        return jsonify({"error": "Service ticket has expired"}), 401
    except jwt.InvalidTokenError:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ATTACK",
            "user": "unknown",
            "service": "HR",
            "resource": resource_id,
            "action": "tampering",
            "decision": "DENY",
            "reason": "Invalid or tampered service ticket"
        })
        return jsonify({"error": "Invalid service ticket"}), 401

    # Make sure it's a service ticket and not a TGT
    if ticket_data.get("type") != "SERVICE_TICKET":
        return jsonify({"error": "Invalid ticket type"}), 401

    # Make sure the ticket is for the HR service
    if ticket_data.get("service") != "HR":
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data.get("username", "unknown"),
            "service": "HR",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Ticket used for wrong service"
        })
        return jsonify({"error": "Ticket not valid for this service"}), 401

    # ---- FIND THE RESOURCE ----
    resources = load_hr_data()
    resource = next((r for r in resources if r["id"] == resource_id), None)

    if not resource:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data.get("username", "unknown"),
            "service": "HR",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Resource not found"
        })
        return jsonify({"error": "Resource not found"}), 404

    # ---- QUERY PDP ----
    # Build the authorization request with user and resource attributes
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

    # Send the authorization request to the PDP
    pdp_response = requests.post("http://localhost:5001/authorize", json=auth_request)
    pdp_decision = pdp_response.json()

    # ---- GRANT OR DENY ACCESS ----
    if pdp_decision["decision"] == "ALLOW":
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data["username"],
            "service": "HR",
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
            "service": "HR",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": str(pdp_decision)
        })
        return jsonify({
            "message": "Access denied",
            "reason": pdp_decision["reason"]
        }), 403



if __name__ == "__main__":
    app.run(port=5002, debug=True)