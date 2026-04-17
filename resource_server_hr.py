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
        return jsonify({"error": "Missing ticket or authenticator"}), 401

    # ---- REPLAY ATTACK PREVENTION ----
    # If this authenticator was used before, reject the request
    if authenticator in used_authenticators:
        return jsonify({"error": "Replay attack detected, authenticator already used"}), 401
    
    # Mark this authenticator as used
    used_authenticators.add(authenticator)

    # ---- TICKET VALIDATION ----
    # Verify the service ticket using SERVICE_SECRET
    try:
        ticket_data = jwt.decode(service_ticket, SERVICE_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Service ticket has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid service ticket"}), 401

    # Make sure it's a service ticket and not a TGT
    if ticket_data.get("type") != "SERVICE_TICKET":
        return jsonify({"error": "Invalid ticket type"}), 401

    # Make sure the ticket is for the HR service
    if ticket_data.get("service") != "HR":
        return jsonify({"error": "Ticket not valid for this service"}), 401

    # ---- FIND THE RESOURCE ----
    resources = load_hr_data()
    resource = next((r for r in resources if r["id"] == resource_id), None)

    if not resource:
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
        return jsonify({
            "message": "Access granted",
            "resource": resource
        }), 200
    else:
        return jsonify({
            "message": "Access denied",
            "reason": pdp_decision["reason"]
        }), 403


if __name__ == "__main__":
    app.run(port=5002, debug=True)