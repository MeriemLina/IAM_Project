from flask import Flask, request, jsonify
import json
import jwt
import uuid
import requests


app = Flask(__name__)

SERVICE_SECRET = "service_projet_iam_s8"
used_authenticators = set()

def load_data():
    with open("it_data.json", "r") as f:
        data = json.load(f)
    return data["resources"]

@app.route("/resource/<resource_id>", methods=["GET"])
def get_resource(resource_id):

    service_ticket = request.headers.get("Service-Ticket")
    authenticator = request.headers.get("Authenticator")

    if not service_ticket or not authenticator:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": "unknown",
            "service": "IT",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Missing ticket or authenticator"
        })
        return jsonify({"error": "Missing ticket or authenticator"}), 401


    # removed ticket tampering protection
    try:
        ticket_data = jwt.decode(service_ticket, SERVICE_SECRET, algorithms=["HS256"], options={"verify_signature": False})
    except Exception:
        return jsonify({"error": "Invalid ticket"}), 401




    resources = load_data()
    resource = next((r for r in resources if r["id"] == resource_id), None)

    if not resource:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data.get("username", "unknown"),
            "service": "Finance",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": "Resource not found"
        })
        return jsonify({"error": "Resource not found"}), 404

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

    if decision["decision"] == "ALLOW":
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data["username"],
            "service": "IT",
            "resource": resource_id,
            "action": "read",
            "decision": "ALLOW",
            "reason": "Access granted"
        })
        return jsonify({"resource": resource}), 200
    else:
        requests.post("http://localhost:6000/log", json={
            "component": "RESOURCE",
            "event": "ACCESS",
            "user": ticket_data["username"],
            "service": "IT",
            "resource": resource_id,
            "action": "read",
            "decision": "DENY",
            "reason": str(decision)
        })
        return jsonify({"error": "Access denied", "reason": decision}), 403


if __name__ == "__main__":
    app.run(port=5004, debug=True)