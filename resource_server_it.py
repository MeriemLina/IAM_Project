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
        return jsonify({"error": "Missing ticket or authenticator"}), 401

    if authenticator in used_authenticators:
        return jsonify({"error": "Replay attack detected"}), 401

    used_authenticators.add(authenticator)

    try:
        ticket_data = jwt.decode(service_ticket, SERVICE_SECRET, algorithms=["HS256"])
    except:
        return jsonify({"error": "Invalid or expired ticket"}), 401

    if ticket_data.get("type") != "SERVICE_TICKET":
        return jsonify({"error": "Invalid ticket type"}), 401

    # 🔥 IMPORTANT CHANGE
    if ticket_data.get("service") != "IT":
        return jsonify({"error": "Wrong service"}), 401

    resources = load_data()
    resource = next((r for r in resources if r["id"] == resource_id), None)

    if not resource:
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
        return jsonify({"resource": resource}), 200
    else:
        return jsonify({"error": "Access denied", "reason": decision}), 403


if __name__ == "__main__":
    app.run(port=5004, debug=True)