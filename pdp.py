from flask import Flask, request, jsonify
import json
import datetime

app = Flask(__name__)

# Load policies from policies.json
def load_policies():
    with open("policies.json", "r") as f:
        data = json.load(f)
    return data["policies"]



def evaluate_condition(condition, context):
    for key, expected_value in condition.items():

        # Get the actual value from the context using the key
        # key will be something like "user.role" or "resource.classification"
        actual_value = get_value_from_context(key, context)

        # Handle the special case of department isolation
        # where we compare two context values against each other
        if isinstance(expected_value, str) and expected_value.startswith("!="):
            # Extract the other attribute to compare against
            # e.g. "!=resource.department" -> "resource.department"
            other_key = expected_value[2:]
            other_value = get_value_from_context(other_key, context)
            if actual_value != other_value:
                # Condition is met, policy applies
                continue
            else:
                # Condition is not met, policy does not apply
                return False

        # Handle list values
        # e.g. "resource.classification": ["confidential", "secret"]
        elif isinstance(expected_value, list):
            if actual_value not in expected_value:
                return False

        # Handle time-based access
        # e.g. "time.outside_hours": "08:00-18:00"
        elif key == "time.outside_hours":
            start, end = expected_value.split("-")
            start_h, start_m = map(int, start.split(":"))
            end_h, end_m = map(int, end.split(":"))
            now = datetime.datetime.now()
            start_time = now.replace(hour=start_h, minute=start_m, second=0)
            end_time = now.replace(hour=end_h, minute=end_m, second=0)
            if start_time <= now <= end_time:
                # We are inside working hours so the deny condition is NOT met
                return False

        # Simple equality check
        else:
            if actual_value != expected_value:
                return False

    # All conditions in this policy are met
    return True


# Helper function to extract a value from context using dot notation
# e.g. "user.role" -> context["user"]["role"]
def get_value_from_context(key, context):
    parts = key.split(".")
    value = context
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


@app.route("/authorize", methods=["POST"])
def authorize():
    body = request.get_json()

    # Build the context object from the request
    context = {
        "user": body.get("user"),         # user attributes from the service ticket
        "resource": body.get("resource"), # resource attributes from hr_data.json
        "action": body.get("action"),     # e.g. "read", "write", "delete"
        "time": {
            "now": datetime.datetime.now().strftime("%H:%M")
        }
    }

    policies = load_policies()

    # Evaluate each policy one by one
    for policy in policies:
        condition_met = evaluate_condition(policy["condition"], context)

        if condition_met:
            if policy["effect"] == "deny":
                return jsonify({
                    "decision": "DENY",
                    "reason": policy["description"]
                }), 200
            elif policy["effect"] == "allow":
                return jsonify({
                    "decision": "ALLOW",
                    "reason": policy["description"]
                }), 200

    # If no policy matched, apply RBAC as the final check
    decision = check_rbac(context["user"]["role"], context["action"])
    return jsonify({"decision": decision}), 200


# RBAC check as a fallback
# If no ABAC policy matched, check if the user's role allows the action
def check_rbac(role, action):
    rbac = {
        "Admin":    ["read", "write", "delete"],
        "Manager":  ["read", "write"],
        "Employee": ["read"]
    }
    allowed_actions = rbac.get(role, [])
    if action in allowed_actions:
        return "ALLOW"
    return "DENY"


if __name__ == "__main__":
    app.run(port=5001, debug=True)