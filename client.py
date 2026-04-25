import requests
import uuid

KDC_URL = "http://localhost:5000"
RS_HR_URL = "http://localhost:5002"

def get_service_url(service):
    service = service.upper()
    if service == "HR":
        return "http://localhost:5002"
    elif service == "FINANCE":
        return "http://localhost:5003"
    elif service == "IT":
        return "http://localhost:5004"
    elif service == "OPERATIONS":
        return "http://localhost:5005"

# -------------------------------------------------------
# STEP 1: Login and get TGT
# -------------------------------------------------------
def login(username, password):
    try:
        response = requests.post(f"{KDC_URL}/login", json={
            "username": username,
            "password": password
        })

        if response.status_code == 200:
            tgt = response.json()["tgt"]
            print(f"[+] Login successful, TGT received")
            return tgt
        else:
            try:
                error = response.json().get("error", "Unknown error")
            except:
                error = "Server error (no JSON response)"
            print(f"[-] Login failed: {error}")
            return None

    except requests.exceptions.ConnectionError:
        print(" Cannot connect to KDC. Is the server running?")
        return None

# -------------------------------------------------------
# STEP 2: Request a service ticket from KDC using TGT
# -------------------------------------------------------
def request_service_ticket(tgt, service):
    response = requests.post(f"{KDC_URL}/request-ticket", json={
        "tgt": tgt,
        "service": service
    })

    if response.status_code == 200:
        service_ticket = response.json()["service_ticket"]
        print(f"[+] Service ticket received for {service}")
        return service_ticket
    else:
        print(f"[-] Failed to get service ticket: {response.json()['error']}")
        return None


# -------------------------------------------------------
# STEP 3: Access a resource on the HR resource server
# -------------------------------------------------------
def access_resource(service_ticket, resource_id, service):
    authenticator = str(uuid.uuid4())

    RS_URL = get_service_url(service)

    if not RS_URL:
        print(" Invalid service name")
        return "invalid"

    try:
        response = requests.get(
            f"{RS_URL}/resource/{resource_id}",
            headers={
                "Service-Ticket": service_ticket,
                "Authenticator": authenticator
            }
        )

        if response.status_code == 200:
            print(f"[+] Access granted")
            print(f"[+] Resource data: {response.json()['resource']}")
            return "success"

        else:
            data = response.json()

            #  Resource does not exist → retry
            if "Resource not found" in str(data):
                print(" Resource not found, try again.")
                return "retry"

            #  Access denied → stop
            print(f"[-] Access denied: {data}")
            return "denied"

    except requests.exceptions.ConnectionError:
        print(" Cannot connect to resource server")
        return "invalid"

if __name__ == "__main__":
    print("\n===== SECURECORP IAM SYSTEM =====\n")

    # Step 1: Login with retry
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")

        tgt = login(username, password)

        if tgt:
            break
        else:
            print(" Invalid credentials, please try again.\n")


    # Step 2: Request service ticket for a Department
    while True:

        service = input("Enter service (HR / Finance / IT / Operations): ").strip().upper()
        RS_URL = get_service_url(service)

        if not RS_URL:
            print(" Invalid service name, please try again.\n")
            continue

        service_ticket = request_service_ticket(tgt, service)

        if service_ticket:
            break
        else:
            print(" Failed to get service ticket, try again.\n")

    # Step 3: Access a resource
    while True:

        resource_id = input("Enter resource ID to access (e.g. hr_001): ")
        result = access_resource(service_ticket, resource_id, service)
        if result == "success":
            break

        elif result == "denied":
            break

        elif result == "retry":
            continue

        else:
            break