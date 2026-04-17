import requests
import uuid

KDC_URL = "http://localhost:5000"
RS_HR_URL = "http://localhost:5002"

# -------------------------------------------------------
# STEP 1: Login and get TGT
# -------------------------------------------------------
def login(username, password):
    response = requests.post(f"{KDC_URL}/login", json={
        "username": username,
        "password": password
    })

    if response.status_code == 200:
        tgt = response.json()["tgt"]
        print(f"[+] Login successful, TGT received")
        return tgt
    else:
        print(f"[-] Login failed: {response.json()['error']}")
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
def access_resource(service_ticket, resource_id):
    # Generate a unique authenticator for this specific request
    # This is what prevents replay attacks
    authenticator = str(uuid.uuid4())

    response = requests.get(
        f"{RS_HR_URL}/resource/{resource_id}",
        headers={
            "Service-Ticket": service_ticket,
            "Authenticator": authenticator
        }
    )

    if response.status_code == 200:
        print(f"[+] Access granted")
        print(f"[+] Resource data: {response.json()['resource']}")
    else:
        print(f"[-] Access denied: {response.json()}")



if __name__ == "__main__":
    print("\n===== SECURECORP IAM SYSTEM =====\n")

    username = input("Enter username: ")
    password = input("Enter password: ")

    # Step 1: Login
    tgt = login(username, password)
    if not tgt:
        exit()

    # Step 2: Request service ticket for HR
    service_ticket = request_service_ticket(tgt, "HR")
    if not service_ticket:
        exit()

    # Step 3: Access a resource
    resource_id = input("Enter resource ID to access (e.g. hr_001): ")
    access_resource(service_ticket, resource_id)