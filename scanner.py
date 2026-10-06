import requests
import json
import time

def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

def test_broken_auth(target_url):
    print("[*] Running State Simulation Broken Authentication (api/v1/admin/dashboard)")
    url = f"{target_url}/api/v1/admin/dashboard"

    # Intentionally omitting the 'Authorization' header
    response = requests.get(url)

    if response.status_code == 200:
        print("     [!] HIGH SEVERITY: Broken Authentication detected. Endpoint accessible without token.")
    else:
        print("     [+] PASS: Authentication enforced")

def test_rate_limiting(target_url):
    print("\n[*] Running Load Simulation: Missing Rate Limiting (api/v1/login)")
    url = f"{target_url}/api/v1/login"
    payload = {"username": "admin", "password": "pass123"}

    rate_limit_enforced = False

    for _ in range(50):
        response = requests.post(url, json=payload)
        if response.status_code == 429:
            rate_limit_enforced = True
            break

    if not rate_limit_enforced:
        print("     [!] HIGH SEVERITY: Missing Rate Limiting. Server accepted 50 rapid requests without 429 status.")
    else:
        print("     [+] PASS: Rate limit enforced.")

def test_data_exposure(target_url, user_id):
    print(f"\n[*] Running Heuristic Fingerprinting: Excessive Data Exposure (/api/v1/users/{user_id})")
    url = f"{target_url}/api/v1/users/{user_id}"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.text.lower()
        # Basic heuristic check for standard sensitive keys
        if "ssn" in data or "password_hash" in data or "internal_db_id" in data:
            print("    [!] HIGH SEVERITY: Excessive Data Exposure. Sensitive keys (ssn, hash) found in JSON payload.")
        else:
            print("    [+] PASS: Payload structure safe.")
    else:
        print(f"    [-] ERROR: Could not reach endpoint (Status {response.status_code})")

if __name__ == "__main__":
    print("--- AutoDIT Local Auditing Engine ---\n")
    config = load_config()
    target = config['target_url']
    
    test_broken_auth(target)
    test_rate_limiting(target)
    test_data_exposure(target, config['test_user_id'])
    
    print("\n--- Scan Complete ---")
