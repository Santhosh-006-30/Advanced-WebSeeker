
import os
import utils
import requests
from config import Colors

def scan(url):
    vulnerabilities = []
    login_url = f"{url}/login.php" 

    Colors.info("Testing for Broken Authentication...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    password_file = os.path.join(base_dir, "Payloads", "Broken_Auth", "best110.txt")
    
    passwords = utils.load_payloads_from_file(password_file)
    
    if not passwords:
        Colors.warning("Password file not found. Using default credentials.")
        passwords = ["123456", "password", "12345678", "qwerty"]

    usernames = ["admin", "root", "user", "test"] 
    max_attempts = 20
    attempts = 0

    for username in usernames:
        for password in passwords:
            # Exhaustive scan: No attempt limit
            
            attempts += 1
            data = {"username": username, "password": password}
            
            try:
                # We use a fresh session or the requester logic, but for auth brute force usually we want clean sessions or a specific logic.
                # using requests directly here for simplicity in session handling if needed, or update requester to support post data
                response = requests.post(login_url, data=data, timeout=5)

                if response.status_code == 200 and "incorrect" not in response.text.lower():
                    Colors.vuln(f"Weak credentials found: {username}:{password}")
                    vulnerabilities.append({
                        "type": "Broken Authentication",
                        "payload": f"{username}:{password}",
                        "location": f"Login Form ({login_url})",
                        "impact": "Attacker can gain unauthorized access to user accounts.",
                        "severity": "High",
                        "recommendation": "Enforce strong password policies and implement account lockout mechanisms."
                    })
                    break 

            except requests.exceptions.RequestException:
                pass
        
        if attempts >= max_attempts:
            break
            
    return vulnerabilities
