
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

    usernames = ["admin", "root", "user", "test", "demo", "guest"] 
    # Removed artificial max_attempts limit to scan all combinations
    
    for username in usernames:
        for password in passwords:
            data = {"username": username, "password": password}
            try:
                # Use a short timeout to keep it relatively fast
                response = requests.post(login_url, data=data, timeout=3)

                if response.status_code == 200 and "incorrect" not in response.text.lower() and "fail" not in response.text.lower():
                    Colors.vuln(f"Weak credentials found: {username}:{password}")
                    vulnerabilities.append({
                        "type": "Broken Authentication",
                        "payload": f"{username}:{password}",
                        "evidence": f"Login successful with {username}:{password}",
                        "location": f"Login Form ({login_url})",
                        "endpoint": login_url,
                        "parameter": "username/password",
                        "impact": "Attacker can gain unauthorized access to user accounts.",
                        "severity": "Critical",
                        "recommendation": "Enforce strong password policies and implement account lockout mechanisms."
                    })
                    # We found the password for this user, move to next user
                    break 

            except requests.exceptions.RequestException:
                pass

            
    return vulnerabilities
