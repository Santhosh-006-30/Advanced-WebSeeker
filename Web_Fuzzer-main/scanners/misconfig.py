
import requests
import time
from core.network import requester
from config import Colors

# CSRF Logic moved to scanners/csrf.py
# def scan_csrf(url):
#     ...

def scan_idor(url):
    vulnerabilities = []
    test_ids = [1, 2, 999, 1000]
    Colors.info("Testing for IDOR...")
    
    for test_id in test_ids:
        test_url = url.replace("{id}", str(test_id))
        response = requester.get(test_url, allow_redirects=False)
        
        if response and response.status_code != 403 and response.status_code != 401:
             vulnerabilities.append({
                "type": "Insecure Direct Object Reference (IDOR)",
                "payload": test_url,
                "location": f"URL Path (ID Parameter)",
                "impact": "Attacker can access unauthorized data by modifying ID parameters.",
                "severity": "High",
                "recommendation": "Implement proper authorization checks before granting access to resources."
            })
    return vulnerabilities

def scan_security_misconfiguration(url):
    vulnerabilities = []
    sensitive_files = ["/robots.txt", "/.git/", "/.htaccess", "/.env"]
    Colors.info("Testing for Security Misconfigurations...")

    for file in sensitive_files:
        test_url = url + file
        response = requester.get(test_url)
        if response and response.status_code == 200:
             Colors.vuln(f"Exposed file found: {file}")
             vulnerabilities.append({
                "type": "Security Misconfiguration",
                "payload": file,
                "location": f"URL Path: {test_url}",
                "impact": "Exposure of sensitive configuration files.",
                "severity": "Medium",
                "recommendation": "Restrict public access to sensitive files and configure proper access control."
            })

    # Headers (A09 & A06)
    response = requester.get(url)
    if response:
        # A06: Server Version
        if "server" in response.headers:
            server_info = response.headers["server"]
            if any(char.isdigit() for char in server_info): 
                vulnerabilities.append({
                    "type": "Vulnerable and Outdated Components",
                    "payload": f"Server Header: {server_info}",
                    "evidence": f"Header Value: {server_info}",
                    "location": "HTTP Response Header",
                    "impact": "Disclosure of server version helps attackers exploit known vulnerabilities in outdated components.",
                    "severity": "Low",
                    "recommendation": "Remove Server header banner or update to the latest secure version."
                })
        
        # A09: Security Logging & Monitoring Failures
        # Check for Correlation IDs (Standard in mature monitoring setups)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if "x-request-id" not in headers_lower and "x-correlation-id" not in headers_lower:
             # This is a "Best Practice" or "Info" finding usually, but for OWASP compliance request we report it.
             vulnerabilities.append({
                "type": "Logging Failure",
                "payload": "Missing X-Request-ID/X-Correlation-ID",
                "location": "HTTP Response Header",
                "impact": "Lack of request correlation identifiers makes incident response and forensic analysis difficult (A09).",
                "severity": "Low", # Info
                "recommendation": "Implement centralized logging with unique request identifiers (e.g. UUIDs) for all transactions."
            })
    return vulnerabilities

def scan_multiple_login_attempts(url):
    vulnerabilities = []
    MAX_ATTEMPTS = 5
    LOGIN_URL = "/login"
    LOGIN_PAYLOAD = {'username': 'admin', 'password': 'incorrect'}
    
    Colors.info("Testing for Rate Limiting (Brute Force)...")
    
    for attempt in range(MAX_ATTEMPTS + 1):
        # We need to measure response/behavior, simply posting repeatedly
        # Simplified logic compared to the complex time-tracking class for demo
        try:
             # Using pure requests to avoid our wrapper's delay which defeats the purpose of test? 
             # Actually wrapper delay is good, but here we want to TEST valid rate limiting.
             # We should probably use raw requests here to be fast.
            response = requests.post(url + LOGIN_URL, data=LOGIN_PAYLOAD, timeout=5)
            # Mock check: if response says "Too many requests" or 429
            if response.status_code == 429 or "too many" in response.text.lower():
                 # Rate limit triggers, expected behavior -> No vuln
                 break 
            
            # If we reached max without blocking (and lets say we assume it should block by 5)
            # This logic is tricky without a real server responding to it.
            # Preserving the "vulnerability found" logic if it DOESN'T block?
            # Original code checked if attempts in timeframe > max. 
            pass 
        except:
            pass

    # Re-adding the original simplified logic or just a placeholder since we don't have state here easily
    # The original file used a global dict `login_attempts` which only works if the script acts as a SERVER or tracking OWN requests?
    # The original script tracked ITS OWN timestamps in `login_attempts` dict which is for server side logic usually.
    # Ah, the original script was weird. It checked "if len > max: vuln". It simulates the CHECK.
    # I will adapt it to report if we can just Keep Hitting it.
    
    # Check if we can hit it 10 times rapidly
    hits = 0
    for i in range(10):
        try:
            r = requests.post(url + LOGIN_URL, data=LOGIN_PAYLOAD, timeout=2)
            if r.status_code != 429:
                hits += 1
        except: pass
        
    if hits == 10:
         vulnerabilities.append({
            "type": "Brute Force / Multiple Login Attempts",
            "payload": "High frequency login attempts",
            "location": f"Login Endpoint: {url+LOGIN_URL}",
            "impact": "Attacker can guess passwords via brute force or credential stuffing.",
            "severity": "Medium",
            "recommendation": "Implement rate limiting and blocking mechanisms for login attempts."
        })
        
    return vulnerabilities
