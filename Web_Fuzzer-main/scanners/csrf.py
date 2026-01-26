
import requests
from core.network import requester
from config import Colors
import utils
import re
import os

def scan(url):
    vulnerabilities = []
    Colors.info("Testing for CSRF (Cross-Site Request Forgery)...")
    
    # 1. Target State-Changing Endpoints (Heuristic)
    # We look for forms or endpoints that look like they change state
    # For this scanner, we will try to find a 'password change' or similar form on the page.
    # Current limitation: We need to know specific endpoints. 
    # Fallback: Check the specific URL provided if it looks like a form handler.
    
    # Let's try to detect if the page has a form first.
    response = requester.get(url)
    if not response: 
        return []
    
    forms = re.findall(r'<form[^>]+>', response.text, re.IGNORECASE)
    if not forms:
        # No forms found, likely API or static page.
        return []
        
    Colors.info(f"Found {len(forms)} forms. checking for Anti-CSRF tokens...")
    
    # 2. Check for Anti-CSRF Token presence
    has_csrf_token = False
    token_names = ['csrf', 'csrf_token', 'authenticity_token', 'xsrf_token', 'token']
    
    lower_text = response.text.lower()
    for name in token_names:
        if f'name="{name}"' in lower_text or f"name='{name}'" in lower_text:
            has_csrf_token = True
            break
            
    if not has_csrf_token:
         # Finding 1: Missing CSRF Token
         Colors.vuln(f"Form without Anti-CSRF token found at {url}")
         vulnerabilities.append({
            "type": "Cross-Site Request Forgery (CSRF)",
            "payload": "Missing Anti-CSRF Token",
            "evidence": "No token found in form fields.",
            "location": f"Form at {url}",
            "impact": "Attacker can force users to perform unwanted actions.",
            "severity": "Medium",
            "recommendation": "Implement Anti-CSRF tokens for all state-changing forms."
        })
    else:
        # Finding 2: Weak Validation / Bypass Attempts
        # If token exists, try to bypass.
        # This requires submitting the form, which is complex without knowing inputs.
        # We will attempt Method Swap (POST -> GET) if it's a POST form.
        pass

    return vulnerabilities
