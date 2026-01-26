import requests
import time
import os
import utils
from core.network import requester
from config import Colors

def scan_ssrf(url):
    vulnerabilities = []
    
    # Common parameters vulnerable to SSRF
    ssrf_params = [
        "url", "uri", "link", "src", "target", "dest", "host", "data", "reference", 
        "site", "html", "val", "validate", "domain", "callback", "feed"
    ]
    
    # Load Payloads (Externalized)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_dir = os.path.join(base_dir, "Payloads", "SSRF")
    
    payloads = []
    
    if os.path.exists(payload_dir):
        payloads = utils.load_payloads_from_dir(payload_dir)
        
    if not payloads:
        # Fallback
        payloads = [
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/"
        ]
    else:
        Colors.info(f"Loaded {len(payloads)} SSRF payloads.")

    if "?" not in url:
        return []

    base_url, query_string = url.split("?", 1)
    params = query_string.split("&")
    
    Colors.info(f"Scanning {url} for SSRF (A10)...")

    for i, param in enumerate(params):
        if "=" not in param:
            continue
            
        key, value = param.split("=", 1)
        
        if key.lower() in ssrf_params:
            for payload in payloads:
                # Reconstruct URL with injected payload
                new_params = params.copy()
                new_params[i] = f"{key}={payload}"
                test_url = f"{base_url}?{'&'.join(new_params)}"
                
                try:
                    start_time = time.time()
                    response = requester.get(test_url)
                    end_time = time.time()
                    
                    # Heuristics:
                    # 1. Timing: If localhost connection is instant vs standard timeout
                    # 2. Status: If internal 403 reduces to 200 or vice versa
                    # 3. Content: If "AWS" or "root" appears (rare via SSRF usually blind)
                    
                    if response and response.status_code == 200:
                         # Very simplistic check for demonstration
                         if "latest" in response.text and "169.254" in payload:
                              Colors.vuln(f"Possible Cloud Metadata SSRF: {test_url}")
                              vulnerabilities.append({
                                "type": "SSRF",
                                "payload": payload,
                                "evidence": f"Response contains Metadata signature: {response.text[:100]}...",
                                "location": f"Parameter: {key}",
                                "impact": "Attacker can read internal server resources (Cloud Metadata, Internal APIs).",
                                "severity": "Critical",
                                "recommendation": "Whitelist allowed domains and block internal IP ranges."
                            })

                except Exception as e:
                    pass
                    
    return vulnerabilities
