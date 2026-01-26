
import os
import sys

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors

def scan(url):
    Colors.info("Testing for Cross-Site Scripting (XSS)...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_dir = os.path.join(base_dir, "Payloads", "XSS_payload")
    
    xss_payloads = utils.load_payloads_from_dir(payload_dir, extensions=[".txt"])
    
    if not xss_payloads:
        Colors.warning("No payloads found. Using default fallback payloads.")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "'\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]
    else:
        Colors.success(f"Loaded {len(xss_payloads)} XSS payloads.")
        # Full scan enabled - No limits
    
    import random
    
    # --- Optimization: Reflection Pre-Check ---
    # Before sending 16,000 payloads, verify if the input is actually reflected.
    canary = f"XSS_CHECK_{random.randint(10000, 99999)}"
    check_url = f"{url}?q={canary}"
    try:
        Colors.info(f"Checking reflection on {url}...")
        check_res = requester.get(check_url, timeout=5)
        if not check_res or canary not in check_res.text:
            Colors.info(f"Input not reflected on {url}. Skipping 16k payload scan (Optimization).")
            return [] # Save time!
        Colors.success(f"Reflection confirmed on {url}! Starting exhaustive XSS scan...")
    except:
        return []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from config import MAX_THREADS

    vulnerabilities = []
    
    def test_payload(payload):
        test_url = f"{url}?q={payload}" 
        try:
            response = requester.get(test_url)

            if response and payload in response.text:
                Colors.vuln(f"Vulnerability Found! (Payload: {payload[:20]}...)")
                
                info = utils.get_vuln_details("Cross-Site Scripting (XSS)")
                
                return {
                    "type": "Cross-Site Scripting (XSS)",
                    "payload": payload,
                    "evidence": f"Reflected Payload found in response: ...{payload}... (Context hidden)",
                    "location": f"Parameter: q (in URL: {test_url})",
                    "impact": info["impact"],
                    "severity": "Medium",
                    "recommendation": info["recommendation"]
                }
        except:
            pass
        return None
    
    Colors.info(f"Scanning with {MAX_THREADS} threads...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(test_payload, p) for p in xss_payloads]
        for future in as_completed(futures):
            res = future.result()
            if res:
                vulnerabilities.append(res)

    return vulnerabilities

if __name__ == "__main__":
    import sys
    print("Standalone XSS Scanner")
    if len(sys.argv) < 2:
        target = input("Enter target URL: ").strip()
    else:
        target = sys.argv[1]
    
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']}")
