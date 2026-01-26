
import os
import sys

# Add parent directory to sys.path to allow imports from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors

def scan(url):
    Colors.info("Testing for SQL Injection...")
    
    # Dynamic payload path
    # Assuming utils.py is in the parent directory or we need to fix imports.
    # For now, let's keep utils in root or move it to core. 
    # Current utils.py is in root.
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Go up one level
    payload_dir = os.path.join(base_dir, "Payloads", "Sql_payload")
    
    sql_payloads = utils.load_payloads_from_dir(payload_dir)
    
    if not sql_payloads:
         Colors.warning("No payloads found. Using default fallback payloads.")
         sql_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
    else:
        Colors.success(f"Loaded {len(sql_payloads)} SQL injection payloads.")
        # Full scan enabled - No limits

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from config import MAX_THREADS

    vulnerabilities = []
    
    # Database error signatures (More accurate than just "error")
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlserver",
        "microsoft ole db provider for sql server",
        "ora-00933",
        "postgresql query failed"
    ]
    
    def test_payload(payload):
        # Helper for threaded execution
        test_url = f"{url}?id={payload}"
        try:
            response = requester.get(test_url)
            if response:
                response_text = response.text.lower()
                # Check for signatures
                if any(sig in response_text for sig in error_signatures):
                    matched_sig = next(sig for sig in error_signatures if sig in response_text)
                    Colors.vuln(f"Vulnerability Found! (Payload: {payload[:20]}...)")
                    
                    info = utils.get_vuln_details("SQL Injection", matched_sig)
                    
                    return {
                        "type": "SQL Injection",
                        "payload": payload,
                        "evidence": f"Database Error Signature matched: '{matched_sig}' in response.",
                        "location": f"Parameter: id (in URL: {test_url})",
                        "impact": info["impact"],
                        "severity": "High",
                        "recommendation": info["recommendation"]
                    }
        except:
            pass
        return None

    # Use ThreadPoolExecutor for speed
    Colors.info(f"Scanning with {MAX_THREADS} threads...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_payload = {executor.submit(test_payload, p): p for p in sql_payloads}
        for future in as_completed(future_to_payload):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

if __name__ == "__main__":
    import sys
    print("Standalone SQL Injection Scanner")
    if len(sys.argv) < 2:
        target = input("Enter target URL: ").strip()
    else:
        target = sys.argv[1]
    
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']} ({v.get('impact', 'N/A')})")
