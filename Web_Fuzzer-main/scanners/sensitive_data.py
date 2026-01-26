import re
import os
import sys
import time

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors

sensitive_patterns = {
    "API Key": r"(?i)(api[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{16,}['\"]?)",
    "Password in Response": r"(?i)(password\s*=\s*['\"]?[A-Za-z0-9@#\$\%\^\&\*\!]{6,}['\"]?)",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b"
}

def scan(url):
    vulnerabilities = []
    Colors.info("Testing for Sensitive Data Exposure...")
    
    # Optimized Sensitive Data Scanner (Parallelized)
    
    # 1. Normalize URL: Strip parameters to scan directory/root
    base_url = url.split("?")[0]
    if not base_url.endswith("/"):
        base_url += "/"
        
    Colors.info(f"Scanning for Sensitive Data on base path: {base_url}")
    
    # 2. Detect Soft 404 Signature
    # Many servers return 200 OK even for missing files. We must learn what a 404 looks like.
    dummy_url = f"{base_url}random_404_check_{int(time.time())}"
    soft_404_content = ""
    soft_404_size = 0
    
    try:
        r_dummy = requester.get(dummy_url)
        if r_dummy:
            soft_404_content = r_dummy.text[:500] # Take a snippet
            soft_404_size = len(r_dummy.content)
    except:
        pass

    def is_valid_finding(response):
        """Returns True if this is likely a REAL file, not a custom 404 page."""
        if not response or response.status_code != 200:
            return False
            
        # Size check (if within 5% of the 404 page size, it's likely a 404)
        if soft_404_size > 0:
            diff = abs(len(response.content) - soft_404_size)
            if diff < (soft_404_size * 0.10): # 10% tolerance is safer
                return False
        
        # Content check
        if soft_404_content and soft_404_content in response.text:
            return False
            
        return True

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_file = os.path.join(base_dir, "Payloads", "Sensitive_files", "raft-small-files.txt")
    
    sensitive_files = utils.load_payloads_from_file(payload_file)
    
    if not sensitive_files:
          sensitive_files = [".env", "config.php", "backup.sql", "web.config", "id_rsa", ".git/HEAD"]

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from config import MAX_THREADS

    Colors.info(f"Scanning {len(sensitive_files)} sensitive paths with {MAX_THREADS} threads...")

    def check_file(file_name):
        target_url = f"{base_url}{file_name.lstrip('/')}"
        try:
            response = requester.get(target_url)
            
            if is_valid_finding(response):
                # Double check: ensure it's not just the homepage reflected
                if len(response.content) < 500 and ("<html" in response.text.lower() or "not found" in response.text.lower()):
                     return None

                Colors.vuln(f"Exposed file found: {target_url}")
                
                info = utils.get_vuln_details("Sensitive Data Exposure", file_name)
                
                return {
                    "type": "Sensitive Data Exposure",
                    "payload": file_name,
                    "evidence": f"File Content Snippet: {response.text[:100]}...",
                    "location": f"URL Path: {target_url}",
                    "impact": info["impact"],
                    "severity": "High",
                    "recommendation": info["recommendation"]
                }
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_file, f) for f in sensitive_files]
        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    # Content check
    response = requester.get(url)
    if response:
        page_content = response.text
        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, page_content)
            if matches:
                Colors.vuln(f"{data_type} found: {matches[:3]}")
                
                info = utils.get_vuln_details("Sensitive Data Exposure", data_type)
                
                vulnerabilities.append({
                    "type": "Sensitive Data Exposure",
                    "payload": f"{data_type} match",
                    "location": "Response Body (content match)",
                    "impact": info["impact"],
                    "severity": "Critical",
                    "recommendation": info["recommendation"]
                })

    return vulnerabilities

if __name__ == "__main__":
    import sys
    print("Standalone Sensitive Data Scanner")
    if len(sys.argv) < 2:
        target = input("Enter target URL: ").strip()
    else:
        target = sys.argv[1]
    
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']}")
