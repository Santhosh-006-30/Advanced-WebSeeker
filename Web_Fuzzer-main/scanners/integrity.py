
import re
from core.network import requester
from config import Colors
import utils

def scan(url):
    vulnerabilities = []
    Colors.info("Testing for Software & Data Integrity Failures (A08)...")

    response = requester.get(url)
    if not response:
        return []

    content = response.text
    
    # 1. Check for Subresource Integrity (SRI) on external scripts
    # Find <script src="..."> tags
    # Regex loosely matches script tags with src attribute
    script_tags = re.findall(r'<script[^>]+src=["\'](http[^"\']+)["\'][^>]*>', content, re.IGNORECASE)
    
    # Filter for external domains (heuristic: starts with http and not current domain?) 
    # For now, simplistic check: if it's a full URL
    
    for script_src in script_tags:
        # If it's an external library (cdn, google, etc) and NO integrity attribute in the tag...
        # We need the full tag content to check for integrity.
        # Let's find full tags first.
        pass

    # Better regex to capture full tag
    full_script_tags = re.findall(r'(<script[^>]+src=["\'](http[^"\']+)["\'][^>]*>)', content, re.IGNORECASE)
    
    for full_tag, src_url in full_script_tags:
        # Check if it's external (simplistic: contains 'http' and looks like a CDN or different domain)
        # We assume 'url' is the target.
        if "integrity=" not in full_tag.lower():
             # Heuristic: only flag if it looks like a CDN or external resource
             if "cdn" in src_url or "googleapis" in src_url or "cloudflare" in src_url or "unpkg" in src_url:
                Colors.vuln(f"Missing SRI on external script: {src_url}")
                
                info = utils.get_vuln_details("Integrity Failure", src_url)
                
                vulnerabilities.append({
                    "type": "Integrity Failure",
                    "payload": f"Missing integrity attribute on {src_url}",
                    "evidence": f"Found insecure script tag: {full_tag}",
                    "location": f"HTML Source (Script Tag)",
                    "impact": info["impact"],
                    "severity": "Medium",
                    "recommendation": info["recommendation"]
                })
                # Limit to one finding per type to avoid spam
                break

    # 2. Mixed Content Check
    if url.startswith("https://"):
        http_resources = re.findall(r'src=["\'](http://[^"\']+)["\']', content, re.IGNORECASE)
        if http_resources:
             Colors.vuln(f"Mixed Content (HTTP) found on HTTPS page: {http_resources[0]}")
             vulnerabilities.append({
                    "type": "Integrity Failure", # Or Misconfig
                    "payload": f"Insecure resource: {http_resources[0]}",
                    "location": "HTML Source",
                    "impact": "Loading insecure content allows MITM attackers to modify the page or steal credentials.",
                    "severity": "High",
                    "recommendation": "Ensure all resources are loaded via HTTPS."
             })

    return vulnerabilities
