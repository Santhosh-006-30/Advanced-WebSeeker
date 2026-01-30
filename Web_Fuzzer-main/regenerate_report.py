
import json
import sys
import os
from reporting import html_generator

def regenerate():
    # Load existing findings
    try:
        with open("report.json", "r") as f:
            vulnerabilities = json.load(f)
            print(f"Loaded {len(vulnerabilities)} findings from report.json")
    except FileNotFoundError:
        print("Error: report.json not found. Please run main.py first.")
        return

    # Mock summary if needed (since report.json might just be the list)
    # The current report.json structure is likely just the list of vulns based on common patterns,
    # but let's check. 
    # If report.json is a list, we pass it directly.
    
    user = "Admin"
    url = "http://altoro.testfire.net/" # Default fallback or try to extract from first finding
    
    if isinstance(vulnerabilities, dict):
        # Extract findings from the dictionary structure
        findings = vulnerabilities.get("findings", [])
        summary_stats = vulnerabilities.get("summary", {}).get("module_stats", {})
        
        # Extract metadata if possible
        if "metadata" in vulnerabilities:
             url = vulnerabilities["metadata"].get("target_url", url)
             user = vulnerabilities["metadata"].get("scanned_by", user)
    else:
        # Fallback if it's just a list
        findings = vulnerabilities
        summary_stats = {}

    print(f"Extraction complete: {len(findings)} findings found.")

    # Call the generator
    html_generator.generate_report(user, url, findings, scan_summary=summary_stats)
    print(f"Report regenerated successfully as report.html for target: {url}")

if __name__ == "__main__":
    regenerate()
