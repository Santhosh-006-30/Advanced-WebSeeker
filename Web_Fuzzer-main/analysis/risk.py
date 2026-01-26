
import random

class RiskAnalyzer:
    def __init__(self):
        self.severity_scores = {
            "Critical": 9.5,
            "High": 8.0,
            "Medium": 5.5,
            "Low": 3.0,
            "Info": 1.0
        }

    def analyze(self, vulnerabilities):
        enriched_vulns = []
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Medium")
            
            # 1. Calculate Numeric Score
            base_score = self.severity_scores.get(severity, 5.0)
            # Add some variance for "realism" or specific heuristics if we had them
            final_score = base_score
            
            # 2. Generate CVSS Vector (Simulated based on type)
            if severity == "Critical":
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            elif severity == "High":
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"
            elif severity == "Medium":
                cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
            else:
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

            # 3. Enhance Recommendation (if simple)
            recommendation = vuln.get("recommendation", "Review code.")
            if len(recommendation) < 20: 
                recommendation += " Please consult the OWASP Cheat Sheet for this vulnerability type."

            # Update the vulnerability object
            vuln["cvss_score"] = final_score
            vuln["cvss_vector"] = cvss_vector
            vuln["recommendation"] = recommendation
            
            enriched_vulns.append(vuln)
            
        # Sort by severity (Critical first)
        enriched_vulns.sort(key=lambda x: x["cvss_score"], reverse=True)
        return enriched_vulns
