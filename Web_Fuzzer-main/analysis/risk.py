
import hashlib

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
        """
        Analyzes and Prioritizes vulnerabilities without clustering (User Request: Show all payload variations).
        """
        if not vulnerabilities:
            return []

        enriched_findings = []
        
        for idx, vuln in enumerate(vulnerabilities):
            # Extract basic details
            severity = vuln.get("severity", "Low")
            confidence = vuln.get("confidence", "Low")
            endpoint = vuln.get("endpoint", "Unknown")
            
            # 1. Calculate Risk Score (CVSS Proxy)
            base_score = self.severity_scores.get(severity, 1.0)
            
            # Boost Score based on Confidence
            conf_multiplier = 1.0
            if confidence == "High": conf_multiplier = 1.0
            elif confidence == "Medium": conf_multiplier = 0.9 
            elif confidence == "Low": conf_multiplier = 0.7
            
            final_score = round(base_score * conf_multiplier, 1)
            
            # 2. Generate CVSS Vector
            cvss_vector = self._get_cvss_vector(severity)
            
            # 3. Determine Fix Priority
            priority_score = final_score
            
            # Boost priority for key assets
            is_auth_endpoint = any(x in str(endpoint).lower() for x in ["login", "admin", "signup", "auth", "profile"])
            if is_auth_endpoint:
                priority_score += 1.0 
            
            # Update the vulnerability object
            vuln["cvss_score"] = final_score
            vuln["cvss_vector"] = cvss_vector
            vuln["priority_score"] = priority_score
            
            # Add metadata expected by report (even if not clustering)
            vuln["is_cluster"] = False
            vuln["variation_count"] = 1
            
            # Ensure nice recommendation
            recommendation = vuln.get("recommendation", "Review code.")
            if len(recommendation) < 20: 
                recommendation += " Please consult the OWASP Cheat Sheet for this vulnerability type."
            vuln["recommendation"] = recommendation

            enriched_findings.append(vuln)
            
        # 4. Sort by Priority (Fix Order)
        # Critical -> High -> Medium
        enriched_findings.sort(key=lambda x: x["priority_score"], reverse=True)
        
        # Add "Fix Order" Index
        for idx, finding in enumerate(enriched_findings):
            finding["fix_index"] = idx + 1
            
        return enriched_findings

    def _get_cvss_vector(self, severity):
        if severity == "Critical":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        elif severity == "High":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
        elif severity == "Medium":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        else:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
