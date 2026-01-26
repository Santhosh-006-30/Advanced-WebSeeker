
import csv
import os
from datetime import datetime

class CsvGenerator:
    def generate_report(self, user_name, target_url, vulnerabilities, filename="report.csv"):
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow(["Type", "Severity", "Risk Score", "URL/Location", "Payload", "Impact", "Remediation"])
                
                # Data
                for v in vulnerabilities:
                    writer.writerow([
                        v.get("type", "Unknown"),
                        v.get("severity", "Informational"),
                        v.get("risk_score", "0.0"),
                        v.get("location", target_url),
                        v.get("payload", ""),
                        v.get("impact", ""),
                        v.get("recommendation", "")
                    ])
                    
            return os.path.abspath(filename)
        except Exception as e:
            return None
