
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Colors
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, json_generator, csv_generator
from core.crawler import Crawler
from analysis.risk import RiskAnalyzer

class ScannerEngine:
    def __init__(self, output_callback=None):
        """
        output_callback: function(message_type, message_content)
        message_type: 'info', 'warning', 'error', 'success', 'progress'
        """
        self.output_callback = output_callback
        self.should_stop = False

    def log(self, type, message):
        if self.output_callback:
            self.output_callback(type, message)
        else:
            # Fallback for when running standalone (if needed)
            pass

    def stop(self):
        self.should_stop = True

    def run_scan(self, url, user_name="Admin"):
        if not url.startswith("http"):
            url = "http://" + url
        
        self.log("info", f"Validating target: {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            self.log("success", f"Target is online! [{response.status_code}]")
            
            if response.url != url:
                self.log("warning", f"Redirected to: {response.url}")
                # For automated engine, we usually follow redirects or stick to original.
                # Here we will follow specific logic or just notify.
                # For now, let's update url if redirected? 
                # In main.py it asks user. Here we'll stick to provided URL unless we decide otherwise.
                # Let's just create a notify.
                url = response.url # Auto-follow for web scanner simplicity
                self.log("info", f"Following redirect to: {url}")

        except requests.exceptions.RequestException as e:
            self.log("error", f"Could not connect to target: {e}")
            return None

        # --- Step 1: Discover Endpoints (Crawler) ---
        self.log("info", "Crawling target for endpoints...")
        crawler = Crawler(url)
        # Note: Crawler might print to console internally if not modified. 
        # Ideally Crawler should also use a logger, but we can't change deep code easily without risk.
        # We assume Crawler is mostly silent or we accept stdout.
        discovered_urls = crawler.crawl(depth=2)
        
        if not discovered_urls:
            self.log("error", "Crawler failed to reach target.")
            return None
        
        self.log("info", f"Discovered {len(discovered_urls)} endpoints.")

        # --- Scan Registry ---
        scan_results = {
            "SQL Injection": [],
            "Cross-Site Scripting (XSS)": [],
            "Broken Authentication": [],
            "Sensitive Data Exposure": [],
            "Command Injection": [],
            "Directory Traversal": [],
            "Insecure File Upload": [],
            "CSRF": [],
            "IDOR": [],
            "Security Misconfiguration": [],
            "Rate Limiting": [],
            "Vulnerable and Outdated Components": [],
            "Integrity Failure": [],
            "Logging Failure": []
        }

        self.log("info", f"Starting Exhaustive Scan on {len(discovered_urls)} endpoints...")

        # Filter targets
        scanned_bases = set()
        targets_to_scan = []
        STATIC_EXTENSIONS = (
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
            '.css', '.js', '.ico', '.woff', '.woff2', '.ttf', '.eot', 
            '.mp3', '.mp4', '.avi', '.zip', '.rar', '.tar', '.gz', 
            '.7z', '.exe', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.xml', '.json'
        )

        for target_url in discovered_urls:
            base_path = target_url.split("?")[0]
            if base_path.lower().endswith(STATIC_EXTENSIONS):
                continue
            if base_path in scanned_bases:
                continue
            scanned_bases.add(base_path)
            targets_to_scan.append(target_url)
            if len(scanned_bases) >= 100:
                self.log("warning", "Hit limit of 100 unique endpoints.")
                break

        if targets_to_scan:
            self.log("info", f"Selected {len(targets_to_scan)} unique endpoints for parallel scanning.")
            
            def scan_endpoint_worker(target_url):
                if self.should_stop: return {}
                
                endpoint_results = {
                    "Command Injection": [],
                    "Directory Traversal": [],
                    "IDOR": [],
                    "SQL Injection": [],
                    "Cross-Site Scripting (XSS)": [],
                    "SSRF": []
                }
                
                # Fast Checks
                endpoint_results["Command Injection"].extend(injection.scan_command_injection(target_url))
                endpoint_results["Directory Traversal"].extend(file_attacks.scan_directory_traversal(target_url))
                endpoint_results["IDOR"].extend(misconfig.scan_idor(target_url))
                
                # Heavy Checks
                endpoint_results["SQL Injection"].extend(sql_injection.scan(target_url))
                endpoint_results["Cross-Site Scripting (XSS)"].extend(xss.scan(target_url))
                endpoint_results["SSRF"].extend(ssrf.scan_ssrf(target_url))
                
                return endpoint_results

            total_targets = len(targets_to_scan)
            completed_targets = 0

            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                
                for future in as_completed(future_to_url):
                    if self.should_stop: break
                    try:
                        data = future.result()
                        for category, findings in data.items():
                            if category in scan_results:
                                scan_results[category].extend(findings)
                    except Exception as exc:
                        self.log("error", f"Scanner generated an exception: {exc}")
                    
                    completed_targets += 1
                    # self.log("progress", f"Scanned {completed_targets}/{total_targets}")
                    # Sending percentage for progress bar
                    percent = int((completed_targets / total_targets) * 100)
                    self.log("progress", str(percent))

        # --- step 3: Global Scanners ---
        if not self.should_stop:
            self.log("info", "Running Global Configuration Scans...")
            scan_results["Sensitive Data Exposure"] = sensitive_data.scan(url)
            scan_results["Broken Authentication"] = auth.scan(url)
            
            upload_endpoint = url + "/upload.php"
            check_endpoint = url + "/uploads"
            scan_results["Insecure File Upload"] = file_attacks.scan_insecure_file_upload(upload_endpoint, check_endpoint)
            
            scan_results["Security Misconfiguration"] = misconfig.scan_security_misconfiguration(url)
            scan_results["Rate Limiting"] = misconfig.scan_multiple_login_attempts(url)
            scan_results["Integrity Failure"] = integrity.scan(url)
            scan_results["CSRF"] = csrf.scan(url)

        # Flatten
        all_vulnerabilities = []
        for findings in scan_results.values():
            all_vulnerabilities.extend(findings)

        # Analysis
        self.log("info", "Analyzing vulnerabilities for Risk Score & Impact...")
        if all_vulnerabilities:
            analyzer = RiskAnalyzer()
            enriched_vulnerabilities = analyzer.analyze(all_vulnerabilities)
            self.log("success", f"Analysis Complete. Found {len(enriched_vulnerabilities)} vulnerabilities.")
        else:
            enriched_vulnerabilities = []
            self.log("success", "Scan completed. No vulnerabilities found.")

        # Reporting
        self.log("info", "Generating reports...")
        report_path = html_generator.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
        
        json_gen = json_generator.JsonGenerator()
        json_path = json_gen.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
        
        csv_gen = csv_generator.CsvGenerator()
        csv_path = csv_gen.generate_report(user_name, url, enriched_vulnerabilities)

        return {
            "html_report": report_path,
            "json_report": json_path,
            "csv_report": csv_path,
            "vulnerability_count": len(enriched_vulnerabilities)
        }
