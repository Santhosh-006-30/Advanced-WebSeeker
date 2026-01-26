
import sys
import argparse
from config import Colors
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, popup

LOGO = """
    _    _      _      ______                      
   | |  | |    | |     |  ___|                     
   | |  | | ___| |__   | |_ _   _ ___________ _ __ 
   | |/\| |/ _ \ '_ \  |  _| | | |_  /_  / _ \ '__|
   \  /\  /  __/ |_) | | | | |_| |/ / / /  __/ |   
    \/  \/ \___|_.__/  \_|  \__,_/___/___\___|_|   
                                                   
    Professional Web Vulnerability Scanner
"""

from core.crawler import Crawler
from analysis.risk import RiskAnalyzer

def main():
    print(Colors.HEADER + LOGO + Colors.ENDC)
    
    # Argument Parsing
    if len(sys.argv) < 2:
        print(f"{Colors.WARNING}Usage: python main.py <url>{Colors.ENDC}")
        url = input("Enter Target URL: ").strip()
        if not url:
            sys.exit(1)
    else:
        url = sys.argv[1]

    if not url.startswith("http"):
        url = "http://" + url

    user_name = "Admin"
    
    # --- Step 1: Discover Endpoints (Crawler) ---
    crawler = Crawler(url)
    discovered_urls = crawler.crawl(depth=2)
    
    if not discovered_urls:
        Colors.error("Crawler failed to reach target. Exiting.")
        sys.exit(1)

    # --- Scan Registry (Track all module results) ---
    # We will accumulate results across ALL endpoints
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
        "Vulnerable and Outdated Components": [], # A06
        "Integrity Failure": [], # A08
        "Logging Failure": [] # A09
    }

    Colors.info(f"Starting Exhaustive Scan on {len(discovered_urls)} endpoints...")
    
    colors_printed = False
    
    # Track scanned base URLs to avoid duplicate scans (e.g., product.php?id=1 vs product.php?id=2)
    scanned_bases = set()
    
    try:
        # --- Step 2: Loop Scanners on Discovered URLs ---
        # --- Step 2: Parallel Scanners on Discovered URLs ---
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Pre-filter targets (Optimization)
        targets_to_scan = []
        
        # Extensions to skip for heavy scanning
        STATIC_EXTENSIONS = (
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
            '.css', '.js', '.ico', '.woff', '.woff2', '.ttf', '.eot', 
            '.mp3', '.mp4', '.avi', '.zip', '.rar', '.tar', '.gz', 
            '.7z', '.exe', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.xml', '.json'
        )

        for target_url in discovered_urls:
            # Normalize and De-duplicate
            base_path = target_url.split("?")[0]
            
            # Skip static files
            if base_path.lower().endswith(STATIC_EXTENSIONS):
                continue
                
            if base_path in scanned_bases:
                continue
            scanned_bases.add(base_path)
            
            # Add to scan list (Scan EVERYTHING that isn't static)
            targets_to_scan.append(target_url)
            
            if len(scanned_bases) >= 20: # Increased limit slightly since we scan more now
                Colors.warning("Hit limit of 20 unique endpoints. Stopping crawl selection.")
                break
        
        if targets_to_scan:
            Colors.info(f"Selected {len(targets_to_scan)} unique endpoints for parallel scanning (XSS/SQLi).")

            def scan_endpoint_worker(target_url):
                """Worker function to scan a single endpoint"""
                endpoint_results = {
                    "Command Injection": [],
                    "Directory Traversal": [],
                    "IDOR": [],
                    "SQL Injection": [],
                    "Cross-Site Scripting (XSS)": [],
                    "SSRF": []
                }
                
                Colors.info(f"Scanning Endpoint: {target_url}")
                
                # Fast Checks
                endpoint_results["Command Injection"].extend(injection.scan_command_injection(target_url))
                endpoint_results["Directory Traversal"].extend(file_attacks.scan_directory_traversal(target_url))
                endpoint_results["IDOR"].extend(misconfig.scan_idor(target_url))
                
                # Heavy Checks
                endpoint_results["SQL Injection"].extend(sql_injection.scan(target_url))
                endpoint_results["Cross-Site Scripting (XSS)"].extend(xss.scan(target_url))
                endpoint_results["SSRF"].extend(ssrf.scan_ssrf(target_url))
                
                return endpoint_results

            # Run scans in parallel (Limit to 10 concurrent endpoints to balance thread usage)
            # Each endpoint can panic up to MAX_THREADS internal threads, so we limit concurrency here.
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        data = future.result()
                        # Aggregate results
                        for category, findings in data.items():
                            if category in scan_results:
                                scan_results[category].extend(findings)
                    except Exception as e:
                        Colors.error(f"Error scanning {url}: {e}")
        
        # --- Step 3: Global/Generic Scanners (Run once on Base URL) ---
        # Protected by the same try/except block now
        
        # Sensitive Data
        scan_results["Sensitive Data Exposure"] = sensitive_data.scan(url)
        
        # Broken Auth
        scan_results["Broken Authentication"] = auth.scan(url)

        # File Upload
        upload_endpoint = url + "/upload.php"
        check_endpoint = url + "/uploads"
        scan_results["Insecure File Upload"] = file_attacks.scan_insecure_file_upload(upload_endpoint, check_endpoint)
        
        # Misconfig
        scan_results["Security Misconfiguration"] = misconfig.scan_security_misconfiguration(url)
        # scan_results["CSRF"] = misconfig.scan_csrf(url) 
        scan_results["Rate Limiting"] = misconfig.scan_multiple_login_attempts(url)
        
        # A08: Integrity
        scan_results["Integrity Failure"] = integrity.scan(url)
        
        # A09: Logging (Included in misconfig)
        
        # CSRF
        scan_results["CSRF"] = csrf.scan(url)

    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user. Generating report with available findings...{Colors.ENDC}")

    # Flatten for Analysis
    all_vulnerabilities = []
    for findings in scan_results.values():
        all_vulnerabilities.extend(findings)

    # --- Intelligence Layer ---
    if all_vulnerabilities:
        Colors.info("Analyzing vulnerabilities for Risk Score & Impact...")
        analyzer = RiskAnalyzer()
        # Note: This modifies objects in place!
        enriched_vulnerabilities = analyzer.analyze(all_vulnerabilities)
        Colors.success(f"Analysis Complete. Processed {len(enriched_vulnerabilities)} findings.")
    else:
        enriched_vulnerabilities = []
        Colors.success("Scan completed. No vulnerabilities found.")
        
    # Reporting
    report_path = html_generator.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    # Export additional formats
    from reporting.json_generator import JsonGenerator
    from reporting.csv_generator import CsvGenerator
    
    json_gen = JsonGenerator()
    json_path = json_gen.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    csv_gen = CsvGenerator()
    csv_path = csv_gen.generate_report(user_name, url, enriched_vulnerabilities)
    
    Colors.success(f"Reports Generated:")
    Colors.info(f" - HTML: {report_path}")
    Colors.info(f" - JSON: {json_path}")
    Colors.info(f" - CSV:  {csv_path}")

    # Popup
    popup.show_results_popup(report_path)

if __name__ == "__main__":
    main()
