
import sys
import argparse
import time
from config import Colors, console
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, popup
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

LOGO = r"""
    _    _      _      ______                      
   | |  | |    | |     |  ___|                     
   | |  | | ___| |__   | |_ _   _ ___________ _ __ 
   | |/\| |/ _ \ '_ \  |  _| | | |_  /_  / _ \ '__|
   \  /\  /  __/ |_) | | | | |_| |/ / / /  __/ |   
    \/  \/ \___|_.__/  \_|  \__,_/___/___\___|_|   
                                                   
    Professional Web Vulnerability Scanner
"""

from core.crawler import Crawler
from core.api_discovery import APIDiscovery
from analysis.risk import RiskAnalyzer

def main():
    console.print(Panel.fit(f"[bold blue]{LOGO}[/bold blue]", border_style="blue"))
    
    # Argument Parsing
    if len(sys.argv) < 2:
        console.print(f"[warning]Usage: python main.py <url>[/warning]")
        url = console.input("[bold green]Enter Target URL: [/bold green]").strip()
        if not url:
            sys.exit(1)
    else:
        url = sys.argv[1]

    if not url.startswith("http"):
        url = "http://" + url
    
    # --- Step 0: Validate Target URL ---
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Headers for API requests
    api_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    }
    
    Colors.info(f"Validating target: {url}...")
    
    # Retry logic for cold-start servers (like Render free tier)
    max_retries = 3
    response = None
    
    for attempt in range(max_retries):
        try:
            # Check connectivity with proper headers
            response = requests.get(url, timeout=30, verify=False, headers=api_headers)
            Colors.success(f"Target is online! [{response.status_code}]")
            break
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                Colors.warning(f"Connection attempt {attempt + 1} failed. Retrying in 3 seconds... (Server might be warming up)")
                time.sleep(3)
            else:
                Colors.error(f"Could not connect to target after {max_retries} attempts: {e}")
                Colors.error("Please check the URL is correct and reachable.")
                sys.exit(1)
    
    if response:
        # Handle Redirects
        if response.url != url:
            Colors.warning(f"Redirected to: {response.url}")
            choice = console.input(f"[warning]Do you want to scan this redirected URL? (y/n): [/warning]").strip().lower()
            if choice == 'y' or choice == '':
                url = response.url
            else:
                Colors.info("Keeping original URL (Warning: Scan might be less effective).")

    user_name = "Admin"
    
    # --- Step 1: Choose Discovery Mode ---
    console.print("\n[bold cyan]Choose Discovery Mode:[/bold cyan]")
    console.print("  [1] API Endpoint Discovery (Recommended for testing)")
    console.print("  [2] Frontend Crawling (Traditional mode)")
    
    mode_choice = console.input("\n[bold green]Enter choice (1 or 2): [/bold green]").strip()
    
    if mode_choice == "2":
        # Traditional Frontend Crawling
        with console.status("[bold green]Crawling target for endpoints...[/bold green]") as status:
            crawler = Crawler(url)
            discovered_urls = crawler.crawl(depth=2)
    else:
        # API Endpoint Discovery (Default)
        Colors.info("Starting API Endpoint Discovery...")
        console.print("[dim]This will analyze JavaScript files, fuzz common API paths, and discover actual API endpoints.[/dim]\n")
        
        api_discovery = APIDiscovery(url)
        discovered_urls = api_discovery.discover()
        
        if not discovered_urls:
            Colors.warning("No API endpoints discovered. Falling back to frontend crawling...")
            with console.status("[bold green]Crawling target for endpoints...[/bold green]") as status:
                crawler = Crawler(url)
                discovered_urls = crawler.crawl(depth=2)
    
    if not discovered_urls:
        Colors.error("No endpoints discovered. Exiting.")
        sys.exit(1)

    # --- Scan Registry (Track all module results) ---
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
    
    # Track scanned base URLs to avoid duplicate scans
    scanned_bases = set()
    
    try:
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
            base_path = target_url.split("?")[0]
            if base_path.lower().endswith(STATIC_EXTENSIONS):
                continue
            if base_path in scanned_bases:
                continue
            scanned_bases.add(base_path)
            targets_to_scan.append(target_url)
            
            if len(scanned_bases) >= 100: 
                Colors.warning("Hit limit of 100 unique endpoints. Stopping crawl selection.")
                break
        
        if targets_to_scan:
            Colors.info(f"Selected {len(targets_to_scan)} unique endpoints for parallel scanning.")

            def scan_endpoint_worker(target_url):
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

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                transient=True
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {len(targets_to_scan)} endpoints...", total=len(targets_to_scan))
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                    
                    for future in as_completed(future_to_url):
                        data = future.result()
                        for category, findings in data.items():
                            if category in scan_results:
                                scan_results[category].extend(findings)
                        progress.advance(task)
        
        # --- Step 3: Global/Generic Scanners ---
        with console.status("[bold green]Running Global Configuration Scans...[/bold green]"):
            scan_results["Sensitive Data Exposure"] = sensitive_data.scan(url)
            scan_results["Broken Authentication"] = auth.scan(url)
            
            upload_endpoint = url + "/upload.php"
            check_endpoint = url + "/uploads"
            scan_results["Insecure File Upload"] = file_attacks.scan_insecure_file_upload(upload_endpoint, check_endpoint)
            
            scan_results["Security Misconfiguration"] = misconfig.scan_security_misconfiguration(url)
            scan_results["Rate Limiting"] = misconfig.scan_multiple_login_attempts(url)
            scan_results["Integrity Failure"] = integrity.scan(url)
            scan_results["CSRF"] = csrf.scan(url)

    except KeyboardInterrupt:
        Colors.warning("[!] Scan interrupted by user. Generating report with available findings...")

    # Flatten for Analysis
    all_vulnerabilities = []
    for findings in scan_results.values():
        all_vulnerabilities.extend(findings)

    # --- Intelligence Layer ---
    if all_vulnerabilities:
        Colors.info("Analyzing vulnerabilities for Risk Score & Impact...")
        analyzer = RiskAnalyzer()
        enriched_vulnerabilities = analyzer.analyze(all_vulnerabilities)
        Colors.success(f"Analysis Complete. Processed {len(enriched_vulnerabilities)} findings.")
    else:
        enriched_vulnerabilities = []
        Colors.success("Scan completed. No vulnerabilities found.")
        
    # Reporting
    report_path = html_generator.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    from reporting.json_generator import JsonGenerator
    from reporting.csv_generator import CsvGenerator
    
    json_gen = JsonGenerator()
    json_path = json_gen.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    csv_gen = CsvGenerator()
    csv_path = csv_gen.generate_report(user_name, url, enriched_vulnerabilities)
    
    # Final Summary Table
    table = Table(title="Scan Summary")
    table.add_column("Report Type", style="cyan")
    table.add_column("Path", style="magenta")
    
    table.add_row("HTML Report", report_path)
    table.add_row("JSON Report", json_path)
    table.add_row("CSV Report", csv_path)
    
    console.print(table)

    # Popup
    popup.show_results_popup(report_path)

if __name__ == "__main__":
    main()
