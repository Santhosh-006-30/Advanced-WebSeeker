
from datetime import datetime
from config import Colors
import json

def generate_report(user, url, vulnerabilities, scan_summary=None):
    Colors.info("Generating Professional Report...")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = "report.html"

    # Statistics for Charts
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    type_counts = {}
    
    # OWASP Mapping
    OWASP_MAPPING = {
        "SQL Injection": "A03:2021-Injection",
        "Cross-Site Scripting (XSS)": "A03:2021-Injection",
        "Command Injection": "A03:2021-Injection",
        "Broken Authentication": "A07:2021-Ident & Auth Failures",
        "Sensitive Data Exposure": "A02:2021-Cryptographic Failures",
        "Security Misconfiguration": "A05:2021-Security Misconfig",
        "IDOR": "A01:2021-Broken Access Control",
        "Insecure File Upload": "A04:2021-Insecure Design", # File upload is often design flaw
        "SSRF": "A10:2021-SSRF",
        "Brute Force / Multiple Login Attempts": "A07:2021-Ident & Auth Failures",
        "Directory Traversal": "A01:2021-Broken Access Control",
        "Vulnerable and Outdated Components": "A06:2021-Vulnerable Components",
        "Integrity Failure": "A08:2021-Software/Data Integrity",
        "Logging Failure": "A09:2021-Logging Failures"
    }
    
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        typ = v.get("type", "Other")
        type_counts[typ] = type_counts.get(typ, 0) + 1

    js_severity_data = list(severity_counts.values())
    js_type_labels = list(type_counts.keys())
    js_type_data = list(type_counts.values())

    # Optimize Display: Limit number of items for HTML to prevent browser crash
    MAX_DISPLAY_LIMIT = 500
    total_findings = len(vulnerabilities)
    display_vulnerabilities = vulnerabilities
    truncated = False
    
    if total_findings > MAX_DISPLAY_LIMIT:
        Colors.warning(f"Findings ({total_findings}) exceed display limit ({MAX_DISPLAY_LIMIT}). Truncating HTML report.")
        # Sort by severity score to show most critical first
        # Assuming RiskAnalyzer added 'cvss_score', otherwise use simple mapping
        def get_score(v):
            return v.get("cvss_score", 0)
            
        display_vulnerabilities.sort(key=get_score, reverse=True)
        display_vulnerabilities = display_vulnerabilities[:MAX_DISPLAY_LIMIT]
        truncated = True

    with open(report_file, "w", encoding="utf-8") as report:
        report.write(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Web Fuzzer - Professional Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://kit.fontawesome.com/a076d05399.js" crossorigin="anonymous"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background-color: #f4f7f6; font-family: 'Segoe UI', system-ui, sans-serif; }}
                .sidebar {{ min-height: 100vh; background: #2c3e50; color: white; }}
                .content {{ padding: 2rem; }}
                .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 10px; margin-bottom: 20px; }}
                .header-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
                .badge-critical {{ background-color: #d63031; color: white; }}
                .badge-high {{ background-color: #e17055; color: white; }}
                .badge-medium {{ background-color: #fdcb6e; color: black; }}
                .badge-low {{ background-color: #00b894; color: white; }}
                .badge-secure {{ background-color: #2ecc71; color: white; }} 
                .status-secure {{ color: #2ecc71; font-weight: bold; }}
                .status-vuln {{ color: #d63031; font-weight: bold; }}
                h2, h3 {{ color: #2d3436; }}
            </style>
        </head>
        <body>
            <div class="d-flex">
                <!-- Sidebar -->
                <nav class="sidebar p-3 d-none d-md-block" style="width: 250px;">
                    <h3 class="mb-4 text-center">🛡️ Web Fuzzer</h3>
                    <ul class="nav flex-column">
                        <li class="nav-item mb-2"><a href="#dashboard" class="nav-link text-white"><i class="fas fa-chart-line"></i> Dashboard</a></li>
                        <li class="nav-item mb-2"><a href="#scope" class="nav-link text-white"><i class="fas fa-tasks"></i> Scan Scope</a></li>
                        <li class="nav-item mb-2"><a href="#findings" class="nav-link text-white"><i class="fas fa-bug"></i> Findings</a></li>
                    </ul>
                    <div class="mt-5 text-small text-muted text-center">v2.1 Enterprise</div>
                </nav>

                <!-- Content -->
                <div class="content w-100">
                    <div class="card header-card p-4 mb-4" id="dashboard">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h1 class="display-6 fw-bold">Executive Summary</h1>
                                <p class="mb-0">Target: <strong>{url}</strong> | Scanned by: <strong>{user}</strong> | Date: <strong>{now}</strong></p>
                            </div>
                            <div class="text-end">
                                <h2 class="display-4 fw-bold">{len(vulnerabilities)}</h2>
                                <span>Issues Found</span>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-md-6 text-start">
                                <p class="text-muted"><small>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                            </div>
                            <div class="col-md-6 text-end">
                                <button onclick="window.print()" class="btn btn-outline-primary"><i class="fas fa-file-pdf"></i> Export to PDF</button>
                                <a href="report.json" download class="btn btn-outline-dark"><i class="fas fa-file-code"></i> JSON</a>
                                <a href="report.csv" download class="btn btn-outline-success"><i class="fas fa-file-csv"></i> CSV</a>
                            </div>
                        </div>
                    </div>

                    <!-- Metrics Row -->
                    <div class="row mb-4">
                        <div class="col-md-3">
                            <div class="card p-3 border-start border-5 border-danger">
                                <h5 class="text-secondary">Critical</h5>
                                <h3>{severity_counts['Critical']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card p-3 border-start border-5 border-warning">
                                <h5 class="text-secondary">High</h5>
                                <h3>{severity_counts['High']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card p-3 border-start border-5 border-warning opacity-75">
                                <h5 class="text-secondary">Medium</h5>
                                <h3>{severity_counts['Medium']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card p-3 border-start border-5 border-success">
                                <h5 class="text-secondary">Low</h5>
                                <h3>{severity_counts['Low']}</h3>
                            </div>
                        </div>
                    </div>

                    <!-- Charts Row -->
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <div class="card p-4">
                                <h5>Vulnerability Distribution</h5>
                                <canvas id="typeChart"></canvas>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card p-4">
                                <h5>Risk Profile</h5>
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Scan Scope & Compliance -->
                    <h2 class="mb-3" id="scope">📋 Scan Scope & Compliance</h2>
                    <div class="card p-4 mb-4">
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle"></i> <strong>Methodology:</strong> This assessment utilized a hybrid dynamic analysis (DAST) approach. 
                            Modules marked as <span class="badge badge-secure">Not Detected</span> were tested against known payloads but yielded no successful exploitation.
                        </div>
                        <table class="table table-hover table-bordered">
                            <thead class="table-light">
                                <tr>
                                    <th style="width: 25%">Security Module</th>
                                    <th style="width: 45%">Attack Vectors / Checks Performed</th>
                                    <th style="width: 15%">Status</th>
                                    <th style="width: 15%">Findings</th>
                                </tr>
                            </thead>
                            <tbody>
        """)
        
        # Scope Descriptions (Academic/Professional descriptions)
        scope_details = {
            "SQL Injection": "Boolean-based, Error-based, Time-based, and Union-based injection tests on URL parameters.",
            "Cross-Site Scripting (XSS)": "Reflected and Stored XSS checks using polyglot payloads and event handler injection.",
            "Broken Authentication": "Default credential testing, weak password spraying, and login page analysis.",
            "Sensitive Data Exposure": "Scanning for backup files (.bak, .old), configuration files (.env, .git), and PII in responses.",
            "Command Injection": "OS command execution tests (e.g., ;ls, |whoami) on input fields.",
            "Directory Traversal": "Path traversal attempts (../../) to access system files (/etc/passwd, boot.ini).",
            "Insecure File Upload": "MIME type bypass, extension spoofing, and executable file upload attempts.",
            "CSRF": "Verification of anti-CSRF tokens and SameSite cookie attributes on state-changing forms.",
            "IDOR": "Sequential and random ID probing to detect horizontal/vertical privilege escalation.",
            "Security Misconfiguration": "Server header analysis, debug info checking, and default page detection.",
            "Rate Limiting": "Brute-force simulation to verify request throttling and account lockout mechanisms."
        }

        # Render Scan Summary Table
        if scan_summary:
            for module_name, findings in scan_summary.items():
                count = len(findings)
                description = scope_details.get(module_name, "Standard vulnerability assessment.")
                
                status_label = '<span class="status-secure"><i class="fas fa-check-circle"></i> Not Detected</span>'
                row_class = ""
                
                if count > 0:
                    status_label = '<span class="status-vuln"><i class="fas fa-exclamation-triangle"></i> Detected</span>'
                    row_class = "table-warning"
                
                report.write(f"""
                <tr class="{row_class}">
                    <td class="fw-bold">{module_name}</td>
                    <td><small class="text-muted">{description}</small></td>
                    <td>{status_label}</td>
                    <td>{count} issue(s)</td>
                </tr>
                """)
        else:
             report.write("<tr><td colspan='4'>Full scan summary not available.</td></tr>")

        report.write("""
                            </tbody>
                        </table>
                    </div>

                    <!-- Findings Section -->
                    <h2 class="mb-3" id="findings">🔍 Detailed Findings</h2>
                    <div class="card p-3">
        """)

        if not vulnerabilities:
            report.write("<div class='alert alert-success'>✅ No vulnerabilities found. System appears secure.</div>")
        else:
            if truncated:
                 report.write(f"""
                 <div class='alert alert-warning border-2 border-warning'>
                    <h4 class="alert-heading"><i class="fas fa-exclamation-triangle"></i> Report Truncated</h4>
                    <p>The scanner found a total of <strong>{total_findings}</strong> vulnerabilities. 
                    For performance reasons, only the top <strong>{MAX_DISPLAY_LIMIT}</strong> most critical findings are displayed below.</p>
                    <hr>
                    <p class="mb-0">Please download the <strong>CSV</strong> or <strong>JSON</strong> report for the complete dataset.</p>
                 </div>
                 """)
                 
            report.write('<div class="accordion" id="vulnAccordion">')
            
            for index, v in enumerate(display_vulnerabilities):
                sev = v.get("severity", "Low")
                badge_class = "badge-low"
                if sev == "Critical": badge_class = "badge-critical"
                elif sev == "High": badge_class = "badge-high"
                elif sev == "Medium": badge_class = "badge-medium"

                cvss = v.get("cvss_score", "N/A")
                vector = v.get("cvss_vector", "")
                
                owasp_tag = OWASP_MAPPING.get(v['type'], "OWASP Top 10")

                report.write(f"""
                <div class="accordion-item mb-2 border">
                    <h2 class="accordion-header" id="heading{index}">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{index}">
                            <span class="badge {badge_class} me-2">{sev}</span>
                            <span class="badge bg-secondary me-3">{owasp_tag}</span>
                            <span class="fw-bold">{v['type']}</span> 
                            <span class="ms-auto text-muted small">{v.get('location', 'N/A')}</span>
                        </button>
                    </h2>
                    <div id="collapse{index}" class="accordion-collapse collapse" data-bs-parent="#vulnAccordion">
                        <div class="accordion-body bg-light">
                            <div class="row">
                                <div class="col-md-8">
                                    <p><strong>&#x1F4CD; Location:</strong> <code>{v.get('location', 'N/A')}</code></p>
                                    <p><strong>&#x1F4A3; Payload:</strong> <code>{v['payload']}</code></p>
                                    <p><strong>&#x1F441; Evidence:</strong> <code style="color: #d63031;">{v.get('evidence', 'See Payload')}</code></p>
                                    <p><strong>&#x1F4A5; Impact:</strong> {v.get('impact', 'N/A')}</p>
                                    <p><strong>&#x1F6E0; Remediation:</strong> {v['recommendation']}</p>
                                </div>
                                <div class="col-md-4 border-start">
                                    <h6>Risk Analysis</h6>
                                    <ul class="list-unstyled">
                                        <li><strong>CVSS Score:</strong> {cvss}</li>
                                        <li><strong>Vector:</strong> <small><code>{vector}</code></small></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                """)
            report.write('</div>') # End Accordion

        report.write(f"""
                    </div> <!-- End Card -->
                </div> <!-- End Content -->
            </div>

            <script>
                // Severity Chart
                const ctxSev = document.getElementById('severityChart').getContext('2d');
                new Chart(ctxSev, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{{
                            data: {js_severity_data},
                            backgroundColor: ['#d63031', '#e17055', '#fdcb6e', '#00b894']
                        }}]
                    }}
                }});

                // Type Chart
                const ctxType = document.getElementById('typeChart').getContext('2d');
                new Chart(ctxType, {{
                    type: 'bar',
                    data: {{
                        labels: {json.dumps(js_type_labels)},
                        datasets: [{{
                            label: 'Count',
                            data: {js_type_data},
                            backgroundColor: '#6c5ce7'
                        }}]
                    }},
                    options: {{
                        scales: {{ y: {{ beginAtZero: true }} }}
                    }}
                }});
            </script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """)
    
    Colors.success(f"Professional Report generated: {report_file}")
    return report_file
