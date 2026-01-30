# Web Fuzzer - Enterprise Grade Security Scanner

![Security Score A](https://img.shields.io/badge/Security_Score-A-brightgreen?style=flat-square) ![Python Version](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square) ![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

**Web Fuzzer** is a powerful, automated web vulnerability scanner designed for security professionals and developers. It helps identify critical security flaws in web applications before attackers do.

## 🚀 Features

- **Comprehensive Scanning**: Detects SQL Injection, XSS, SSRF, IDOR, Misconfigurations, and more.
- **Intelligent Analysis**: Calculates a "Security Grade" (A-F) based on findings.
- **Professional Reporting**: Generates interactive HTML, JSON, and CSV reports.
- **Top Vulnerable Endpoints**: Automatically identifies the most critical areas of your application.
- **Remediation Guides**: Provides developer-friendly code fixes for every vulnerability found.
- **Parallel Processing**: Multi-threaded architecture for fast and efficient scanning.

## 🛠️ Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/web-fuzzer.git
    cd Web_Fuzzer-main
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## ⚡ Usage

Run the scanner against a target URL:

```bash
python main.py https://example.com
```

### Options

The scanner is designed to be interactive and easy to use. Simply provide the URL, and let the tool do the heavy lifting.

## 📊 Reports

After a scan is complete, reports are automatically generated in the root directory:

-   `report.html`: Interactive dashboard with graphs and detailed findings.
-   `report.json`: Machine-readable format for integration with other tools.
-   `report.csv`: Spreadsheet-friendly format for auditing.

## 🛡️ Vulnerability Coverage

-   **Injection**: SQLi, Command Injection
-   **Auth**: Broken Authentication, Weak Passwords
-   **Web**: XSS (Reflected/Stored), CSRF
-   **Server**: SSRF, Directory Traversal, Insecure File Uploads
-   **Config**: Security Misconfigurations, Exposed Sensitive Data, IDOR

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.

---
*Disclaimer: This tool is for educational and authorized testing purposes only. Usage against targets without prior mutual consent is illegal.*
