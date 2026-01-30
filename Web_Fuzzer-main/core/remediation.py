
class RemediationLibrary:
    def __init__(self):
        self.fixes = {
            "SQL Injection": {
                "desc": "SQL Injection occurs when untrusted user input is directly concatenated into a database query.",
                "secure_code": """
# PHP (PDO) - Recommended
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
$stmt->execute(['email' => $userInput]);
$user = $stmt->fetch();

# Python (Flask/SQLAlchemy)
user = User.query.filter_by(email=user_input).first()

# Java (Prepared Statement)
String query = "SELECT * FROM users WHERE email = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userInput);
ResultSet results = pstmt.executeQuery();
""",
                "tips": [
                    "Use Prepared Statements (Parameterized Queries) for ALL database access.",
                    "Use Object Relational Mappers (ORMs) like Eloquent, Hibernate, or SQLAlchemy.",
                    "Validate and sanitize input (e.g., ensure IDs are integers)."
                ]
            },
            "Cross-Site Scripting (XSS)": {
                "desc": "XSS happens when the application includes untrusted data in a web page without proper validation or escaping.",
                "secure_code": """
<!-- HTML Context (General) -->
<!-- Output Encoding converts special characters into their HTML entities -->
<div>{{ user_input | e }}</div>  <!-- Jinja2 (Python) -->
<div><?= htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8') ?></div> <!-- PHP -->
<div>{userInput}</div> <!-- React (Auto-escapes by default) -->

<!-- JavaScript Context -->
<script>
    // NEVER put untrusted data directly here. 
    // Use JSON.stringify() with proper escaping if needed.
    var data = JSON.parse('{{ data | tojson }}'); 
</script>
""",
                "tips": [
                    "Context-sensitive output encoding is the primary defense.",
                    "Implement Content Security Policy (CSP) headers.",
                    "Use modern frameworks (React, Vue, Angular) which handle escaping automatically."
                ]
            },
            "Broken Authentication": {
                "desc": "Weak usage of session IDs or credentials allows attackers to impersonate users.",
                "secure_code": """
# Password Storage (Python)
import bcrypt

# Hashing a password
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Verifying
if bcrypt.checkpw(user_input.encode('utf-8'), hashed):
    login_user(user)

# Session Management
# - Set 'Secure' and 'HttpOnly' flags on cookies.
# - Set strict session timeouts.
""",
                "tips": [
                    "Never store passwords in plain text. Use Argon2 or Bcrypt.",
                    "Implement Multi-Factor Authentication (MFA).",
                    "Rate limit login attempts to prevent brute force."
                ]
            },
            "Sensitive Data Exposure": {
                "desc": "Exposure of sensitive information like keys, passwords, or PII.",
                "secure_code": r"""
# 1. Disable Directory Listing (Apache .htaccess)
Options -Indexes

# 2. Deny Access to Sensitive Files (Nginx)
location ~ /\.(env|git|htaccess) {
    deny all;
}

# 3. Environment Variables (Python)
import os
secret_key = os.environ.get('SECRET_KEY') # Never hardcode secrets!
""",
                "tips": [
                    "Encrypt data at rest and in transit (HTTPS).",
                    "Ensure .git, .env, and backup files are not accessible via web.",
                    "Use generic error messages to avoid leaking implementation details."
                ]
            },
             "Security Misconfiguration": {
                "desc": "Insecure default settings, incomplete computations, or open cloud storage.",
                "secure_code": """
# HTTP Security Headers (Nginx)
add_header X-Frame-Options "SAMEORIGIN";
add_header X-XSS-Protection "1; mode=block";
add_header X-Content-Type-Options "nosniff";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self';";
""",
                "tips": [
                    "Remove default accounts and sample pages.",
                    "Keep all software libraries and OS patched.",
                    "Automate configuration verification."
                ]
            },
            "IDOR": {
                "desc": "Access control failure where users can access resources belonging to others by changing IDs.",
                "secure_code": """
# Python (Logic Check)
@app.route('/document/<doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get(doc_id)
    
    # CRITICAL: Verify Ownership!
    if doc.owner_id != current_user.id:
        abort(403) # Forbidden
        
    return render_template('doc.html', doc=doc)
""",
                "tips": [
                    "Never rely on the ID parameter alone found in the URL.",
                    "Always check if the 'current_user' has permission to access the requested object ID.",
                    "Use indirect references (e.g., random GUIDs or session maps) instead of database IDs."
                ]
            },
            "Command Injection": {
                "desc": "Attackers can execute arbitrary operating system commands via vulnerable inputs.",
                "secure_code": """
# Python (subprocess)
import subprocess

# VULNERABLE:
# os.system("ping " + user_input)

# SECURE:
# Use a list of arguments. This prevents shell expansion.
subprocess.run(["ping", "-c", "1", user_input])
""",
                "tips": [
                    "Avoid calling OS commands directly if possible.",
                    "Use parameterized APIs (e.g., subprocess.run with a list).",
                    "Validate inputs against a strict whitelist."
                ]
            },
            "Directory Traversal": {
                "desc": "Attackers can access restricted files by using '../' sequences.",
                "secure_code": """
# Python
import os

filename = user_input
base_dir = '/var/www/images/'
abs_path = os.path.abspath(os.path.join(base_dir, filename))

if not abs_path.startswith(base_dir):
    raise PermissionError("Access Denied")

# Safe to open
with open(abs_path) as f:
    ...
""",
                "tips": [
                    "Validate that the resolved path starts with the expected base directory.",
                    "Use simple alphanumeric filenames where possible.",
                    "Disable directory listing."
                ]
            },
            "Insecure File Upload": {
                "desc": "Uploading dangerous files (like .php shells) can compromise the server.",
                "secure_code": """
# Python (Flask)
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \\
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    # Generate a random name to prevent overwrites/execution
    save_path = os.path.join(UPLOAD_FOLDER, uuid.uuid4().hex + ".png")
    file.save(save_path)
""",
                "tips": [
                    "Whitelist allowed file extensions and MIME types.",
                    "Rename uploaded files to random strings.",
                    "Store uploads outside the web root."
                ]
            },
            "CSRF": {
                "desc": "Forces an end user to execute unwanted actions on a web application.",
                "secure_code": """
<!-- Add CSRF Token to Forms -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>

# Backend (Flask-WTF does this automatically)
""",
                "tips": [
                    "Use Anti-CSRF tokens for all state-changing requests (POST, PUT, DELETE).",
                    "Use SameSite cookie attribute (Strict or Lax).",
                    "Require re-authentication for sensitive actions."
                ]
            },
            "SSRF": {
                "desc": "Server-Side Request Forgery allows attackers to induce the server to make HTTP requests.",
                "secure_code": """
# Python
import ipaddress
from urllib.parse import urlparse

def validate_url(url):
    parsed = urlparse(url)
    ip = ipaddress.ip_address(parsed.hostname)
    
    # Deny private ranges (127.0.0.1, 10.x, 192.168.x, etc.)
    if ip.is_private:
        raise ValueError("Private IPs not allowed")
    
    return url
""",
                "tips": [
                    "Validate and sanitize all user-supplied URLs.",
                    "Deny requests to private IP ranges (localhost, 10.0.0.0/8, etc.).",
                    "Run the service in an isolated network environment."
                ]
            },
            "Rate Limiting": {
                 "desc": "Lack of rate limiting allows brute force attacks.",
                 "secure_code": """
# Nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

server {
    location /login {
        limit_req zone=mylimit burst=20 nodelay;
        ...
    }
}
""",
                "tips": [
                    "Implement rate limiting on all login and intensive endpoints.",
                    "Use CAPTCHAs to prevent automated abuse.",
                    "Monitor for abnormal traffic spikes."
                ]
            }
        }

    def get_fix(self, vulnerability_type, context=None):
        fix = self.fixes.get(vulnerability_type, {
            "desc": "Standard vulnerability optimization required.",
            "secure_code": "# Refer to OWASP Cheat Sheets for remediation.",
            "tips": ["Validate all inputs.", "Follow least privilege context."]
        }).copy()
        
        # Dynamic Substitution
        if context:
            param = context.get("parameter", "user_input")
            if param == "Generic" or not param: param = "user_input"
            
            # Simple string replacement for a "Generated" feel
            code = fix["secure_code"]
            code = code.replace("user_input", param)
            code = code.replace("userInput", param)
            code = code.replace("email", param) # Heuristic replacement for SQLi example
            fix["secure_code"] = code
            
        return fix
