# Vulnerability Categories and Criteria

## Access Control
### Overview:
- Situations where a user gains unauthorized access to features or data.
- Clearly declare attacker(s) and victim(s) with their roles and credentials.

### Requirements:
- How a lower-privileged role accessed a higher-privileged role’s feature.
- Explanation of tenant/group isolation issues (e.g., cross-tenant data access).
- Justify why this is an access control issue.

### Low-Impact Examples:
- Read-only access to non-sensitive data or interfaces.
- Write access to low-impact data that doesn’t affect other users.

---

## IDOR (Insecure Direct Object Reference)
### Overview:
- Occurs when an application exposes internal object references, allowing attackers to access unauthorized data.

### Requirements:
- Clearly explain why this is an IDOR vulnerability.
- Provide sufficient context for understanding the access issue.
- Demonstrate how object references are guessed or discovered (e.g., enumeration).

### Note:
- Complex identifiers (e.g., UUIDs) require proof of discoverability or they will be considered low impact.

---

## Default/Leaked Credentials
### Applicable Categories:
- Default Credentials - Admin/Non-Admin/Limited Risk.
- Leaked Credentials (High/Low Privilege).

### Scope:
- Credentials must work on in-scope assets or originate from them (e.g., third-party credentials exposed in scope).

### Disclosure Requirements:
1. Source of credentials (e.g., misconfigured server, public breach data).
2. Impact of the credentials (e.g., sensitive data access or critical system compromise).
3. Fix recommendations.

### Not Accepted:
- Credentials unrelated to in-scope assets or test accounts with no real-world impact.

---

## Unrestricted File Upload
### Minimum Criteria:
- The ability to upload disallowed file types capable of execution (e.g., `.php`, `.exe`).
- Files must be downloadable, accessible, and unmodified after upload.

---

## Referrer Header Token Leak
### Minimum Criteria:
- Sensitive tokens leaked in `Referer` headers to qualifying third-party domains.
- High-risk domains include little-known or unclaimed domains—not popular services like social media or analytics.

---

## Reflected XSS
### Definition:
- Occurs when user input is reflected in the immediate server response in an unsafe way.

### Minimum Criteria:
1. Demonstrate DOM access (e.g., `alert(document.domain)`).
2. Payload must be deliverable to a victim (e.g., via CSRF PoC or crafted link).
3. Defacement-only PoCs or unlikely user actions (e.g., key combinations) are not acceptable.

---

## Persistent XSS
### Minimum Criteria:
- Access to the DOM must be demonstrated (e.g., `alert(document.domain)`).
- The payload must be deliverable to a victim (e.g., stored data executed in another user’s session).

---

## DOM-Based XSS (DOM-XSS)
### Definition:
- Triggered when client-side scripts process attacker-controlled data in unsafe ways.

### Minimum Criteria:
- Demonstrate access to the DOM or critical client-side data.
- Highlight specific vulnerable code paths and sinks (e.g., `eval()`, `innerHTML`).

---

## Reflected-DOM XSS (RDOM-XSS)
### Definition:
- Occurs when reflected data is processed unsafely in the DOM via client-side scripts.

### Requirements:
- Isolate the vulnerable code path and demonstrate arbitrary JavaScript execution.
- Provide PoC showing access to critical objects (e.g., `document.cookie`).

---

## Blind XSS
### Evidence Requirements:
1. **DOM Evidence:** Show where the payload exists in the DOM pre-execution.
2. **Proof of Execution:** Logs or collected data from payload execution.
3. **Request-Response Context:** Highlight where the payload was injected and rendered.

### Tools:
- Use Burp Collaborator, Synack C2, or XSS Hunter for monitoring and evidence collection.

---

## CSRF (Cross-Site Request Forgery)
### Low-Impact:
- Changes limited to integrity (e.g., profile updates, basic info edits).

### High-Impact:
- Significant impacts on confidentiality or integrity (e.g., account takeover via email change, PII changes).

### Note:
- PoC must demonstrate cross-user impacts without high complexity (e.g., UUID enumeration).

---

## CORS (Cross-Origin Resource Sharing)
### Minimum Criteria:
- Provide a working PoC showing that sensitive data can be accessed from a malicious domain.
- Demonstrate misconfigurations allowing unauthorized origins to access data.

---

## SSRF (Server-Side Request Forgery)
### Partial SSRF:
- Host/port scans or file existence checks demonstrated via error messages or response times.

### Full SSRF:
- Data exfiltration (e.g., AWS metadata).
- Retrieving sensitive files or NTLM hashes.
- Impact beyond basic requests (e.g., authentication to attacker-controlled SMB).

---

## XXE (XML External Entity)
### Minimum Criteria:
- HTTP requests and payloads showing interaction.
- Screenshots or logs proving sensitive file access or other impacts.

---

## SQL Injection (SQLi)
### Full SQLi:
- Extract sensitive data from outside the current table.

### Partial SQLi:
- Retrieve metadata (e.g., table names, columns).
- Demonstrate successful delay-based payloads (e.g., `SLEEP()`).

---

## Remote Code Execution (RCE)
### Criteria:
- Provide proof of command execution (e.g., `ls`, `ping`).
- Demonstrate multiple commands where possible (e.g., DNS callbacks with environment variables).

---

## Known Vulnerable Software
### Criteria:
- Exploit must demonstrate RCE or show critical risk (e.g., crashes, admin lockouts).
- Scans must prove high-confidence exploitability.

---

## Mobile Vulnerabilities
### Examples:
- StrandHogg vulnerability (1 report per target).
- Exported activities with sensitive data.
- Hardcoded sensitive information (e.g., API keys).
- Root/jailbreak detection bypass.

---

## HTML Injection (HTMLi)
### Criteria:
- Demonstrate realistic attack scenarios (e.g., phishing, spoofed application content).
- PoCs must appear as legitimate client functionality.

---

## Notes for Testing
- Ensure responsible testing (e.g., avoid SQLi or RCE impacts on live data).
- For API keys, demonstrate measurable impact and ensure they are directly linked to in-scope assets.
- Always verify scope and adhere to rules of engagement.

---

- **Testing Scope:** Always verify scope and adhere to rules of engagement.

---

For more information, please reference the official Synack guidelines or PortSwigger's documentation.
