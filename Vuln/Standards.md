# Vulnerability Categories and Criteria

## Access Control
### Criteria:
- Situations where a user can access features/data they are not authorized for.
- **Attacker:** Role + credentials (e.g., Read-only User + ROU: P@ssW0rd).
- **Victim:** Role + credentials (e.g., Admin User + ADM: P@ssW0rd).

### Examples of Low-Impact Violations:
- Read-only access to non-sensitive data or interfaces.
- Write access to low-impact data.

---

## IDOR (Insecure Direct Object Reference)
### Criteria:
- Exposure of internal implementation objects.
- **Attacker:** Role + credentials.
- **Victim:** Role + credentials.

### Requirements:
- Clearly describe why it’s an IDOR issue.
- Demonstrate how identifiers can be guessed or discovered.

---

## Default/Leaked Credentials
### Applicable Categories:
- **Default Credentials - Admin/Non-Admin/Limited Risk.**
- **Leaked Credentials (High/Low Privilege).**

### Criteria:
- Credentials must work on in-scope assets.
- Provide proof of impact and secure handling during testing.

### Not Accepted:
- Self-registered accounts unless exceptions apply (e.g., high-impact accounts).

---

## Unrestricted File Upload
### Criteria:
- Uploading disallowed file types capable of execution (e.g., `.php`, `.exe`).
- Files must be downloadable and unmodified after upload.

---

## Referrer Header Token Leak
### Criteria:
- Tokens leaked in `Referer` headers to third-party domains.
- High bar for approval—third parties must pose significant risk.

---

## Reflected XSS
### Criteria:
- Must demonstrate access to the DOM (e.g., `alert(document.domain)`).
- Payload must be deliverable to a victim (e.g., CSRF PoC, crafted link).

### Not Accepted:
- Defacement-only PoCs or unlikely user actions (e.g., pressing unusual key combinations).

---

## Persistent XSS
### Criteria:
- Must demonstrate DOM access.
- Payload must be deliverable to a victim.

---

## DOM-Based XSS (DOM-XSS)
### Criteria:
- Execution due to DOM manipulation without server-side reflection.
- Demonstrate arbitrary JavaScript execution and vulnerable code paths.

---

## Reflected-DOM XSS (RDOM-XSS)
### Criteria:
- Data reflected into DOM sinks via client-side scripts.
- Proof of arbitrary JavaScript execution is required.

---

## Blind XSS
### Evidence Requirements:
- DOM evidence of payload location.
- Proof of execution (e.g., logs, HTTP requests).
- Use of tools like Burp Collaborator or Synack C2 for evidence.

---

## CSRF (Cross-Site Request Forgery)
### Low Impact:
- Integrity-only changes (e.g., profile updates, basic info changes).

### High Impact:
- Significant confidentiality impacts (e.g., email changes, account takeovers).

---

## CORS (Cross-Origin Resource Sharing)
### Criteria:
- Demonstrate access to sensitive data due to misconfiguration.
- Provide a working HTML PoC.

---

## SSRF (Server-Side Request Forgery)
### Partial SSRF:
- Host/port scans or file existence checks.

### Full SSRF:
- Data exfiltration (e.g., AWS metadata, NTLM hashes).
- Internal file retrieval or sensitive resource exposure.

---

## XXE (XML External Entity)
### Criteria:
- HTTP requests showing payloads sent.
- Proof of file access or sensitive data extraction.

---

## SQL Injection (SQLi)
### Full SQLi:
- Extract data from outside the current table.

### Partial SQLi:
- Extract metadata (e.g., table names, database info).
- Demonstrate successful sleep/delay commands.

---

## Remote Code Execution (RCE)
### Criteria:
- Provide proof of command execution (e.g., `ping`, `ls`, `dir`).
- Avoid modifying sensitive files or disrupting services.

---

## Known Vulnerable Software
### Criteria:
- Demonstrate full exploitation or show proof of severe risk (e.g., RCE potential).

---

## Mobile
### Accepted Submissions:
- Exploiting exported activities or misconfigured protocol schemes.
- Hardcoded sensitive data (e.g., API keys).
- Root/jailbreak/emulator detection bypasses.

---

## HTML Injection (HTMLi)
### Criteria:
- Must demonstrate a realistic attack scenario (e.g., phishing, spoofing application content).

---

## Additional Notes
- **Destructive Testing:** Ensure responsible testing, especially for SQLi and RCE.
- **API Keys:** Must demonstrate measurable impact and clear connection to in-scope assets.
- **Testing Scope:** Always verify scope and adhere to rules of engagement.

---

For more information, please reference the official Synack guidelines or PortSwigger's documentation.
