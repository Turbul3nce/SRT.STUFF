# Vulnerability Categories and Payouts

## Authentication/Session Management
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| 2FA Authentication Bypass                      | $500       | $500       |
| Account Enumeration                            | $150       | $150       |
| Cookie-related Flaws                           | $100       | $100       |
| Credential/Session Prediction                  | $700       | $700       |
| Default Credentials Admin                      | $700       | $700       |
| Default Credentials Non-Admin                  | $250       | $250       |
| Email/Password Recovery Flaw                   | $800       | $800       |
| Login Authentication Bypass                   | $850       | $850       |
| SSO Authentication Bypass                     | $750       | $750       |
| Session Fixation                               | $100       | $100       |
| Step-Up Authentication Bypass                 | $100       | $750       |

## Access Control Violations
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Non-Admin Functions (Read Only)               | $300       | $300       |
| Non-Admin Functions (Read/Write or Write Only)| $450       | $450       |
| Admin Functions (Read Only)                   | $600       | $600       |
| Admin Functions (Read/Write or Write Only)    | $800       | $800       |

## Authorization/Permissions
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| File Inclusion (No execution)                 | $850       | $850       |
| Insecure Direct Object Reference (Read Only)  | $500       | $500       |
| Insecure Direct Object Reference (Read/Write) | $600       | $600       |
| Path Traversal                                | $850       | $850       |
| SSRF (Full)                                   | $1500      | $1500      |
| SSRF (Limited)                                | $500       | $500       |

## Brute Force
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Bypass of Lack of Rate Limiting Protections    | $200       | $200       |
| Lack of Rate Limiting Protections             | $100       | $100       |
| Admin Login Credentials                       | $700       | $700       |
| User Login Credentials                        | $250       | $250       |

## Cloud Security
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| AWS Security Compliance                       | $450       | $450       |

## Content Injection
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| CSS Injection                                 | $330       | $330       |
| HTTP Parameter Pollution                      | $100       | $250       |
| HTTP Response Splitting (CRLF Injection)     | $300       | $300       |
| JSON Injection                               | $300       | $600       |
| LDAP Injection                               | $475       | $475       |
| ORM Injection                                | $300       | $600       |
| Server-Side Includes Injection (SSI)        | $300       | $600       |
| Spoof HTML Content                           | $200       | $200       |
| XXE (Full)                                   | $1500      | $1500      |
| XXE (Limited)                                | $500       | $500       |
| XPath/XQuery Injection                       | $2000      | $2000      |

## Cross-Site Scripting (XSS)
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Blind XSS                                     | $880       | $880       |
| Cross-Site Scripting Inclusion (XSSI)        | $330       | $330       |
| DOM-based XSS                                | $775       | $775       |
| Persistent XSS                               | $880       | $880       |
| Reflected XSS                                | $330       | $330       |
| Reflected-DOM XSS                            | $500       | $500       |

## Cross-Site Request Forgery (CSRF)
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| High Impact                                   | $400       | $400       |
| Low Impact                                    | $225       | $225       |

## Cryptography
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Cryptography Implementation Flaw             | $150       | $150       |
| Encrypted Information Compromised            | $1400      | $1400      |
| Weak Ciphers Used for Encryption             | $300       | $300       |

## Denial-of-Service (DoS)
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| DoS against a specific server service         | $500       | $500       |
| DoS against a specific user                   | $250       | $750       |

## Dependency Confusion
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Dependency Confusion                          | $750       | $1000      |

## Functional/Business Logic
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Client Side Validation                        | $125       | $125       |
| Functionality Abuse with Malicious Impact     | $200       | $200       |
| Improper Input Validation                     | $125       | $125       |
| Insecure Deserialization                      | $375       | $375       |
| Unrestricted File Upload (No Execution)       | $180       | $180       |
| Unvalidated Redirect Bypass                   | $150       | $150       |
| Unvalidated Redirects                         | $150       | $150       |

## Information Disclosure
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Directory Contents Disclosed                  | $150       | $150       |
| Directory Structure Enumeration               | $170       | $170       |
| Identity of Network Topology                  | $150       | $150       |
| Identity of Software Architecture             | $150       | $150       |
| Leaked Credentials (High Privilege)           | $700       | $700       |
| Leaked Credentials (Low Privilege)            | $250       | $250       |
| Sensitive API Keys                            | $500       | $500       |
| Sensitive Client Information Disclosed        | $300       | $300       |
| Sensitive Directory/File Contents Disclosed   | $300       | $300       |
| Sensitive Information Leak to Third-Parties   | $200       | $200       |
| Sensitive Source Code                         | $150       | $150       |
| Service Version Disclosed                     | $100       | $100       |
| Software Version Disclosed                    | $100       | $100       |

## Remote Code Execution (RCE)
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Remote Code Execution                         | $3000      | $3000      |

## SQL Injection (SQLi)
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| SQL Injection (Full)                          | $3000      | $3000      |
| SQL Injection (Partial)                       | $1500      | $1500      |

## Server/Application Misconfiguration
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Application Level Protection                  | $200       | $200       |
| Cache Directives                              | $100       | $100       |
| Cache Poisoning                               | $300       | $300       |
| Cross-Origin Resource Sharing (CORS)         | $700       | $700       |
| DNS Misconfiguration                          | $350       | $350       |
| External Service Interaction                  | $250       | $500       |
| HTTP Request/Response Smuggling               | $300       | $300       |
| Host Level Protection                         | $375       | $375       |
| Improper Filesystem Permissions               | $175       | $175       |
| Insecure Data Storage                         | $375       | $375       |
| Open Mail Relay                               | $0         | $400       |
| Root/Jailbreak Detection Bypass               | $200       | $200       |
| SSL Pinning Bypass                            | $100       | $100       |
| Security HTTP Headers                         | $100       | $500       |
| DNS Zone/Subdomain Takeover                   | $0         | $1000      |
| UI Redressing/Clickjacking                    | $100       | $100       |
| Unclaimed Domain in Use                       | $150       | $150       |
| Using Known Vulnerable Software               | $175       | $175       |

## Other
| Vulnerability Type                              | Min Payout | Max Payout |
|------------------------------------------------|------------|------------|
| Other                                         | TBD        | TBD        |
