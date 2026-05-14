# APIHawk 🦅

> Fast async API & GraphQL vulnerability scanner built for bug bounty hunters and penetration testers.

---

## What it does

APIHawk automates the recon and vulnerability discovery phase for REST APIs and GraphQL endpoints. Instead of manually poking at every path with Burp Suite or waiting for gobuster to finish, APIHawk hits hundreds of endpoints in seconds using async requests — and goes deeper by scraping JS bundles to find backend URLs and secrets that other scanners miss.

---

## Features

- **JS Scraper** — fetches all JS bundles from the target, extracts API endpoints, backend URLs, and scans for hardcoded secrets (API keys, tokens, AWS keys, DB URIs)
- **SPA False Positive Filter** — fingerprints the catch-all 200 response (common in React/Vue/Angular apps) and automatically filters fake results
- **Async Endpoint Fuzzing** — probes 100+ common API and GraphQL paths concurrently
- **POST Mode Probing** — retries 405 endpoints with POST requests to catch auth and data endpoints
- **GraphQL Checks** — detects introspection enabled, verbose error leakage
- **CORS Misconfiguration Detection** — catches wildcard CORS and credential-allowing reflected origins
- **Security Header Audit** — checks for missing `X-Content-Type-Options`, `X-Frame-Options`, `HSTS`
- **Technology Fingerprinting** — detects server, framework, CDN, WAF, runtime from response headers and cookies
- **WAF Evasion Mode** — rotates user agents, randomizes headers, jitters requests, probes URL-encoded path variants

---

## Installation

```bash
git clone https://github.com/Prajwol6/ApiHawk.git
cd ApiHawk
pip install aiohttp brotli --break-system-packages
```

---

## Usage

```bash
# Basic scan
python Apihawk.py -u https://target.com

# Full scan with verbose output
python Apihawk.py -u https://target.com -v

# JS scraper only (fast recon — finds backend URLs)
python Apihawk.py -u https://target.com --js-only

# WAF evasion mode
python Apihawk.py -u https://target.com --waf-evasion

# Higher timeout for slow servers
python Apihawk.py -u https://target.com -t 30

# All options combined
python Apihawk.py -u https://target.com -t 30 -c 100 --waf-evasion -v
```

## Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL (required) |
| `-t` | Request timeout in seconds (default: 8) |
| `-c` | Concurrent workers (default: 50) |
| `-v` | Verbose — show 404s, timeouts, SPA filtered results |
| `--js-only` | Only run JS scraper, skip endpoint fuzzing |
| `--waf-evasion` | Enable WAF evasion techniques |

---

## Example Output

```
  APIHawk | API & GraphQL Vulnerability Scanner
  For authorized targets only

[*] Phase 0: Scraping JS files for endpoints and secrets...
[*] Found 2 JS file(s)
[*] Scraping https://target.com/static/js/main.4f28f604.js (169KB)
[+] External URLs found (possible backends):
         https://api.target-backend.onrender.com/api/analyze
[+] No hardcoded secrets detected in JS files

[!] SPA catch-all detected (size=385 bytes, hash=f1aedd97)
[!] Responses matching this fingerprint will be marked as false positives

[*] Phase 1: Discovering API endpoints (102 paths)...
[+] [200] https://api.target-backend.onrender.com/api/v1  (1243 bytes)
[!] [401] https://api.target-backend.onrender.com/api/admin  (Auth required — endpoint exists)

[*] Phase 4: Fingerprinting target + checking CORS / security headers...
[+] Target fingerprint:
         Server     : cloudflare
         Framework  : Express
         CDN/WAF    : Cloudflare
         Runtime    : Node.js

[VULN] CORS Misconfiguration
       URL      : https://api.target-backend.onrender.com/api/v1
       Severity : HIGH
       Impact   : Cross-origin credential theft possible
```

---

## What it finds

| Vulnerability | Severity |
|---------------|----------|
| GraphQL Introspection Enabled | HIGH |
| CORS Misconfiguration | HIGH |
| Hardcoded Secrets in JS | HIGH |
| GraphQL Verbose Errors | MEDIUM |
| Missing Security Headers | LOW |

---

## Legal Disclaimer

**Only use APIHawk on targets you own or have explicit written permission to test.**

Unauthorized scanning is illegal. This tool is intended for:
- Your own applications
- Authorized penetration testing engagements
- Bug bounty programs where automated scanning is permitted

The author is not responsible for any misuse of this tool.

---

