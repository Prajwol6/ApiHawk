#!/usr/bin/env python3
"""
APIHawk - Fast Async API & GraphQL Vulnerability Scanner
Usage: python apihawk.py -u https://target.com [options]
"""

import asyncio
import argparse
import json
import random
import re
import sys
import time
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    from yarl import URL
except ImportError:
    print("[!] Missing dependency: pip install aiohttp")
    sys.exit(1)

# ─── Color Output ─────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):    print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def bad(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def info(msg):  print(f"{C.CYAN}[*]{C.RESET} {msg}")

# ─── Wordlists ─────────────────────────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/graphql/v2",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query",
    "/gql", "/api/gql", "/graphiql", "/playground",
    "/altair", "/graphql-explorer", "/api/graphql/v1",
    "/graphql/console", "/graphql/playground",
]

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/service", "/services",
    "/api/v1/login", "/api/v1/register", "/api/auth/login",
    "/api/auth/register", "/api/auth/token", "/api/auth/refresh",
    "/api/v1/auth", "/api/v2/auth", "/auth/token", "/oauth/token",
    "/api/token", "/api/login", "/login", "/signup",
    "/api/v1/users", "/api/v2/users", "/api/users",
    "/api/v1/user", "/api/v2/user", "/api/user",
    "/api/v1/me", "/api/v2/me", "/api/me",
    "/api/v1/profile", "/api/v2/profile", "/api/profile",
    "/api/v1/account", "/api/v2/account", "/api/account",
    "/api/v1/accounts", "/api/v2/accounts",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/admin/api", "/admin", "/api/dashboard",
    "/api/v1/admin/users", "/api/v2/admin/users",
    "/api/internal", "/internal/api",
    "/api/v1/config", "/api/config", "/api/settings",
    "/api/v1/data", "/api/v2/data", "/api/data",
    "/api/v1/export", "/api/export", "/api/v1/import",
    "/api/v1/search", "/api/search",
    "/api/v1/upload", "/api/upload",
    "/api/debug", "/api/test", "/api/dev",
    "/api/v1/debug", "/api/swagger", "/swagger",
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/openapi.yaml", "/api-docs", "/api/docs",
    "/docs", "/redoc", "/.well-known",
    "/api/health", "/health", "/ping", "/status",
    "/api/status", "/api/v1/status", "/metrics",
    "/api/v1/products", "/api/v1/orders", "/api/v1/payments",
    "/api/v1/transactions", "/api/v1/notifications",
    "/api/v1/messages", "/api/v1/comments",
    "/api/v1/posts", "/api/v1/files",
    "/api/v1/keys", "/api/v1/tokens",
    "/api/v1/webhooks", "/api/v1/integrations",
    "/api/analyze",
]

# ─── JS Scraper Patterns ───────────────────────────────────────────────────────

# Finds API paths inside JS bundles
JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-\.]+)["\']',
    r'["\']([a-zA-Z0-9/_\-\.]*graphql[a-zA-Z0-9/_\-\.]*)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'BASE_URL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'API_URL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]*',
]

# Finds sensitive strings leaked in JS
JS_SECRET_PATTERNS = [
    (r'["\']?api[_\-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']',       "API Key"),
    (r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']',              "Secret"),
    (r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]{20,})["\']',             "Token"),
    (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',                     "Password"),
    (r'["\']?auth["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_\.]{20,})["\']',              "Auth value"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                    "Google API Key"),
    (r'sk-[a-zA-Z0-9]{32,}',                                                       "OpenAI Key"),
    (r'ghp_[a-zA-Z0-9]{36}',                                                       "GitHub Token"),
    (r'AKIA[0-9A-Z]{16}',                                                          "AWS Access Key"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',                                    "Private Key"),
    (r'mongodb(\+srv)?://[^\s"\']+',                                               "MongoDB URI"),
    (r'postgres://[^\s"\']+',                                                      "Postgres URI"),
    (r'mysql://[^\s"\']+',                                                         "MySQL URI"),
]

# ─── WAF Evasion ───────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.69",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:120.0) Gecko/20100101 Firefox/120.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-US,en;q=0.9,es;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.linkedin.com/",
    None,
]


def random_ip():
    """Generate a plausible public-looking IPv4 for X-Forwarded-For."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def evasion_headers(waf_evasion, extra=None):
    """Build per-request headers. With waf_evasion on, rotate UA, language, encoding, referer, X-Forwarded-For."""
    if waf_evasion:
        h = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
            "X-Forwarded-For": random_ip(),
        }
        ref = random.choice(REFERERS)
        if ref:
            h["Referer"] = ref
    else:
        h = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, */*",
        }
    if extra:
        h.update(extra)
    return h


async def evasion_delay(delay, waf_evasion):
    """Sleep before a request. Fixed --delay wins; otherwise WAF mode adds random jitter."""
    if delay > 0:
        await asyncio.sleep(delay)
    elif waf_evasion:
        await asyncio.sleep(random.uniform(0.5, 2.0))


def encoded_path_variants(paths):
    """For paths with >=2 segments, produce a variant with inner slashes percent-encoded as %2F."""
    variants = []
    seen = set(paths)
    for p in paths:
        if p.count("/") >= 2:
            v = "/" + p.lstrip("/").replace("/", "%2F")
            if v not in seen and v != p:
                variants.append(v)
                seen.add(v)
    return variants


# ─── GraphQL Introspection Query ───────────────────────────────────────────────

INTROSPECTION_QUERY = {
    "query": """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name }
        }
      }
    }
    """
}

# ─── JS Scraper ────────────────────────────────────────────────────────────────

class JSScraper:
    def __init__(self, target, session, waf_evasion=False, delay=0):
        self.target   = target.rstrip("/")
        self.session  = session
        self.waf_evasion = waf_evasion
        self.delay    = delay
        self.js_files = []
        self.endpoints_found = set()
        self.secrets_found   = []
        self.external_urls   = set()

    async def fetch_html(self):
        """Fetch homepage and find all JS file references."""
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with self.session.get(self.target, ssl=False,
                                         headers=evasion_headers(self.waf_evasion)) as r:
                html = await r.text()
                # Find all .js files referenced
                js_refs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
                for ref in js_refs:
                    if ref.startswith("http"):
                        self.js_files.append(ref)
                    else:
                        self.js_files.append(urljoin(self.target, ref))
                # Also check asset-manifest.json (Create React App)
                manifest_url = urljoin(self.target, "/asset-manifest.json")
                try:
                    await evasion_delay(self.delay, self.waf_evasion)
                    async with self.session.get(manifest_url, ssl=False,
                                                 headers=evasion_headers(self.waf_evasion)) as mr:
                        if mr.status == 200:
                            manifest = await mr.json(content_type=None)
                            files = manifest.get("files", {})
                            for key, path in files.items():
                                if key.endswith(".js"):
                                    self.js_files.append(urljoin(self.target, path))
                except Exception:
                    pass
        except Exception as e:
            bad(f"Could not fetch homepage: {e}")

    async def scrape_js_file(self, js_url):
        """Download and extract endpoints + secrets from a JS file."""
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with self.session.get(js_url, ssl=False,
                                         headers=evasion_headers(self.waf_evasion)) as r:
                if r.status != 200:
                    return
                content = await r.text(errors="ignore")
                size_kb = len(content) // 1024
                info(f"Scraping {js_url} ({size_kb}KB)")

                # ── Extract API endpoints ──
                for pattern in JS_ENDPOINT_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        m = match.strip()
                        # Filter out noise
                        if len(m) < 4 or len(m) > 200:
                            continue
                        if m.startswith("http"):
                            parsed = urlparse(m)
                            # Separate external URLs (different domain = backend candidate)
                            target_host = urlparse(self.target).netloc
                            if parsed.netloc and parsed.netloc != target_host:
                                self.external_urls.add(m.split("?")[0])
                            else:
                                path = parsed.path
                                if path and path not in self.endpoints_found:
                                    self.endpoints_found.add(path)
                        elif m.startswith("/"):
                            if m not in self.endpoints_found:
                                self.endpoints_found.add(m)

                # ── Detect secrets ──
                for pattern, label in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        val = match if isinstance(match, str) else match[0]
                        # Skip obvious placeholders
                        if any(p in val.lower() for p in ["your_", "xxx", "example", "placeholder", "undefined", "process.env"]):
                            continue
                        finding = {
                            "type": label,
                            "value": val[:60] + "..." if len(val) > 60 else val,
                            "js_file": js_url
                        }
                        self.secrets_found.append(finding)
                        print(f"\n{C.RED}{C.BOLD}[SECRET] {label} found in JS!{C.RESET}")
                        print(f"         File  : {js_url}")
                        print(f"         Value : {finding['value']}\n")

        except Exception as e:
            bad(f"Failed to scrape {js_url}: {e}")

    async def run(self):
        info("Phase 0: Scraping JS files for endpoints and secrets...")
        await self.fetch_html()

        if not self.js_files:
            warn("No JS files found on homepage.")
            return

        info(f"Found {len(self.js_files)} JS file(s)")
        tasks = [self.scrape_js_file(url) for url in self.js_files]
        await asyncio.gather(*tasks)

        # Print results
        print()
        if self.endpoints_found:
            ok(f"JS Scraper found {len(self.endpoints_found)} endpoint(s):")
            for ep in sorted(self.endpoints_found):
                print(f"         {C.GREEN}{ep}{C.RESET}")

        if self.external_urls:
            print()
            ok(f"External URLs found (possible backends):")
            for url in sorted(self.external_urls):
                print(f"         {C.YELLOW}{url}{C.RESET}")

        if not self.secrets_found:
            ok("No hardcoded secrets detected in JS files")

        print()
        return {
            "js_files": self.js_files,
            "endpoints": list(self.endpoints_found),
            "external_urls": list(self.external_urls),
            "secrets": self.secrets_found
        }


# ─── Scanner Class ─────────────────────────────────────────────────────────────

class APIHawk:
    def __init__(self, target, concurrency=50, timeout=8, verbose=False, js_only=False,
                 waf_evasion=False, delay=0):
        self.target        = target.rstrip("/")
        self.concurrency   = concurrency
        self.timeout       = aiohttp.ClientTimeout(total=timeout)
        self.verbose       = verbose
        self.js_only       = js_only
        self.waf_evasion   = waf_evasion
        self.delay         = delay
        self.found_apis    = []
        self.found_graphql = []
        self.vulns         = []
        self.js_results    = {}
        self.spa_fingerprint = None  # (status, content_length, content_hash)
        self.fingerprint   = {}

    async def probe(self, session, path, semaphore):
        # encoded=True preserves %2F so WAF-evasion URL variants reach the server intact.
        url = URL(urljoin(self.target, path), encoded=True)
        async with semaphore:
            await evasion_delay(self.delay, self.waf_evasion)
            try:
                async with session.get(url, ssl=False, allow_redirects=False,
                                        headers=evasion_headers(self.waf_evasion)) as r:
                    status = r.status
                    cl = r.headers.get("Content-Length", "?")

                    if status in (200, 201, 204):
                        # Filter SPA false positives
                        if self.spa_fingerprint:
                            import hashlib
                            body = await r.read()
                            h = hashlib.md5(body).hexdigest()
                            spa_status, spa_len, spa_hash = self.spa_fingerprint
                            if h == spa_hash or len(body) == spa_len:
                                if self.verbose:
                                    bad(f"[SPA] {url}  (false positive — matches catch-all)")
                                return
                        ok(f"[{status}] {url}  ({cl} bytes)")
                        self.found_apis.append({"url": url, "status": status})
                    elif status in (301, 302, 307, 308):
                        loc = r.headers.get("Location", "")
                        warn(f"[{status}] {url}  -> {loc}")
                        self.found_apis.append({"url": url, "status": status})
                    elif status == 401:
                        warn(f"[401] {url}  (Auth required — endpoint exists)")
                        self.found_apis.append({"url": url, "status": 401})
                    elif status == 403:
                        warn(f"[403] {url}  (Forbidden — endpoint exists)")
                        self.found_apis.append({"url": url, "status": 403})
                    elif status == 405:
                        info(f"[405] {url}  (Method not allowed — try POST)")
                        self.found_apis.append({"url": url, "status": 405})
                    elif self.verbose and status == 404:
                        bad(f"[404] {url}")

            except asyncio.TimeoutError:
                if self.verbose:
                    bad(f"[TIMEOUT] {url}")
            except Exception:
                pass

    async def probe_post(self, session, url, semaphore):
        async with semaphore:
            await evasion_delay(self.delay, self.waf_evasion)
            try:
                async with session.post(
                    URL(url, encoded=True), json={}, ssl=False, allow_redirects=False,
                    headers=evasion_headers(self.waf_evasion, {"Content-Type": "application/json"})
                ) as r:
                    status = r.status
                    cl = r.headers.get("Content-Length", "?")
                    if status in (200, 201, 401, 403):
                        ok(f"[{status}] {url}  (POST {cl} bytes)")
                        self.found_apis.append({"url": url, "status": status, "method": "POST"})
            except asyncio.TimeoutError:
                if self.verbose:
                    bad(f"[TIMEOUT] POST {url}")
            except Exception:
                pass


    async def detect_spa(self, session):
        """
        Probe a guaranteed non-existent path to fingerprint the SPA fallback.
        If the server returns 200 for a random path, it's a SPA catch-all.
        We record the response size + hash to filter false positives later.
        """
        import hashlib
        test_url = urljoin(self.target, "/apihawk-test-nonexistent-path-xyz123")
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with session.get(test_url, ssl=False, allow_redirects=True,
                                    headers=evasion_headers(self.waf_evasion)) as r:
                if r.status == 200:
                    body = await r.read()
                    h = hashlib.md5(body).hexdigest()
                    self.spa_fingerprint = (r.status, len(body), h)
                    warn(f"SPA catch-all detected (size={len(body)} bytes, hash={h[:8]})")
                    warn("Responses matching this fingerprint will be marked as false positives")
        except Exception:
            pass

    async def check_graphql_introspection(self, session, url):
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with session.post(
                URL(url, encoded=True), json=INTROSPECTION_QUERY, ssl=False,
                headers=evasion_headers(self.waf_evasion, {"Content-Type": "application/json"})
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    if data.get("data", {}).get("__schema"):
                        vuln = {
                            "type": "GraphQL Introspection Enabled",
                            "severity": "HIGH",
                            "url": url,
                            "detail": "Full schema exposed. Attackers can map every query, mutation, and type."
                        }
                        self.vulns.append(vuln)
                        print(f"\n{C.RED}{C.BOLD}[VULN] GraphQL Introspection ENABLED{C.RESET}")
                        print(f"       URL      : {url}")
                        print(f"       Severity : HIGH")
                        print(f"       Impact   : Full schema exposed to attackers\n")
                        types = data["data"]["__schema"].get("types", [])
                        user_types = [t["name"] for t in types if not t["name"].startswith("__")]
                        info(f"Exposed types ({len(user_types)}): {', '.join(user_types[:15])}{'...' if len(user_types) > 15 else ''}")
                        return True
        except Exception:
            pass
        return False

    async def check_graphql_debug_mode(self, session, url):
        bad_query = {"query": "{ __typename { INVALID }"}
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with session.post(URL(url, encoded=True), json=bad_query, ssl=False,
                                     headers=evasion_headers(self.waf_evasion, {"Content-Type": "application/json"})) as r:
                text = await r.text()
                if any(kw in text.lower() for kw in ["traceback", "stack trace", "exception", "at line", "syntax error"]):
                    vuln = {
                        "type": "GraphQL Verbose Errors",
                        "severity": "MEDIUM",
                        "url": url,
                        "detail": "Server returns detailed error messages, leaking internal info."
                    }
                    self.vulns.append(vuln)
                    print(f"\n{C.YELLOW}{C.BOLD}[VULN] GraphQL Verbose Errors{C.RESET}")
                    print(f"       URL      : {url}")
                    print(f"       Severity : MEDIUM")
                    print(f"       Impact   : Stack traces / internal paths leaked\n")
        except Exception:
            pass

    async def check_missing_auth_headers(self, session, url):
        missing = []
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with session.get(URL(url, encoded=True), ssl=False,
                                    headers=evasion_headers(self.waf_evasion)) as r:
                headers = r.headers
                if "x-content-type-options" not in headers:
                    missing.append("X-Content-Type-Options")
                if "x-frame-options" not in headers:
                    missing.append("X-Frame-Options")
                if "strict-transport-security" not in headers and self.target.startswith("https"):
                    missing.append("Strict-Transport-Security")
                if missing:
                    vuln = {
                        "type": "Missing Security Headers",
                        "severity": "LOW",
                        "url": url,
                        "detail": f"Missing: {', '.join(missing)}"
                    }
                    self.vulns.append(vuln)
                    warn(f"Missing headers on {url}: {', '.join(missing)}")
        except Exception:
            pass

    async def check_cors(self, session, url):
        try:
            await evasion_delay(self.delay, self.waf_evasion)
            headers = evasion_headers(self.waf_evasion, {"Origin": "https://evil.com"})
            async with session.get(URL(url, encoded=True), headers=headers, ssl=False) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*":
                    warn(f"CORS wildcard (*) on {url}")
                elif acao == "https://evil.com":
                    if acac.lower() == "true":
                        vuln = {
                            "type": "CORS Misconfiguration",
                            "severity": "HIGH",
                            "url": url,
                            "detail": "Origin reflected + credentials allowed. Leads to credential theft."
                        }
                        self.vulns.append(vuln)
                        print(f"\n{C.RED}{C.BOLD}[VULN] CORS Misconfiguration{C.RESET}")
                        print(f"       URL      : {url}")
                        print(f"       Severity : HIGH")
                        print(f"       Impact   : Cross-origin credential theft possible\n")
        except Exception:
            pass

    async def fingerprint_target(self, session):
        """
        GET the root URL and infer server, framework, CDN/WAF, runtime, and
        framework-specific session cookies from response headers.
        """
        result = {
            "server": None,
            "framework": None,
            "cdn_waf": [],
            "runtime": None,
            "cookies": [],
        }

        try:
            await evasion_delay(self.delay, self.waf_evasion)
            async with session.get(self.target, ssl=False, allow_redirects=True,
                                    headers=evasion_headers(self.waf_evasion)) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}

                # ── Server ──
                server_hdr = headers.get("server", "")
                if server_hdr:
                    sl = server_hdr.lower()
                    for name in ("nginx", "apache", "iis", "caddy", "litespeed",
                                 "openresty", "cloudflare", "envoy", "gunicorn"):
                        if name in sl:
                            result["server"] = server_hdr
                            break
                    if not result["server"]:
                        result["server"] = server_hdr

                # ── Framework / Runtime via X-Powered-By ──
                xpb = headers.get("x-powered-by", "")
                if xpb:
                    xl = xpb.lower()
                    framework_map = {
                        "express": "Express (Node.js)",
                        "next.js": "Next.js",
                        "laravel": "Laravel (PHP)",
                        "django": "Django (Python)",
                        "rails": "Ruby on Rails",
                        "asp.net": "ASP.NET",
                        "php": "PHP",
                        "servlet": "Java Servlet",
                    }
                    for key, label in framework_map.items():
                        if key in xl:
                            result["framework"] = label
                            break
                    if not result["framework"]:
                        result["framework"] = xpb
                    if "php" in xl:
                        result["runtime"] = "PHP"
                    elif "node" in xl or "express" in xl:
                        result["runtime"] = "Node.js"
                    elif "asp.net" in xl:
                        result["runtime"] = ".NET"

                # ── Runtime via X-Runtime (Rails-ish) ──
                if not result["runtime"] and "x-runtime" in headers:
                    result["runtime"] = "Ruby (X-Runtime present)"

                # ── CDN / WAF ──
                if "cf-ray" in headers or "cf-cache-status" in headers:
                    result["cdn_waf"].append("Cloudflare")
                if "x-cache" in headers:
                    xc = headers["x-cache"].lower()
                    if "varnish" in xc:
                        result["cdn_waf"].append("Varnish")
                    else:
                        result["cdn_waf"].append(f"CDN cache ({headers['x-cache']})")
                for h in headers:
                    if h.startswith("x-amz") or h == "x-amz-cf-id":
                        if "AWS CloudFront/S3" not in result["cdn_waf"]:
                            result["cdn_waf"].append("AWS CloudFront/S3")
                        break
                for h in headers:
                    if h.startswith("x-vercel"):
                        if "Vercel" not in result["cdn_waf"]:
                            result["cdn_waf"].append("Vercel")
                        break
                if "x-fastly-request-id" in headers or "fastly-debug-digest" in headers:
                    result["cdn_waf"].append("Fastly")
                if "x-akamai-transformed" in headers or "akamai-grn" in headers:
                    result["cdn_waf"].append("Akamai")

                # ── Cookies ──
                cookie_map = {
                    "PHPSESSID": "PHP",
                    "JSESSIONID": "Java (Servlet/JSP)",
                    "laravel_session": "Laravel (PHP)",
                    "connect.sid": "Express (Node.js)",
                    "ci_session": "CodeIgniter (PHP)",
                    "ASP.NET_SessionId": "ASP.NET",
                    "_rails_session": "Ruby on Rails",
                    "django_session": "Django",
                    "sessionid": "Django (likely)",
                }
                set_cookies = r.headers.getall("Set-Cookie", []) if hasattr(r.headers, "getall") else []
                if not set_cookies and "set-cookie" in headers:
                    set_cookies = [headers["set-cookie"]]
                for cookie_line in set_cookies:
                    cookie_name = cookie_line.split("=", 1)[0].strip()
                    for known, tech in cookie_map.items():
                        if cookie_name.lower() == known.lower():
                            result["cookies"].append({"name": cookie_name, "tech": tech})
                            if not result["framework"] and tech not in ("PHP",):
                                result["framework"] = tech
                            if not result["runtime"]:
                                if "PHP" in tech:
                                    result["runtime"] = "PHP"
                                elif "Node" in tech:
                                    result["runtime"] = "Node.js"
                                elif "Java" in tech:
                                    result["runtime"] = "Java"
                                elif "Ruby" in tech:
                                    result["runtime"] = "Ruby"
                                elif "Django" in tech:
                                    result["runtime"] = "Python"
                                elif ".NET" in tech:
                                    result["runtime"] = ".NET"

        except Exception as e:
            bad(f"Fingerprinting failed: {e}")
            self.fingerprint = result
            return

        # ── Print results ──
        any_found = (result["server"] or result["framework"]
                     or result["cdn_waf"] or result["runtime"] or result["cookies"])
        if not any_found:
            info("Fingerprint: no identifying headers exposed")
        else:
            ok("Target fingerprint:")
            if result["server"]:
                print(f"         Server     : {C.GREEN}{result['server']}{C.RESET}")
            if result["framework"]:
                print(f"         Framework  : {C.GREEN}{result['framework']}{C.RESET}")
            if result["runtime"]:
                print(f"         Runtime    : {C.GREEN}{result['runtime']}{C.RESET}")
            if result["cdn_waf"]:
                print(f"         CDN/WAF    : {C.GREEN}{', '.join(result['cdn_waf'])}{C.RESET}")
            if result["cookies"]:
                cookie_str = ", ".join(f"{c['name']} → {c['tech']}" for c in result["cookies"])
                print(f"         Cookies    : {C.GREEN}{cookie_str}{C.RESET}")

        self.fingerprint = result

    async def run(self):
        banner()
        info(f"Target     : {self.target}")
        info(f"Concurrency: {self.concurrency} workers")
        if self.waf_evasion:
            warn("WAF evasion ON: rotating UA/IP, randomizing headers, jittering requests, probing %2F variants")
        if self.delay > 0:
            info(f"Fixed delay: {self.delay}s between requests")
        print()

        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
        ) as session:

            # ── Phase 0: JS Scraping ──
            scraper = JSScraper(self.target, session,
                                waf_evasion=self.waf_evasion, delay=self.delay)
            self.js_results = await scraper.run() or {}

            if self.js_only:
                self.report()
                return

            # Add JS-discovered endpoints to scan list
            extra_paths = []
            if self.js_results:
                extra_paths = [ep for ep in self.js_results.get("endpoints", [])
                               if ep not in API_PATHS + GRAPHQL_PATHS]
                if extra_paths:
                    info(f"Adding {len(extra_paths)} JS-discovered paths to scan")

            # ── SPA Detection ──
            await self.detect_spa(session)
            print()

            # ── Phase 1: Discover API endpoints ──
            semaphore = asyncio.Semaphore(self.concurrency)
            all_paths = API_PATHS + extra_paths
            if self.waf_evasion:
                variants = encoded_path_variants(all_paths)
                if variants:
                    info(f"WAF evasion: adding {len(variants)} %2F-encoded path variants")
                    all_paths = all_paths + variants
            info(f"Phase 1: Discovering API endpoints ({len(all_paths)} paths)...")
            tasks = [self.probe(session, path, semaphore) for path in all_paths]
            await asyncio.gather(*tasks)

            # ── Phase 1b: POST probing on 405 results ──
            method_not_allowed = [e["url"] for e in self.found_apis if e["status"] == 405]
            if method_not_allowed:
                print()
                info(f"Phase 1b: POST probing {len(method_not_allowed)} endpoint(s) that returned 405...")
                post_tasks = [self.probe_post(session, url, semaphore) for url in method_not_allowed]
                await asyncio.gather(*post_tasks)

            # ── Phase 2: Discover GraphQL endpoints ──
            print()
            info("Phase 2: Discovering GraphQL endpoints...")
            gql_tasks = [self.probe(session, path, semaphore) for path in GRAPHQL_PATHS]
            await asyncio.gather(*gql_tasks)

            gql_keywords = ["graphql", "gql", "query", "playground", "graphiql", "altair"]
            self.found_graphql = [
                e for e in self.found_apis
                if any(kw in e["url"].lower() for kw in gql_keywords)
                and e["status"] in (200, 201, 405)
            ]

            # ── Phase 3: GraphQL vulnerability checks ──
            print()
            if self.found_graphql:
                info(f"Phase 3: Running GraphQL checks on {len(self.found_graphql)} endpoint(s)...")
                for endpoint in self.found_graphql:
                    await self.check_graphql_introspection(session, endpoint["url"])
                    await self.check_graphql_debug_mode(session, endpoint["url"])
            else:
                info("Phase 3: Probing default GraphQL paths for vulns anyway...")
                for path in ["/graphql", "/api/graphql"]:
                    url = urljoin(self.target, path)
                    await self.check_graphql_introspection(session, url)

            # ── Phase 4: Fingerprint + Header + CORS checks ──
            print()
            info("Phase 4: Fingerprinting target + checking CORS / security headers...")
            await self.fingerprint_target(session)
            live_apis = [e for e in self.found_apis if e["status"] == 200][:5]
            for endpoint in live_apis:
                await self.check_cors(session, endpoint["url"])
                await self.check_missing_auth_headers(session, endpoint["url"])

        self.report()

    def report(self):
        print(f"\n{C.BOLD}{'─'*60}{C.RESET}")
        print(f"{C.BOLD}  SCAN COMPLETE{C.RESET}")
        print(f"{'─'*60}")
        print(f"  JS files scraped  : {len(self.js_results.get('js_files', []))}")
        print(f"  Endpoints from JS : {len(self.js_results.get('endpoints', []))}")
        print(f"  External URLs     : {len(self.js_results.get('external_urls', []))}")
        print(f"  Secrets in JS     : {len(self.js_results.get('secrets', []))}")
        print(f"  Endpoints found   : {len(self.found_apis)}")
        print(f"  GraphQL found     : {len(self.found_graphql)}")
        print(f"  Vulnerabilities   : {len(self.vulns)}")
        print(f"{'─'*60}\n")

        if self.vulns:
            print(f"{C.BOLD}Vulnerabilities:{C.RESET}")
            for v in self.vulns:
                sev_color = C.RED if v["severity"] == "HIGH" else C.YELLOW if v["severity"] == "MEDIUM" else C.CYAN
                print(f"  {sev_color}[{v['severity']}]{C.RESET} {v['type']}")
                print(f"         {v['url']}")
                print(f"         {v['detail']}\n")

        report_data = {
            "target": self.target,
            "fingerprint": self.fingerprint,
            "js_scraper": self.js_results,
            "endpoints": self.found_apis,
            "graphql_endpoints": self.found_graphql,
            "vulnerabilities": self.vulns
        }
        with open("apihawk_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        ok("Report saved to apihawk_report.json")


# ─── Banner ────────────────────────────────────────────────────────────────────

def banner():
    print(C.CYAN + C.BOLD + """
  APIHawk | API & GraphQL Vulnerability Scanner
""" + C.RESET + C.CYAN + "  For authorized targets only" + C.RESET)
    print()


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="APIHawk - Fast API & GraphQL Vulnerability Scanner"
    )
    parser.add_argument("-u", "--url",         required=True,        help="Target URL (e.g. https://target.com)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Concurrent workers (default: 50)")
    parser.add_argument("-t", "--timeout",     type=int, default=8,  help="Request timeout in seconds (default: 8)")
    parser.add_argument("-v", "--verbose",     action="store_true",  help="Show 404s and timeouts")
    parser.add_argument("--js-only",           action="store_true",  help="Only run JS scraper, skip endpoint fuzzing")
    parser.add_argument("--waf-evasion",       action="store_true",  help="Rotate UA/IP, randomize browser headers, jitter requests, probe %%2F-encoded paths")
    parser.add_argument("--delay",             type=float, default=0, help="Fixed delay in seconds between requests (default: 0)")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        bad("Invalid URL. Use format: https://target.com")
        sys.exit(1)

    if args.delay < 0:
        bad("--delay must be >= 0")
        sys.exit(1)

    scanner = APIHawk(
        target=args.url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose,
        js_only=args.js_only,
        waf_evasion=args.waf_evasion,
        delay=args.delay,
    )

    start = time.time()
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        warn("Scan interrupted by user.")
    finally:
        elapsed = time.time() - start
        info(f"Time elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
