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
import socket
import hashlib
import struct
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

# ─── Small built-in subdomain wordlist (top 500) ──────────────────────────────
# Extends to ~2000 common patterns for built-in brute force.
# For full-scale recon, use --subdomain-wordlist with assetnote's 9M list.
SUBDOMAIN_WORDLIST = [
    # dev/staging environments — these are the real bounty finds
    "staging", "stage", "dev", "development", "test", "testing", "qa",
    "uat", "preprod", "pre-prod", "beta", "alpha", "demo", "sandbox",
    "internal", "external", "public", "private", "corp", "corporate",
    "admin", "administrator", "manage", "management", "dashboard",
    "portal", "app", "apps", "application", "api", "api-v1", "api-v2",
    "v1", "v2", "v3", "v4", "v5",
    "www", "www2", "www3", "www1", "web", "webserver", "webserver1",
    "mail", "email", "smtp", "imap", "pop3", "webmail", "exchange",
    "owa", "outlook", "mail2", "mx", "mx1", "mx2",
    "remote", "vpn", "vpn1", "vpn2", "openvpn", "wireguard",
    "ssh", "rdp", "bastion", "jump", "jumpbox", "jumpserver",
    "jenkins", "ci", "cd", "build", "builder", "buildserver",
    "git", "gitlab", "github", "bitbucket", "gitea", "gogs",
    "jira", "confluence", "wiki", "notion", "sharepoint",
    "grafana", "prometheus", "datadog", "newrelic", "sentry",
    "kibana", "elastic", "elasticsearch", "logstash",
    "sonar", "sonarqube", "nexus", "artifactory", "jfrog",
    "swagger", "swagger-ui", "redoc", "docs", "documentation",
    "api-docs", "api-v1-docs", "developer", "developers",
    "blog", "news", "status", "help", "support", "community",
    "forum", "chat", "discord", "slack", "teams",
    "analytics", "stats", "statistics", "metrics", "monitor",
    "monitoring", "logging", "logs", "audit",
    "auth", "login", "signin", "signup", "register", "registration",
    "oauth", "oauth2", "saml", "sso", "identity", "idp",
    "cdn", "static", "static1", "static2", "assets", "assets1",
    "img", "images", "media", "video", "videos", "cdn1", "cdn2",
    "upload", "uploads", "download", "downloads", "files", "file",
    "s3", "bucket", "storage", "backup", "backups",
    "db", "database", "mysql", "postgres", "redis", "mongodb",
    "search", "elasticsearch", "solr", "sphinx",
    "ws", "wss", "socket", "sockets", "websocket", "websockets",
    "stream", "streaming", "rtmp", "rtsp",
    "proxy", "proxy1", "proxy2", "gateway", "api-gateway",
    "lb", "loadbalancer", "load-balancer", "cluster", "node",
    "server", "server1", "server2", "server3",
    "ns1", "ns2", "ns3", "dns1", "dns2", "dns",
    "ntp", "time", "ntp1", "ntp2",
    "ldap", "ldaps", "ad", "active-directory", "dc",
    "console", "panel", "cpanel", "whm", "plesk",
    "phpmyadmin", "phpadmin", "adminer", "mysql-admin",
    "phpmyadmin2", "pma",
    "debug", "debugger", "debugging", "profiler", "xdebug",
    "testapi", "api-test", "apitest", "api-dev", "api-staging",
    "api-qa", "api-uat", "sandbox-api", "api-sandbox",
    "mobile", "mobile-api", "mapi", "mobileapi",
    "ios", "android", "iphone", "app-ios", "app-android",
    "graphql", "gql", "graphql-api", "gql-api", "graphiql",
    "playground", "altair", "graphql-playground",
    "redis", "redis-admin", "redis-commander",
    "kafka", "zookeeper", "rabbitmq", "mq", "activemq",
    "splunk", "splunk-search", "splunk-web",
    "nagios", "icinga", "zabbix", "cacti", "prometheus-ui",
    "docker", "registry", "docker-registry", "harbor",
    "k8s", "kubernetes", "kube", "kubernetes-dashboard",
    "dashboard-k8s", "k8s-dashboard",
    "swarm", "nomad", "consul",
    "terraform", "vault", "vault-ui",
    "pipeline", "pipelines", "runner", "runners",
    "worker", "workers", "queue", "queues",
    "webhook", "webhooks", "hook", "hooks",
    "callback", "callbacks", "notify", "notification",
    "sms", "sms-api", "sms-gateway", "sms-gw",
    "push", "push-api", "notifications",
    "payment", "payments", "pay", "billing",
    "checkout", "cart", "shop", "store",
    "orders", "order", "inventory",
    "crm", "sales", "marketing", "analytics",
    "recruit", "recruitment", "jobs", "careers",
    "partner", "partners", "partner-api",
    "vendor", "vendors", "supplier",
    "tunnel", "tunnels", "ngrok", "localtunnel",
    "mirror", "mirrors", "cache", "caching",
    "office", "office365", "sharepoint",
    "lync", "skype", "teams",
    "hq", "nyc", "london", "sfo", "ams", "fra", "sin", "tokyo",
    "us-east", "us-west", "eu-west", "eu-central",
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "sa-east-1", "ca-central-1",
    "prod", "production", "prod-1", "prod-2", "production-1",
    "dr", "disaster-recovery", "backup-site",
    "failover", "replica", "replicas", "replication",
    "read", "readonly", "read-only", "replica-read",
    "write", "writeonly", "master", "slave",
    "primary", "secondary", "standby",
    "blue", "green", "bluegreen", "canary",
    "release", "releases", "feature", "branch",
    "review", "review-app", "reviewapps",
    "pr", "pullrequest", "preview", "preview-app",
    "web-app", "webapp", "frontend", "front-end",
    "backend", "back-end", "middleware",
    "service", "services", "microservice", "microservices",
    "soa", "esb", "bus", "eventbus",
    "rpc", "grpc", "rest", "rest-api", "restapi",
    "soap", "soap-api", "wsdl",
    "odata", "odata-api",
    "hub", "connect", "integration", "integrations",
    "sync", "synchronization", "data-sync",
    "import", "exports", "export", "data-import",
    "etl", "data-pipeline",
    "report", "reports", "reporting", "bi",
    "insight", "insights", "dashboard-reports",
    "ml", "ai", "inference", "model", "models",
    "recommendation", "recommendations", "suggest",
    "personalization", "personalize",
    "config", "configuration", "settings", "setup",
    "admin-console", "admin-panel", "admin-dashboard",
    "superadmin", "root",
    "register", "registration", "sign-up", "sign_up",
    "forgot", "reset", "password-reset",
    "verify", "verification", "confirm",
    "mfa", "2fa", "otp", "totp", "authenticator",
    "validate", "validation",
    "compliance", "audit-log", "audit-logs",
    "privacy", "gdpr", "ccpa",
    "legal", "terms", "tos",
    "tutorial", "tutorials", "guide", "guides",
    "faq", "faqs", "knowledgebase", "knowledge-base",
    "kb", "help-center", "helpcenter",
    "roadmap", "changelog", "changelogs",
    "version", "versions", "version-history",
    "api-keys", "apikeys", "api-key", "credentials",
    "license", "licenses", "licensing",
    "trial", "trials", "onboarding", "onboard",
    "welcome", "getting-started", "gettingstarted",
    "start", "home", "index", "landing",
    "feature", "features", "pricing",
    "about", "contact", "team",
    "press", "media-kit", "brand",
    "investor", "investors", "ir",
    "security", "trust", "vulnerability-disclosure",
    "bugbounty", "hackerone", "bugcrowd",
    "hall-of-fame", "halloffame",
    "robots.txt", "sitemap", "sitemap.xml",
    "manifest", "manifest.json",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "env", ".env", "environment",
    ".git", ".git/config", ".svn", ".hg",
    "backup", "old", "new", "temp", "tmp",
    "bak", "backup-db", "db-backup",
    "dump", "sql-dump", "database-dump",
    "schema", "schema.sql", "migration", "migrations",
    "logs", "error_log", "access_log",
    "info", "phpinfo", "info.php",
    "server-status", "server-info",
    "wsgi", "uwsgi", "gunicorn",
    "nginx-status", "nginx-health",
    "php-fpm", "fpm-status", "fpm-ping",
    "opcache", "apc", "apcu",
    "xhprof", "xdebug", "tideways",
    "blackfire", "blackfire.io",
    "newrelic", "new-relic",
    "appdynamics", "dynatrace",
    "instana", "datadog-agent", "dd-agent",
    "consul-agent", "consul-ui",
    "nomad-ui", "vault-ui",
    "traefik", "traefik-dashboard",
    "haproxy", "haproxy-stats",
    "envoy", "envoy-admin",
    "istio", "istio-dashboard",
    "linkerd", "linkerd-dashboard",
    "nginx-ingress", "ingress-nginx",
    "kong", "kong-admin", "kong-manager",
    "tyk", "tyk-dashboard",
    "apisix", "apisix-dashboard",
    "page", "pages", "page1", "page2",
    "mysite", "site", "sites", "website",
    "wordpress", "wp", "wp-admin", "wp-login",
    "joomla", "drupal", "magento",
    "phpbb", "vbulletin", "smf",
    "shopify", "shopify-admin",
    "salesforce", "sf", "force",
    "hubspot", "marketo", "pardot",
    "zendesk", "freshdesk", "freshservice",
    "jira-servicedesk", "servicedesk",
    "statuspage", "status-page",
    "s3-website", "bucket-s3", "s3-bucket",
    "cloudfront", "cf", "cloudfront-cdn",
    "azure", "azure-app", "azure-webapp",
    "azure-api", "azure-functions", "azure-func",
    "gcp", "google-cloud", "gae", "appspot",
    "firebase", "firebase-app", "firebase-hosting",
    "heroku", "heroku-app", "herokuapp",
    "netlify", "netlify-app",
    "vercel", "vercel-app", "now",
    "render", "render-app",
    "fly", "fly-app", "flyio",
    "railway", "railway-app",
    "pantheon", "acquia",
    "awstats", "awstat",
    "webdav", "dav",
    "caldav", "carddav",
    "cal", "calendar",
    "contacts", "addressbook",
    "drive", "fileserver", "file-server", "nas",
    "print", "printer",
    "scanner", "scan",
    "fax", "faxserver",
    "voip", "sip", "asterisk", "freeswitch",
    "phone", "phones",
    "pbx", "ipbx",
    "uc", "unified-communications",
    "meet", "meeting", "meetings", "zoom",
    "webex", "gotomeeting", "teams-meetings",
    "classroom", "training", "learn",
    "moodle", "canvas", "blackboard",
    "lms", "learning",
    "e-learning", "elearning",
    "academy", "university",
    "adfs", "adfs01", "adfs02",
    "sts", "secure-token-service",
    "idp", "identity-provider",
    "shibboleth", "cas",
    "keycloak", "keycloak-admin",
    "okta", "okta-admin",
    "duo", "duo-admin",
    "ping", "pingid", "pingfederate",
    "radius", "radius-server",
    "tacacs", "tacacs+",
    "networking", "network",
    "router", "switch", "firewall",
    "fw", "fortinet", "fortigate", "forti",
    "paloalto", "pal", "panorama",
    "cisco", "cisco-asa", "asa",
    "juniper", "netscreen",
    "sophos", "sonicwall", "checkpoint",
    "f5", "bigip", "f5-bigip",
    "citrix", "netscaler",
    "vmware", "vsphere", "vcenter", "esxi",
    "vcloud", "vcd",
    "hyper-v", "hyperv", "scvmm",
    "xen", "xenserver", "xcp-ng",
    "proxmox", "pve",
    "ovirt", "ovirt-engine",
    "virtualbox", "vbox",
    "kvm", "libvirt",
    "docker-host", "dockerhost",
    "rancher", "rancher-server",
    "portainer", "portainer-ce",
    "lxc", "lxd",
    "openshift", "ocp",
    "okd", "origin",
    "eks", "aks", "gke",
    "k8s-api", "kubernetes-api",
    "kubelet", "kubelet-api",
    "etcd", "etcd-cluster",
    "harbor", "harbor-ui",
    "nexus-repo", "nexus-repository",
    "artifactory-ui",
    "gcr", "docker-hub",
    "quay", "quay-io",
    "ecr", "aws-ecr",
    "serverless", "lambda",
    "function", "functions", "func",
    "step-functions", "stepfunctions",
    "sqs", "sns", "eventbridge",
]

# Common subdomain prefixes built from permutations of the above patterns
SUBDOMAIN_WORDLIST += [
    f"{prefix}-{suffix}"
    for prefix in ["dev", "stage", "staging", "beta", "test", "qa", "uat", "preprod", "sandbox", "demo", "internal", "private", "corp"]
    for suffix in ["api", "app", "web", "portal", "admin", "dashboard", "graphql", "swagger", "docs"]
]
SUBDOMAIN_WORDLIST += [
    f"{prefix}{suffix}"
    for prefix in ["dev", "stage", "staging", "test", "qa", "uat", "preprod", "sandbox"]
    for suffix in ["api", "app", "web", "portal", "admin", "graphql"]
]
SUBDOMAIN_WORDLIST += [
    f"s{suffix}"
    for suffix in ["3", "3-console", "3-website", "3-bucket"]
]
# Add numerics
SUBDOMAIN_WORDLIST += [f"app{n}" for n in range(1, 20)]
SUBDOMAIN_WORDLIST += [f"api{n}" for n in range(1, 20)]
SUBDOMAIN_WORDLIST += [f"web{n}" for n in range(1, 20)]
SUBDOMAIN_WORDLIST += [f"server{n}" for n in range(1, 20)]
SUBDOMAIN_WORDLIST += [f"node{n}" for n in range(1, 10)]

# Deduplicate while preserving order
_seen = set()
SUBDOMAIN_WORDLIST = [w for w in SUBDOMAIN_WORDLIST if not (w in _seen or _seen.add(w))]

info(f"Built-in subdomain wordlist: {len(SUBDOMAIN_WORDLIST)} entries")

# ─── JS Scraper Patterns ───────────────────────────────────────────────────────

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
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def evasion_headers(waf_evasion, extra=None):
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
    if delay > 0:
        await asyncio.sleep(delay)
    elif waf_evasion:
        await asyncio.sleep(random.uniform(0.5, 2.0))


def encoded_path_variants(paths):
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

# ─── CNAME patterns for subdomain takeover detection ──────────────────────────

TAKEOVER_FINGERPRINTS = [
    # AWS
    (r"(?i)s3-website[-.](us|eu|ap|sa|ca|me|af|il)",                        "AWS S3"),
    (r"(?i)cloudfront\.net$",                                                "AWS CloudFront"),
    (r"(?i)elasticbeanstalk\.com$",                                          "AWS Elastic Beanstalk"),
    (r"(?i)execute-api\..*\.amazonaws\.com$",                                "AWS API Gateway"),
    (r"(?i)loadbalancer\.amazonaws\.com$",                                   "AWS ALB/NLB"),
    (r"(?i)rds\.amazonaws\.com$",                                            "AWS RDS"),
    # Azure
    (r"(?i)\.azurewebsites\.net$",                                           "Azure App Service"),
    (r"(?i)\.azureedge\.net$",                                               "Azure CDN"),
    (r"(?i)\.trafficmanager\.net$",                                          "Azure Traffic Manager"),
    (r"(?i)\.azure-api\.net$",                                               "Azure API Management"),
    (r"(?i)\.azurefd\.net$",                                                 "Azure Front Door"),
    (r"(?i)\.cloudapp\.net$",                                                "Azure Cloud Services"),
    (r"(?i)\.blob\.core\.windows\.net$",                                     "Azure Blob Storage"),
    # GCP
    (r"(?i)\.appspot\.com$",                                                 "Google App Engine"),
    (r"(?i)\.firebaseio\.com$",                                              "Firebase"),
    (r"(?i)\.firebaseapp\.com$",                                             "Firebase Hosting"),
    (r"(?i)\.storage\.googleapis\.com$",                                     "Google Cloud Storage"),
    (r"(?i)\.run\.app$",                                                     "Google Cloud Run"),
    (r"(?i)\.cloudfunctions\.net$",                                          "Google Cloud Functions"),
    # Other clouds
    (r"(?i)\.herokuapp\.com$",                                               "Heroku"),
    (r"(?i)\.netlify\.com$",                                                 "Netlify"),
    (r"(?i)\.netlify\.app$",                                                 "Netlify"),
    (r"(?i)\.vercel\.app$",                                                  "Vercel"),
    (r"(?i)\.pages\.dev$",                                                   "Cloudflare Pages"),
    (r"(?i)\.workers\.dev$",                                                 "Cloudflare Workers"),
    (r"(?i)\.fly\.dev$",                                                     "Fly.io"),
    (r"(?i)\.fly\.io$",                                                      "Fly.io"),
    (r"(?i)\.pantheonsite\.io$",                                             "Pantheon"),
    (r"(?i)\.kinsta\.cloud$",                                                "Kinsta"),
    # CDN / DNS
    (r"(?i)\.cdn\.ampproject\.org$",                                         "AMP Cache"),
    (r"(?i)\.myshopify\.com$",                                               "Shopify"),
    (r"(?i)\.shopify\.com$",                                                 "Shopify"),
    (r"(?i)\.wordpress\.com$",                                               "WordPress.com"),
    (r"(?i)\.wpengine\.com$",                                                "WP Engine"),
    (r"(?i)\.ghost\.io$",                                                    "Ghost"),
    (r"(?i)\.helpscoutdocs\.com$",                                           "Help Scout"),
    (r"(?i)\.zendesk\.com$",                                                 "Zendesk"),
    (r"(?i)\.freshdesk\.com$",                                               "Freshdesk"),
    (r"(?i)\.unbouncepages\.com$",                                           "Unbounce"),
    (r"(?i)\.instapage\.com$",                                               "Instapage"),
    (r"(?i)\.launchdarkly\.com$",                                            "LaunchDarkly"),
    (r"(?i)\.strikingly\.com$",                                              "Strikingly"),
    (r"(?i)\.squarespace\.com$",                                             "Squarespace"),
    (r"(?i)\.wixsite\.com$",                                                 "Wix"),
    (r"(?i)\.wix\.com$",                                                     "Wix"),
    (r"(?i)\.webflow\.io$",                                                  "Webflow"),
    (r"(?i)\.webflow\.app$",                                                 "Webflow"),
    (r"(?i)\.teamwork\.com$",                                                "Teamwork"),
    (r"(?i)\.atlassian\.net$",                                               "Atlassian"),
    (r"(?i)\.statuspage\.io$",                                               "Statuspage"),
    (r"(?i)\.status\.page\.io$",                                             "Statuspage (ex-Bitbucket)"),
    (r"(?i)\.cargocollective\.com$",                                         "Cargo Collective"),
    (r"(?i)\.tictail\.com$",                                                 "Tictail"),
    (r"(?i)\.surge\.sh$",                                                    "Surge.sh"),
    (r"(?i)\.bitbucket\.io$",                                                "Bitbucket Pages"),
    (r"(?i)\.gitlab\.io$",                                                   "GitLab Pages"),
    (r"(?i)\.github\.io$",                                                   "GitHub Pages"),
    (r"(?i)\.readthedocs\.io$",                                              "Read the Docs"),
    (r"(?i)\.readthedocs\.org$",                                             "Read the Docs"),
    (r"(?i)\.pythonanywhere\.com$",                                          "PythonAnywhere"),
    (r"(?i)\.repl\.co$",                                                     "Replit"),
    (r"(?i)\.glitch\.me$",                                                   "Glitch"),
    (r"(?i)\.codepen\.io$",                                                  "CodePen"),
    (r"(?i)\.ngrok\.io$",                                                    "ngrok"),
    (r"(?i)\.ngrok\.app$",                                                   "ngrok"),
    (r"(?i)\.trycloudflare\.com$",                                           "Cloudflare Tunnel"),
    (r"(?i)\.loca\.lt$",                                                     "localtunnel"),
    (r"(?i)\.serveo\.net$",                                                  "Serveo"),
    # Known vulnerable patterns
    (r"(?i)\.desk\.com$",                                                    "Desk.com"),
    (r"(?i)\.zendesk\.com$",                                                 "Zendesk"),
    (r"(?i)\.fastly\.net$",                                                  "Fastly"),
    (r"(?i)\.helpjuice\.com$",                                               "Helpjuice"),
    (r"(?i)\.helpscout\.net$",                                               "Help Scout"),
    (r"(?i)\.uservoice\.com$",                                               "UserVoice"),
    (r"(?i)\.intercom\.io$",                                                 "Intercom"),
    (r"(?i)\.tawk\.to$",                                                     "Tawk.to"),
    (r"(?i)\.smartsheet\.com$",                                              "Smartsheet"),
    (r"(?i)\.freshservice\.com$",                                            "Freshservice"),
    (r"(?i)\.com$",                                                          "Unmanaged CNAME"),  # fallback for checking any unmanaged CNAME
]


# ─── Subdomain Scanner ─────────────────────────────────────────────────────────

class SubdomainScanner:
    """
    Discovers subdomains via:
      1) Certificate Transparency (crt.sh) — passive, no API key
      2) DNS brute-force with configurable wordlist
      3) DNS resolution to find live hosts
      4) HTTP probe on resolved hosts
      5) CNAME-based takeover detection
    """

    def __init__(self, domain, session, concurrency=100, timeout=5, waf_evasion=False,
                 delay=0, verbose=False, wordlist=None, brute_force=False):
        self.domain = domain.lower().strip()
        # Strip protocol if someone passes https://target.com
        if "://" in self.domain:
            self.domain = urlparse(self.domain).netloc or self.domain.split("://")[1]
        # Remove trailing slash, path, port
        self.domain = self.domain.split("/")[0].split(":")[0]

        self.session = session
        self.concurrency = concurrency
        self.timeout = timeout
        self.waf_evasion = waf_evasion
        self.delay = delay
        self.verbose = verbose
        self.custom_wordlist = wordlist
        self.do_brute = brute_force

        self.subdomains = set()       # all unique subdomains discovered
        self.resolved = {}            # subdomain -> list of IPs
        self.cname_records = {}       # subdomain -> CNAME target
        self.live_http = {}           # subdomain -> (status, title, tech)
        self.takeover_candidates = [] # subdomains potentially vulnerable
        self.scanned_hosts = []       # full URLs for the main scanner

    async def query_crtsh(self, semaphore):
        """Query Certificate Transparency logs via crt.sh API."""
        info(f"Querying crt.sh for *.{self.domain}...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        results = []
        try:
            async with semaphore:
                await evasion_delay(self.delay, self.waf_evasion)
                headers = evasion_headers(self.waf_evasion, {"Accept": "application/json"})
                async with self.session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200:
                        text = await r.text()
                        try:
                            certs = json.loads(text)
                        except json.JSONDecodeError:
                            warn(f"crt.sh returned non-JSON response (length={len(text)})")
                            return
                        for cert in certs:
                            name_value = cert.get("name_value", "")
                            for sub in name_value.split("\n"):
                                sub = sub.strip().lower()
                                # Filter wildcards, the domain itself, and empty
                                if sub and "*" not in sub and sub != self.domain:
                                    # Ensure it ends with the target domain
                                    if sub.endswith("." + self.domain) or sub.endswith(self.domain):
                                        results.append(sub)
                    else:
                        warn(f"crt.sh returned HTTP {r.status}")
        except asyncio.TimeoutError:
            warn("crt.sh query timed out")
        except Exception as e:
            warn(f"crt.sh error: {e}")

        # Deduplicate
        for sub in results:
            self.subdomains.add(sub)
        ok(f"crt.sh: {len(results)} subdomains found")

    async def query_crtsh_identity(self, semaphore):
        """Also query identity subdomains via crt.sh with SAN parsing."""
        # Some subdomains only appear in SAN, not name_value
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json&excluded=expired"
        try:
            async with semaphore:
                await evasion_delay(self.delay, self.waf_evasion)
                headers = evasion_headers(self.waf_evasion, {"Accept": "application/json"})
                async with self.session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200:
                        text = await r.text()
                        try:
                            certs = json.loads(text)
                        except json.JSONDecodeError:
                            return
                        for cert in certs:
                            for field in ("name_value", "common_name", "issuer_name"):
                                val = cert.get(field, "")
                                if isinstance(val, str) and self.domain in val.lower():
                                    for sub in val.replace("\n", " ").split():
                                        sub = sub.strip().lower().rstrip(".")
                                        if sub and "*" not in sub and sub.endswith(self.domain) and sub != self.domain:
                                            self.subdomains.add(sub)
        except Exception:
            pass

    async def try_dns_resolve(self, hostname, semaphore):
        """Resolve a hostname to IPs and check CNAME."""
        try:
            # We use asyncio's event loop's getaddrinfo for non-blocking DNS
            loop = asyncio.get_event_loop()
            ips = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            addresses = list(set(info[4][0] for info in ips))
            self.resolved[hostname] = addresses
            return True
        except socket.gaierror:
            return False
        except Exception:
            return False

    async def try_dns_resolve_with_cname(self, hostname, semaphore):
        """Resolve and capture CNAME for takeover detection."""
        try:
            loop = asyncio.get_event_loop()
            ips = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            addresses = list(set(info[4][0] for info in ips))
            self.resolved[hostname] = addresses
            return True
        except socket.gaierror:
            # Even on NXDOMAIN, try to get CNAME if there's a SERVFAIL or no A record
            # We can't easily get CNAME from getaddrinfo, so use aiohttp's DNS or skip
            # We'll catch CNAME in the HTTP probe phase via response inspection
            return False
        except Exception:
            return False

    async def brute_force_subdomains(self, semaphore):
        """Brute-force subdomains using wordlist."""
        wordlist = self.custom_wordlist or SUBDOMAIN_WORDLIST
        info(f"Brute-forcing subdomains with {len(wordlist)} names...")

        resolved_count = 0
        total = len(wordlist)

        # We need to rate-limit DNS queries to avoid being blocked
        dns_sem = asyncio.Semaphore(50)

        async def try_sub(word):
            hostname = f"{word}.{self.domain}"
            if hostname in self.subdomains:
                return  # Already known from crt.sh
            async with dns_sem:
                try:
                    loop = asyncio.get_event_loop()
                    ips = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                    addresses = list(set(info[4][0] for info in ips))
                    self.subdomains.add(hostname)
                    self.resolved[hostname] = addresses
                    return hostname, addresses
                except (socket.gaierror, OSError):
                    return None
                except Exception:
                    return None

        # Process in chunks to show progress
        chunk_size = 200
        found_any = False
        for i in range(0, total, chunk_size):
            chunk = wordlist[i:i+chunk_size]
            tasks = [try_sub(w) for w in chunk]
            results = await asyncio.gather(*tasks)
            chunk_found = sum(1 for r in results if r is not None)
            resolved_count += chunk_found
            if chunk_found > 0:
                found_any = True
            if self.verbose or (chunk_found > 0 and i % 1000 == 0):
                pct = min(100, (i + chunk_size) / total * 100)
                info(f"DNS brute-force: {i+len(chunk)}/{total} ({pct:.0f}%) — {resolved_count} resolved so far")

        if found_any:
            ok(f"DNS brute-force: {resolved_count} new subdomains resolved")

    async def dns_resolve_all(self, semaphore):
        """Resolve all un-resolved subdomains discovered via crt.sh."""
        to_resolve = [s for s in self.subdomains if s not in self.resolved]
        if not to_resolve:
            return

        info(f"Resolving {len(to_resolve)} subdomains...")
        dns_sem = asyncio.Semaphore(100)

        async def resolve_one(hostname):
            async with dns_sem:
                try:
                    loop = asyncio.get_event_loop()
                    ips = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                    addresses = list(set(info[4][0] for info in ips))
                    self.resolved[hostname] = addresses
                except socket.gaierror:
                    pass  # unresolvable, don't add
                except Exception:
                    pass

        tasks = [resolve_one(s) for s in to_resolve]
        await asyncio.gather(*tasks)
        resolved_now = sum(1 for s in to_resolve if s in self.resolved)
        ok(f"DNS resolution: {resolved_now}/{len(to_resolve)} live")

    async def http_probe(self, semaphore):
        """Probe resolved subdomains over HTTP/HTTPS to find live web services."""
        to_probe = list(self.resolved.keys())
        if not to_probe:
            return

        info(f"HTTP probing {len(to_probe)} live subdomains...")

        async def probe_one(hostname):
            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                try:
                    async with semaphore:
                        await evasion_delay(self.delay, self.waf_evasion)
                        async with self.session.get(
                            url, ssl=False, allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers=evasion_headers(self.waf_evasion)
                        ) as r:
                            status = r.status
                            # Try to get page title
                            body = await r.text(errors="ignore")
                            title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
                            title = title_match.group(1).strip()[:80] if title_match else ""
                            # Detect server tech
                            tech = []
                            server = r.headers.get("Server", "")
                            if server:
                                tech.append(server)
                            xpb = r.headers.get("X-Powered-By", "")
                            if xpb:
                                tech.append(xpb)
                            # Check CNAME from headers / redirects
                            cname = None
                            redirect_url = str(r.url)
                            if redirect_url != url:
                                parsed = urlparse(redirect_url)
                                if parsed.netloc != hostname:
                                    cname = parsed.netloc

                            self.live_http[hostname] = {
                                "status": status,
                                "title": title,
                                "tech": tech,
                                "final_url": redirect_url,
                                "scheme": scheme,
                            }
                            # Build scan targets for APIHawk main scanner
                            self.scanned_hosts.append(url)

                            tech_str = f" | {', '.join(tech)}" if tech else ""
                            title_str = f" — {title}" if title else ""
                            # Color by status
                            if 200 <= status < 300:
                                ok(f"[{status}] {url}{title_str}{tech_str}")
                            elif 300 <= status < 400:
                                warn(f"[{status}] {url} -> {redirect_url}{title_str}")
                            elif 400 <= status < 500:
                                warn(f"[{status}] {url}{title_str}{tech_str} (auth required, possible endpoint)")
                            elif status >= 500:
                                bad(f"[{status}] {url}{title_str}{tech_str}")
                            return url, status, title, tech
                except asyncio.TimeoutError:
                    if self.verbose:
                        bad(f"[TIMEOUT] {url}")
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                    pass
            return None

        tasks = [probe_one(h) for h in to_probe]
        results = await asyncio.gather(*tasks)
        live_count = sum(1 for r in results if r is not None)
        ok(f"HTTP probe: {live_count}/{len(to_probe)} respond to HTTP(S)")

        # Print summary
        if live_count > 0:
            print(f"\n{C.BOLD}  Live Subdomains Summary:{C.RESET}")
            print(f"  {'─'*60}")
            for hostname in sorted(self.live_http.keys()):
                info = self.live_http[hostname]
                tech = " | ".join(info["tech"]) if info["tech"] else "—"
                status = info["status"]
                color = C.GREEN if 200 <= status < 300 else C.YELLOW if status < 400 else C.RED
                print(f"  {color}{info['scheme']}://{hostname}{C.RESET}")
                print(f"     Status: {status} | Title: {info['title'][:60] or '—'} | Tech: {tech}")

    async def check_takeover(self, semaphore):
        """
        Check for subdomain takeover by examining CNAME records.
        We check if the CNAME target matches known services and if the
        HTTP response indicates an unclaimed resource.
        """
        takeover_checks = []

        # For each live subdomain that redirected to a different host
        for hostname, info in self.live_http.items():
            final_url = info.get("final_url", "")
            if final_url:
                final_host = urlparse(final_url).netloc
                if final_host and final_host != hostname:
                    takeover_checks.append((hostname, final_host, info))

        # Also check any subdomain we couldn't resolve (NXDOMAIN) but was discovered
        # — these are prime takeover candidates if they have CNAME records to unclaimed services
        unresolved = [s for s in self.subdomains if s not in self.resolved]
        for hostname in unresolved[:100]:  # limit to first 100
            # Check if there's a CNAME by trying to resolve a CNAME
            # We'll do this via simple heuristic: try to getaddrinfo and if
            # we get SERVFAIL vs NXDOMAIN, one might have a dangling CNAME
            takeover_checks.append((hostname, None, None))

        # For live hosts, check body content for known unclaimed patterns
        takeover_fingerprints_body = [
            (r"(?i)no such bucket",                             "AWS S3"),
            (r"(?i)the specified bucket does not exist",         "AWS S3"),
            (r"(?i)404 Not Found.*Code.*NoSuchBucket",           "AWS S3"),
            (r"(?i)there is no app hosted at this address",      "Heroku"),
            (r"(?i)something went wrong.*no app configured",     "Heroku"),
            (r"(?i)application not found",                       "Heroku"),
            (r"(?i)heroku.*no such app",                         "Heroku"),
            (r"(?i)404.*page not found.*azure",                  "Azure"),
            (r"(?i)the site you are looking for does not exist",  "Azure"),
            (r"(?i)404.*not found.*azurewebsites",               "Azure App Service"),
            (r"(?i)this virtual machine doesn't exist",          "Azure Cloud Services"),
            (r"(?i)there is no site configured",                 "IIS / Azure"),
            (r"(?i)404.*file not found.*firebase",               "Firebase"),
            (r"(?i)project not found",                           "Firebase"),
            (r"(?i)not found.*firebaseio",                       "Firebase Realtime DB"),
            (r"(?i)hosting.*not found",                          "Firebase Hosting"),
            (r"(?i)404.*not found.*appspot",                     "Google App Engine"),
            (r"(?i)there is no such app",                        "Google App Engine"),
            (r"(?i)not found.*cloudfront",                       "CloudFront"),
            (r"(?i)bad request.*cloudfront",                     "CloudFront"),
            (r"(?i)the request could not be satisfied",          "CloudFront"),
            (r"(?i)cdn.*not found",                              "Generic CDN"),
            (r"(?i)no such site",                                "WordPress.com"),
            (r"(?i)doesn't exist.*wordpress",                    "WordPress.com"),
            (r"(?i)this site is no longer available",            "WordPress.com"),
            (r"(?i)there is no site here",                       "Shopify"),
            (r"(?i)shopify.*not found",                          "Shopify"),
            (r"(?i)not found.*shopify",                          "Shopify"),
            (r"(?i)page not found.*netlify",                     "Netlify"),
            (r"(?i)not found.*netlify",                          "Netlify"),
            (r"(?i)deploy.*not found",                           "Vercel"),
            (r"(?i)vercel.*404",                                 "Vercel"),
            (r"(?i)this page is not found",                      "GitHub Pages"),
            (r"(?i)404.*github.*pages",                          "GitHub Pages"),
            (r"(?i)there is no such page",                       "GitLab Pages"),
            (r"(?i)page not found.*gitlab",                      "GitLab Pages"),
            (r"(?i)bitbucket.*not found",                        "Bitbucket Pages"),
            (r"(?i)repository not found",                        "Bitbucket"),
            (r"(?i)project not found.*readthedocs",              "Read the Docs"),
            (r"(?i)page not found.*surge",                       "Surge.sh"),
            (r"(?i)project not found.*pythonanywhere",           "PythonAnywhere"),
            (r"(?i)this page is unavailable",                    "Pantheon"),
            (r"(?i)pantheon.*not found",                         "Pantheon"),
            (r"(?i)no such app.*fly\.io",                        "Fly.io"),
            (r"(?i)not found.*fly\.io",                          "Fly.io"),
            (r"(?i)page not found.*wix",                         "Wix"),
            (r"(?i)wix.*not found",                              "Wix"),
            (r"(?i)site not found.*squarespace",                 "Squarespace"),
            (r"(?i)squarespace.*not found",                      "Squarespace"),
            (r"(?i)not found.*zendesk",                          "Zendesk"),
            (r"(?i)this help site is not available",             "Zendesk"),
            (r"(?i)not found.*freshdesk",                        "Freshdesk"),
            (r"(?i)this page is gone",                           "Tumblr"),
            (r"(?i)there's nothing here.*tumblr",                "Tumblr"),
            (r"(?i)unbounce.*not found",                         "Unbounce"),
            (r"(?i)this site is not configured",                 "Fastly"),
            (r"(?i)fastly.*error.*not found",                    "Fastly"),
            (r"(?i)domain not configured",                       "Kinsta"),
            (r"(?i)the page you are looking for was not found",  "Ghost"),
            (r"(?i)page not found.*ghost",                       "Ghost"),
            (r"(?i)404.*not found",                              "Generic 404 — check manually"),
        ]

        for hostname in list(self.live_http.keys()):
            try:
                async with semaphore:
                    await evasion_delay(self.delay, self.waf_evasion)
                    url = f"{self.live_http[hostname]['scheme']}://{hostname}/"
                    async with self.session.get(
                        url, ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers=evasion_headers(self.waf_evasion)
                    ) as r:
                        body = await r.text(errors="ignore")
                        for pattern, service in takeover_fingerprints_body:
                            if re.search(pattern, body):
                                candidate = {
                                    "hostname": hostname,
                                    "service": service,
                                    "pattern": pattern,
                                    "status": r.status,
                                    "body_snippet": body[:300] if len(body) > 300 else body,
                                }
                                self.takeover_candidates.append(candidate)
                                print(f"\n{C.RED}{C.BOLD}[TAKEOVER] {hostname} may be vulnerable to {service}!{C.RESET}")
                                print(f"            Status: {r.status}")
                                print(f"            Match : {pattern}\n")
                                break
            except Exception:
                pass

        if self.takeover_candidates:
            warn(f"Found {len(self.takeover_candidates)} potential subdomain takeover candidates")
        else:
            ok("No obvious subdomain takeover indicators detected")

    async def run(self):
        """Execute the full subdomain discovery pipeline."""
        banner_sub()

        info(f"Subdomain Recon Target: {self.domain}")
        print()

        sem = asyncio.Semaphore(self.concurrency)

        # Phase S0: Certificate Transparency (passive, no fingerprint)
        await self.query_crtsh(sem)
        await self.query_crtsh_identity(sem)
        print()

        # Phase S1: DNS brute-force (if enabled)
        if self.do_brute or self.custom_wordlist:
            await self.brute_force_subdomains(sem)
            print()

        # Phase S2: DNS resolution for all discovered subdomains
        await self.dns_resolve_all(sem)
        print()

        # Print subdomain stats
        info(f"Subdomains discovered: {len(self.subdomains)}")
        info(f"Resolved (live DNS)   : {len(self.resolved)}")
        print()

        if self.resolved:
            # Phase S3: HTTP(S) probe
            await self.http_probe(sem)
            print()

            # Phase S4: Subdomain takeover checks
            await self.check_takeover(sem)
            print()

        # Print final summary
        self.print_summary()
        return {
            "domain": self.domain,
            "subdomains": sorted(self.subdomains),
            "resolved": {k: v for k, v in self.resolved.items()},
            "live_http": self.live_http,
            "takeover_candidates": self.takeover_candidates,
            "scanned_hosts": self.scanned_hosts,
        }

    def print_summary(self):
        banner_line()
        print(f"{C.BOLD}  SUBDOMAIN RECON SUMMARY{C.RESET}")
        banner_line()
        print(f"  Target domain       : {self.domain}")
        print(f"  Subdomains found    : {len(self.subdomains)}")
        print(f"  DNS-resolved        : {len(self.resolved)}")
        print(f"  HTTP(S) live        : {len(self.live_http)}")
        print(f"  Takeover candidates : {len(self.takeover_candidates)}")
        print()

        if self.takeover_candidates:
            print(f"{C.RED}{C.BOLD}  ⚠ Potential Takeover Targets:{C.RESET}")
            for c in self.takeover_candidates:
                print(f"    {c['hostname']} — {c['service']}")
            print()

        if self.live_http:
            print(f"{C.GREEN}{C.BOLD}  Live Endpoints:{C.RESET}")
            for hostname, info in sorted(self.live_http.items()):
                status = info["status"]
                color = C.GREEN if 200 <= status < 300 else C.YELLOW if status < 400 else C.RED
                title = info.get("title", "")[:50]
                tech = " | ".join(info.get("tech", [])) if info.get("tech") else ""
                print(f"    {color}{info['scheme']}://{hostname}{C.RESET} [{status}] {title}")
                if tech:
                    print(f"      └─ {tech}")
        banner_line()


def banner_sub():
    print(C.CYAN + C.BOLD + """
  ╔══════════════════════════════════════════════╗
  ║      SUBHawk — Subdomain Recon Engine         ║
  ║  CT Logs · DNS Brute-force · HTTP Probe       ║
  ║  Takeover Detection · Auto-feed to APIHawk    ║
  ╚══════════════════════════════════════════════╝
""" + C.RESET)


def banner_line():
    print(f"{C.BOLD}{'─'*60}{C.RESET}")


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

                for pattern in JS_ENDPOINT_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        m = match.strip()
                        if len(m) < 4 or len(m) > 200:
                            continue
                        if m.startswith("http"):
                            parsed = urlparse(m)
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

                for pattern, label in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        val = match if isinstance(match, str) else match[0]
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
                 waf_evasion=False, delay=0, subdomain_scan=False, subdomain_brute=False,
                 subdomain_wordlist=None, no_subscan=False):
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
        self.spa_fingerprint = None
        self.fingerprint   = {}
        self.subdomain_scan = subdomain_scan
        self.subdomain_brute = subdomain_brute
        self.subdomain_wordlist = subdomain_wordlist
        self.no_subscan = no_subscan
        self.subdomain_results = {}
        self.all_targets = [self.target]  # includes subdomain results

    async def probe(self, session, path, semaphore):
        url = URL(urljoin(self.target, path), encoded=True)
        async with semaphore:
            await evasion_delay(self.delay, self.waf_evasion)
            try:
                async with session.get(url, ssl=False, allow_redirects=False,
                                        headers=evasion_headers(self.waf_evasion)) as r:
                    status = r.status
                    cl = r.headers.get("Content-Length", "?")

                    if status in (200, 201, 204):
                        if self.spa_fingerprint:
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

                if not result["runtime"] and "x-runtime" in headers:
                    result["runtime"] = "Ruby (X-Runtime present)"

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

    async def run_scan_on_target(self, session, target_url, target_label):
        """Run full API endpoint + GraphQL + vuln scan on a single target."""
        original_target = self.target
        self.target = target_url.rstrip("/")

        print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
        print(f"{C.BOLD}  Scanning: {target_label}{C.RESET}")
        print(f"{'═'*60}\n")

        # Phase SPA detection
        await self.detect_spa(session)
        print()

        # Phase 1: API endpoint discovery
        semaphore = asyncio.Semaphore(self.concurrency)
        all_paths = API_PATHS
        if self.waf_evasion:
            variants = encoded_path_variants(all_paths)
            if variants:
                all_paths = all_paths + variants
        info(f"Phase 1: API endpoint discovery ({len(all_paths)} paths)...")
        tasks = [self.probe(session, path, semaphore) for path in all_paths]
        await asyncio.gather(*tasks)

        # Phase 1b: POST probing on 405s
        method_not_allowed = [a for a in self.found_apis if a.get("status") == 405]
        if method_not_allowed:
            info(f"Phase 1b: POST probing {len(method_not_allowed)} endpoints returning 405...")
            post_sem = asyncio.Semaphore(min(self.concurrency, 10))
            tasks = [self.probe_post(session, str(a['url']), post_sem) for a in method_not_allowed]
            await asyncio.gather(*tasks)
        print()

        # Phase 2: GraphQL detection
        graphql_check_paths = []
        for path in GRAPHQL_PATHS:
            full_url = urljoin(self.target, path)
            graphql_check_paths.append(full_url)
        graphql_check_paths = list(set(graphql_check_paths))
        info(f"Phase 2: GraphQL detection ({len(graphql_check_paths)} paths)...")

        async def graphql_probe(path_url, sem):
            async with sem:
                await evasion_delay(self.delay, self.waf_evasion)
                try:
                    async with session.post(
                        URL(path_url, encoded=True), json={"query": "{__typename}"},
                        ssl=False, headers=evasion_headers(self.waf_evasion, {"Content-Type": "application/json"})
                    ) as r:
                        if r.status != 200:
                            return
                        data = await r.json(content_type=None)
                        if data.get("data") is not None:
                            ok(f"[GQL] {path_url}")
                            self.found_graphql.append(path_url)
                except Exception:
                    pass

        gql_sem = asyncio.Semaphore(self.concurrency)
        gql_tasks = [graphql_probe(p, gql_sem) for p in graphql_check_paths]
        await asyncio.gather(*gql_tasks)
        print()

        # Phase 3: Deep GraphQL vuln scanning
        if self.found_graphql:
            for gql_url in self.found_graphql:
                info(f"Testing: {gql_url}")
                await self.check_graphql_introspection(session, gql_url)
                await self.check_graphql_debug_mode(session, gql_url)
                print()

        # Phase 4: Security checks on primary API endpoints
        api_scan_targets = ([a["url"] for a in self.found_apis if a["status"] in (200, 201, 401, 403)]
                            + self.found_graphql)
        api_scan_targets = list(set(api_scan_targets))
        if api_scan_targets:
            info(f"Phase 4: Security checks on {len(api_scan_targets)} endpoints...")

            cors_sem = asyncio.Semaphore(min(self.concurrency, 5))
            auth_sem = asyncio.Semaphore(min(self.concurrency, 10))

            cors_tasks = [self.check_cors(session, url) for url in api_scan_targets[:10]]
            auth_tasks = [self.check_missing_auth_headers(session, url) for url in api_scan_targets[:10]]

            await asyncio.gather(*cors_tasks, *auth_tasks)
            print()

        # Restore original target
        self.target = original_target

    async def run(self):
        banner()

        info(f"Target : {self.target}")
        info(f"Concurrency: {self.concurrency} | Timeout: {self.timeout.total}")
        info(f"WAF Evasion: {'ON' if self.waf_evasion else 'OFF'} | Delay: {self.delay}s")
        print()

        async with aiohttp.ClientSession(timeout=self.timeout,
                                          connector=aiohttp.TCPConnector(ssl=False)) as session:

            # Phase 0: Subdomain recon (if enabled)
            if self.subdomain_scan and not self.no_subscan:
                domain = urlparse(self.target).netloc or self.target.split("://")[-1].split("/")[0]
                scanner = SubdomainScanner(
                    domain=domain,
                    session=session,
                    concurrency=self.concurrency,
                    timeout=min(8, self.timeout.total),
                    waf_evasion=self.waf_evasion,
                    delay=self.delay,
                    verbose=self.verbose,
                    wordlist=self.subdomain_wordlist,
                    brute_force=self.subdomain_brute,
                )
                self.subdomain_results = await scanner.run()

                # Add subdomain HTTP hosts to the scanning queue
                if scanner.scanned_hosts:
                    # Scan the primary target first
                    self.all_targets = [self.target]
                    self.all_targets.extend(scanner.scanned_hosts)
                print()

            # Phase X: Fingerprint primary target
            info("Phase 0: Target fingerprinting...")
            await self.fingerprint_target(session)
            print()

            # JS Scraper (on primary target)
            js = JSScraper(self.target, session, self.waf_evasion, self.delay)
            self.js_results = await js.run()

            # If subdomains found, also scrape JS on live subdomains
            if self.subdomain_results and self.subdomain_results.get("live_http"):
                sub_js_targets = list(self.subdomain_results["live_http"].keys())[:5]
                for sub_host in sub_js_targets:
                    scheme = self.subdomain_results["live_http"][sub_host]["scheme"]
                    sub_js = JSScraper(f"{scheme}://{sub_host}", session,
                                        self.waf_evasion, self.delay)
                    sub_js_results = await sub_js.run()
                    # Merge results
                    if sub_js_results:
                        if sub_js_results.get("endpoints"):
                            js.endpoints_found.update(sub_js_results["endpoints"])
                        if sub_js_results.get("secrets"):
                            js.secrets_found.extend(sub_js_results["secrets"])

            # Main scan — primary target
            await self.run_scan_on_target(session, self.target, self.target)

            # Also scan subdomains that returned 200/401/403
            if self.subdomain_results and self.subdomain_results.get("live_http"):
                sub_scan_targets = []
                for hostname, host_info in self.subdomain_results["live_http"].items():
                    if host_info["status"] in (200, 401, 403):
                        url = f"{host_info['scheme']}://{hostname}"
                        sub_scan_targets.append((url, hostname))

                if sub_scan_targets:
                    info(f"Scanning {len(sub_scan_targets)} live subdomains for APIs/GQL...")
                    for url, label in sub_scan_targets:
                        await self.run_scan_on_target(session, url, label)

        # ─── Final Report ────────────────────────────────────────────
        self.summary_report()

    def summary_report(self):
        print()
        banner_end()
        print(C.BOLD + "  FINAL REPORT".center(60) + C.RESET)
        banner_end()

        print(f"  Target                      : {self.target}")
        print(f"  Subdomains discovered       : {len(self.subdomain_results.get('subdomains', [])) if self.subdomain_results else 0}")
        print(f"  Live HTTP(S) endpoints      : {len(self.subdomain_results.get('live_http', {})) if self.subdomain_results else 0}")
        print(f"  API endpoints found         : {len(self.found_apis)}")
        print(f"  GraphQL endpoints found     : {len(self.found_graphql)}")
        print(f"  JS endpoints extracted      : {len(self.js_results.get('endpoints', [])) if self.js_results else 0}")
        print(f"  JS secrets found            : {len(self.js_results.get('secrets', [])) if self.js_results else 0}")
        print(f"  Vulnerabilities detected    : {len(self.vulns)}")
        print()

        # Subdomain takeover summary
        takeover = self.subdomain_results.get("takeover_candidates", []) if self.subdomain_results else []
        if takeover:
            print(f"  {C.RED}{C.BOLD}  ⚠ Subdomain Takeover Candidates:{C.RESET}")
            for t in takeover:
                print(f"     {C.RED}{t['hostname']} — {t['service']}{C.RESET}")
            print()

        # Vulnerabilities
        if self.vulns:
            vulns_by_severity = {"HIGH": [], "MEDIUM": [], "LOW": []}
            for v in self.vulns:
                sev = v.get("severity", "LOW")
                vulns_by_severity.setdefault(sev, []).append(v)

            for sev in ("HIGH", "MEDIUM", "LOW"):
                if vulns_by_severity[sev]:
                    color = C.RED if sev == "HIGH" else C.YELLOW if sev == "MEDIUM" else C.CYAN
                    print(f"  {color}{C.BOLD}{sev} Severity:{C.RESET}")
                    for v in vulns_by_severity[sev]:
                        print(f"     [{v['type']}] {v['url']}")
                        print(f"     {v['detail']}")
                    print()

        # API endpoints discovered
        if self.found_apis:
            print(f"  {C.GREEN}{C.BOLD}API Endpoints Found:{C.RESET}")
            for a in self.found_apis:
                url = str(a["url"])
                status = a["status"]
                color = C.GREEN if 200 <= status < 300 else C.YELLOW if status < 400 else C.RED
                print(f"     {color}[{status}]{C.RESET} {url}")
            print()

        # GraphQL endpoints
        if self.found_graphql:
            print(f"  {C.GREEN}{C.BOLD}GraphQL Endpoints Found:{C.RESET}")
            for g in self.found_graphql:
                print(f"     {C.GREEN}{g}{C.RESET}")
            print()

        # JS endpoints
        if self.js_results and self.js_results.get("endpoints"):
            print(f"  {C.YELLOW}{C.BOLD}Endpoints from JS:{C.RESET}")
            for ep in sorted(self.js_results["endpoints"])[:20]:
                print(f"     {C.YELLOW}{ep}{C.RESET}")
            if len(self.js_results["endpoints"]) > 20:
                print(f"     ... and {len(self.js_results['endpoints']) - 20} more")
            print()

        # Secrets
        if self.js_results and self.js_results.get("secrets"):
            print(f"  {C.RED}{C.BOLD}Secrets from JS:{C.RESET}")
            for s in self.js_results["secrets"]:
                print(f"     [{s['type']}] {s['value']}")
                print(f"     File: {s['js_file']}")
            print()

        # Subdomain summary
        if self.subdomain_results and self.subdomain_results.get("subdomains"):
            subdomains = self.subdomain_results["subdomains"]
            print(f"  {C.CYAN}{C.BOLD}Subdomains Discovered ({len(subdomains)}):{C.RESET}")
            for s in sorted(subdomains)[:30]:
                if s in self.subdomain_results.get("resolved", {}):
                    ips = ", ".join(self.subdomain_results["resolved"][s])
                    print(f"     {C.GREEN}{s}{C.RESET}  → {ips}")
                else:
                    print(f"     {C.YELLOW}{s}{C.RESET}  (unresolved)")
            if len(subdomains) > 30:
                print(f"     ... and {len(subdomains) - 30} more")
            print()

        banner_end()


# ─── Main Entry Point ──────────────────────────────────────────────────────────

def banner():
    print(C.CYAN + C.BOLD + r"""
   ╔══════════════════════════════════════════════════╗
   ║         █████╗ ██████╗ ██╗  ██╗ █████╗ ██╗    ║
   ║        ██╔══██╗██╔══██╗██║  ██║██╔══██╗██║    ║
   ║        ███████║██████╔╝███████║███████║██║    ║
   ║        ██╔══██║██╔═══╝ ██╔══██║██╔══██║██║    ║
   ║        ██║  ██║██║     ██║  ██║██║  ██║██║    ║
   ║        ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝    ║
   ║   Fast Async API & GraphQL Vulnerability Scanner ║
   ║           with Subdomain Recon Engine            ║
   ╚══════════════════════════════════════════════════╝
""" + C.RESET)


def banner_end():
    print(C.BOLD + "─" * 60 + C.RESET)


def main():
    parser = argparse.ArgumentParser(
        description="APIHawk — Fast Async API & GraphQL Vulnerability Scanner with Subdomain Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python apihawk.py -u https://target.com
  python apihawk.py -u target.com --subdomain             # with subdomain recon
  python apihawk.py -u target.com --subdomain --brute     # subdomain + DNS brute-force
  python apihawk.py -u target.com --waf --delay 1          # WAF evasion
  python apihawk.py -u target.com --js-only                # JS scraping only
  python apihawk.py -u target.com -c 100 -t 10             # high concurrency
  python apihawk.py -u target.com --subdomain --subdomain-wordlist list.txt
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL or domain")

    scan_opts = parser.add_argument_group("Scanning Options")
    scan_opts.add_argument("-c", "--concurrency", type=int, default=50,
                           help="Max concurrent tasks (default: 50)")
    scan_opts.add_argument("-t", "--timeout", type=int, default=8,
                           help="HTTP request timeout in seconds (default: 8)")
    scan_opts.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose output (show 404s)")
    scan_opts.add_argument("--js-only", action="store_true",
                           help="Only run JS scraper, skip API/GQL scan")

    waf_opts = parser.add_argument_group("WAF Evasion")
    waf_opts.add_argument("--waf", action="store_true",
                          help="Enable WAF evasion (random User-Agents, delay, IP spoofing)")
    waf_opts.add_argument("--delay", type=float, default=0,
                          help="Fixed delay between requests in seconds")

    sub_opts = parser.add_argument_group("Subdomain Recon")
    sub_opts.add_argument("--subdomain", action="store_true",
                          help="Enable subdomain reconnaissance (crt.sh)")
    sub_opts.add_argument("--brute", action="store_true",
                          help="Enable DNS brute-force (requires --subdomain)")
    sub_opts.add_argument("--subdomain-wordlist", type=str,
                          help="Custom wordlist file for DNS brute-force (one per line)")
    sub_opts.add_argument("--no-subscan", action="store_true",
                          help="Don't scan discovered subdomains for APIs/GQL")

    args = parser.parse_args()

    wordlist = None
    if args.subdomain_wordlist:
        try:
            with open(args.subdomain_wordlist, 'r', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            ok(f"Loaded {len(wordlist)} entries from {args.subdomain_wordlist}")
        except Exception as e:
            bad(f"Failed to load wordlist: {e}")
            sys.exit(1)

    scanner = APIHawk(
        target=args.url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose,
        js_only=args.js_only,
        waf_evasion=args.waf,
        delay=args.delay,
        subdomain_scan=args.subdomain,
        subdomain_brute=args.brute,
        subdomain_wordlist=wordlist,
        no_subscan=args.no_subscan,
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
