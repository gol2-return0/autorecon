"""
modules/recon.py - Reconnaissance engine
Collects: DNS, subdomains, ports, HTTP headers, technologies, WHOIS
"""

import socket
import ssl
import time
import json
import subprocess
import concurrent.futures
from urllib.parse import urljoin
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from modules.console import Console


# Common subdomains wordlist for brute-forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "ftp", "m", "mobile", "shop", "forum", "cdn", "static",
    "img", "images", "media", "assets", "download", "downloads", "upload",
    "uploads", "status", "support", "help", "docs", "wiki", "git",
    "gitlab", "github", "jenkins", "ci", "jira", "confluence", "monitor",
    "grafana", "prometheus", "dashboard", "app", "apps", "web", "old",
    "new", "beta", "alpha", "demo", "db", "database", "mysql", "redis",
    "elasticsearch", "kibana", "internal", "intranet", "vpn2", "gateway",
    "proxy", "auth", "sso", "login", "oauth", "accounts", "account",
    "payments", "pay", "billing", "crm", "erp", "uat", "qa", "preprod",
    "production", "prod", "backup", "mx", "smtp2", "imap", "pop", "pop3",
    "autodiscover", "autoconfig", "webdisk", "whm", "cpanel", "phpmyadmin",
    "adminer", "wpadmin", "wordpress", "wp", "cms", "magento", "drupal",
    "joomla", "panel", "control", "manage", "management", "office", "cloud",
]

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161,
    179, 194, 389, 443, 445, 465, 500, 514, 587, 636, 993, 995,
    1080, 1194, 1433, 1521, 2049, 2181, 2222, 2375, 2376, 3000,
    3306, 3389, 3690, 4000, 4369, 5000, 5432, 5601, 5672, 5900,
    6379, 6443, 7001, 7443, 8000, 8001, 8008, 8080, 8081, 8082,
    8083, 8085, 8086, 8088, 8090, 8091, 8095, 8181, 8443, 8888,
    9000, 9001, 9090, 9091, 9092, 9200, 9300, 9418, 9443, 10000,
    27017, 27018, 28017,
]

# Technology detection signatures
TECH_SIGNATURES = {
    "WordPress":     ["wp-content", "wp-includes", "wp-json", "/xmlrpc.php"],
    "Drupal":        ["Drupal", "drupal.js", "sites/default"],
    "Joomla":        ["Joomla!", "/components/com_", "joomla"],
    "Magento":       ["Mage.Cookies", "magento", "/skin/frontend/"],
    "Laravel":       ["laravel_session", "XSRF-TOKEN"],
    "Django":        ["csrftoken", "csrfmiddlewaretoken", "__admin__"],
    "Ruby on Rails": ["_rails_session", "X-Powered-By: Phusion Passenger"],
    "ASP.NET":       ["ASP.NET_SessionId", "X-Powered-By: ASP.NET", "__VIEWSTATE"],
    "PHP":           ["X-Powered-By: PHP", "PHPSESSID"],
    "Node.js":       ["X-Powered-By: Express", "connect.sid"],
    "React":         ["react", "__NEXT_DATA__", "_next/static"],
    "Angular":       ["ng-version", "angular", "ng-app"],
    "Vue.js":        ["__vue__", "vue.js", "nuxt"],
    "jQuery":        ["jquery", "jQuery"],
    "Bootstrap":     ["bootstrap.min.css", "bootstrap.min.js"],
    "Nginx":         ["nginx", "Server: nginx"],
    "Apache":        ["Apache", "Server: Apache"],
    "IIS":           ["Server: Microsoft-IIS", "IIS"],
    "Cloudflare":    ["cloudflare", "CF-RAY", "__cfduid"],
    "AWS":           ["amazonaws.com", "X-Amzn", "cloudfront.net"],
    "Google Cloud":  ["googleusercontent.com", "X-Google"],
    "Fastly":        ["Fastly", "X-Served-By"],
    "Varnish":       ["X-Varnish", "Age:"],
    "GraphQL":       ["/graphql", "graphql", "__schema"],
    "Swagger":       ["/swagger", "/api-docs", "swagger-ui"],
    "Elasticsearch": ["/elasticsearch", "_search", "_cluster/health"],
}


class ReconEngine:
    def __init__(self, config):
        self.config = config
        self.target = config.target
        self.results = {
            "dns": {},
            "whois": {},
            "subdomains": [],
            "ports": [],
            "headers": {},
            "technologies": [],
            "certificates": {},
            "interesting_files": [],
        }

    def run(self):
        self._dns_lookup()
        self._fetch_headers_and_detect_tech()
        self._certificate_info()

        if not self.config.no_subdomains:
            self._enumerate_subdomains()

        if not self.config.no_ports:
            self._port_scan()

        self._check_interesting_paths()
        return self.results

    # ── DNS ─────────────────────────────────────────────────────────────────
    def _dns_lookup(self):
        Console.subsection("DNS Lookup")
        host = self.target.host
        dns_data = {}

        # A record
        try:
            ip = socket.gethostbyname(host)
            dns_data["A"] = [ip]
            Console.success(f"A Record    : {ip}")
        except Exception as e:
            Console.warning(f"A record lookup failed: {e}")

        # Reverse DNS
        try:
            ip = dns_data.get("A", [None])[0]
            if ip:
                rdns = socket.gethostbyaddr(ip)[0]
                dns_data["PTR"] = rdns
                Console.info(f"Reverse DNS : {rdns}")
        except Exception:
            pass

        # Try to get MX, NS, TXT via nslookup/host if available
        for record_type in ["MX", "NS", "TXT", "CNAME"]:
            try:
                result = subprocess.run(
                    ["nslookup", f"-type={record_type}", host],
                    capture_output=True, text=True, timeout=5
                )
                lines = [l.strip() for l in result.stdout.splitlines()
                         if record_type.lower() in l.lower() or
                         ("mail exchanger" in l.lower() and record_type == "MX") or
                         ("nameserver" in l.lower() and record_type == "NS")]
                if lines:
                    dns_data[record_type] = lines[:5]
                    Console.info(f"{record_type:<12}: {lines[0]}")
            except Exception:
                pass

        # Try dig if available
        try:
            result = subprocess.run(
                ["dig", "+short", "any", host],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                dns_data["dig_any"] = result.stdout.strip().splitlines()[:10]
        except Exception:
            pass

        self.results["dns"] = dns_data

    # ── HTTP Headers & Technology Detection ──────────────────────────────────
    def _fetch_headers_and_detect_tech(self):
        Console.subsection("HTTP Headers & Technology Detection")

        if not HAS_REQUESTS:
            Console.warning("requests library not available; skipping HTTP header fetch")
            return

        try:
            import requests
            resp = requests.get(
                self.target.base_url,
                headers=self.config.headers,
                timeout=self.config.timeout,
                allow_redirects=True,
                verify=False,
            )

            # Store headers
            headers_dict = dict(resp.headers)
            self.results["headers"] = headers_dict

            # Print interesting headers
            interesting = [
                "Server", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
                "Content-Security-Policy", "Strict-Transport-Security",
                "X-Content-Type-Options", "Access-Control-Allow-Origin",
                "Set-Cookie", "CF-RAY", "X-Amzn-Trace-Id",
            ]
            for h in interesting:
                val = headers_dict.get(h, headers_dict.get(h.lower()))
                if val:
                    Console.result(h, val[:100])

            # Detect technologies
            body = resp.text
            combined = body + " " + json.dumps(headers_dict)
            detected = []

            for tech, sigs in TECH_SIGNATURES.items():
                if any(sig.lower() in combined.lower() for sig in sigs):
                    detected.append(tech)
                    Console.success(f"Technology  : {tech}")

            self.results["technologies"] = detected

            # Security header analysis
            missing_security = []
            sec_headers = [
                "Strict-Transport-Security", "X-Content-Type-Options",
                "X-Frame-Options", "Content-Security-Policy",
                "X-XSS-Protection",
            ]
            for h in sec_headers:
                if h not in headers_dict and h.lower() not in headers_dict:
                    missing_security.append(h)

            if missing_security:
                Console.warning(f"Missing security headers: {', '.join(missing_security)}")
                self.results["missing_security_headers"] = missing_security

        except requests.exceptions.SSLError:
            Console.warning("SSL certificate error, retrying without verification...")
        except requests.exceptions.ConnectionError as e:
            Console.error(f"Connection error: {e}")
        except Exception as e:
            Console.error(f"Header fetch error: {e}")

    # ── SSL/TLS Certificate ──────────────────────────────────────────────────
    def _certificate_info(self):
        if self.target.scheme != "https":
            return

        Console.subsection("SSL/TLS Certificate")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            port = self.target.port or 443

            with socket.create_connection((self.target.host, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "subjectAltName": [
                            name for _, name in cert.get("subjectAltName", [])
                        ],
                        "cipher": cipher[0] if cipher else None,
                        "tls_version": cipher[1] if cipher else None,
                    }
                    self.results["certificates"] = cert_info

                    Console.result("Issuer", cert_info["issuer"].get("organizationName", "Unknown"))
                    Console.result("Valid Until", cert_info["notAfter"])
                    Console.result("TLS Version", cert_info.get("tls_version"))
                    Console.result("Cipher", cert_info.get("cipher"))

                    # SANs can reveal subdomains
                    sans = cert_info.get("subjectAltName", [])
                    if sans:
                        Console.info(f"SAN domains: {len(sans)} entries")
                        # Add valid SANs as discovered subdomains
                        for san in sans:
                            san_clean = san.lstrip("*.")
                            if san_clean.endswith(self.target.host) and san_clean != self.target.host:
                                if san_clean not in self.results["subdomains"]:
                                    self.results["subdomains"].append(san_clean)

        except Exception as e:
            Console.warning(f"Certificate fetch failed: {e}")

    # ── Subdomain Enumeration ────────────────────────────────────────────────
    def _enumerate_subdomains(self):
        Console.subsection("Subdomain Enumeration")

        host = self.target.host
        # Extract base domain (last 2 parts)
        parts = host.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        found = list(self.results.get("subdomains", []))

        def check_subdomain(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return fqdn, ip
            except Exception:
                return None

        Console.info(f"Checking {len(COMMON_SUBDOMAINS)} common subdomains...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                if result:
                    fqdn, ip = result
                    if fqdn not in found:
                        found.append(fqdn)
                        Console.success(f"Subdomain   : {fqdn} → {ip}")
                Console.progress(done, len(COMMON_SUBDOMAINS), f"Checking subdomains...")

        # Also try crt.sh (certificate transparency)
        self._crtsh_subdomains(base_domain, found)

        self.results["subdomains"] = list(set(found))
        Console.info(f"Total subdomains found: {len(self.results['subdomains'])}")

    def _crtsh_subdomains(self, domain, found):
        """Query crt.sh for certificate transparency subdomains."""
        if not HAS_REQUESTS:
            return
        try:
            import requests
            Console.info("Querying certificate transparency (crt.sh)...")
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            if name not in found:
                                found.append(name)
                                Console.success(f"crt.sh      : {name}")
        except Exception as e:
            Console.warning(f"crt.sh query failed: {e}")

    # ── Port Scanning ────────────────────────────────────────────────────────
    def _port_scan(self):
        Console.subsection("Port Scanning")
        host = self.target.host
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        Console.info(f"Scanning {len(COMMON_PORTS)} common ports on {host}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, self.config.threads * 5)) as executor:
            futures = {executor.submit(check_port, p): p for p in COMMON_PORTS}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                port = future.result()
                if port:
                    service = self._guess_service(port)
                    open_ports.append({"port": port, "service": service})
                    Console.success(f"Open Port   : {port}/tcp  ({service})")
                Console.progress(done, len(COMMON_PORTS), f"Scanning ports...")

        open_ports.sort(key=lambda x: x["port"])
        self.results["ports"] = open_ports
        Console.info(f"Open ports: {len(open_ports)}")

    def _guess_service(self, port):
        SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
            135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
            389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
            500: "ISAKMP", 514: "Syslog", 587: "SMTP-Submission",
            636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
            1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
            2049: "NFS", 2181: "ZooKeeper", 2222: "SSH-Alt",
            2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-Server",
            3306: "MySQL", 3389: "RDP", 3690: "SVN", 4000: "App",
            4369: "RabbitMQ", 5000: "Dev-Server", 5432: "PostgreSQL",
            5601: "Kibana", 5672: "AMQP", 5900: "VNC",
            6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic",
            7443: "WebLogic-SSL", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
            8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8082: "HTTP-Alt",
            8083: "HTTP-Alt", 8085: "HTTP-Alt", 8086: "InfluxDB",
            8088: "HTTP-Alt", 8090: "HTTP-Alt", 8091: "Couchbase",
            8095: "HTTP-Alt", 8181: "HTTP-Alt", 8443: "HTTPS-Alt",
            8888: "Jupyter", 9000: "PHP-FPM", 9001: "Supervisord",
            9090: "Prometheus", 9091: "HTTP-Alt", 9092: "Kafka",
            9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
            9418: "Git", 9443: "HTTPS-Alt", 10000: "Webmin",
            27017: "MongoDB", 27018: "MongoDB-Shard", 28017: "MongoDB-Web",
        }
        return SERVICES.get(port, "Unknown")

    # ── Interesting Paths ────────────────────────────────────────────────────
    def _check_interesting_paths(self):
        Console.subsection("Interesting Paths & Files")

        if not HAS_REQUESTS:
            return

        import requests
        paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/security.txt", "/humans.txt", "/.env", "/.git/HEAD",
            "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
            "/swagger.json", "/openapi.json", "/api-docs", "/graphql",
            "/.htaccess", "/web.config", "/phpinfo.php", "/info.php",
            "/server-status", "/server-info", "/wp-login.php", "/admin",
            "/administrator", "/login", "/wp-admin", "/phpmyadmin",
            "/config.php", "/config.yml", "/config.yaml", "/.DS_Store",
            "/backup.zip", "/backup.tar.gz", "/database.sql",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
        ]

        interesting_found = []

        def check_path(path):
            url = self.target.base_url + path
            try:
                resp = requests.get(
                    url,
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    verify=False,
                )
                if resp.status_code in [200, 301, 302, 401, 403]:
                    return {
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "path": path,
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in paths}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                if result:
                    interesting_found.append(result)
                    status = result["status"]
                    color = "green" if status == 200 else "yellow"
                    Console.finding(
                        f"[{status}] {result['url']}  ({result['size']} bytes)",
                        "info" if status != 200 else "low"
                    )
                    if self.config.stealth:
                        time.sleep(self.config.delay)

        # Parse robots.txt for disallowed paths
        self._parse_robots_txt(interesting_found)

        self.results["interesting_files"] = interesting_found
        Console.info(f"Interesting paths found: {len(interesting_found)}")

    def _parse_robots_txt(self, interesting_found):
        robots_entry = next((x for x in interesting_found if x["path"] == "/robots.txt"), None)
        if not robots_entry or robots_entry["status"] != 200:
            return

        if not HAS_REQUESTS:
            return

        import requests
        try:
            resp = requests.get(
                self.target.base_url + "/robots.txt",
                headers=self.config.headers,
                timeout=self.config.timeout,
                verify=False,
            )
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in resp.text.splitlines()
                if line.lower().startswith("disallow:")
            ]
            if disallowed:
                Console.info(f"robots.txt disallowed paths: {len(disallowed)}")
                for d in disallowed[:10]:
                    Console.result("  Disallowed", d)
                self.results["robots_disallowed"] = disallowed
        except Exception:
            pass
