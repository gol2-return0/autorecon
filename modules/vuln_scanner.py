"""
modules/vuln_scanner.py - Vulnerability scanning engine
Integrates: Nikto, Nuclei, plus custom checks
"""

import subprocess
import shutil
import json
import re
import os
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from modules.console import Console


class VulnScanner:
    def __init__(self, config):
        self.config = config
        self.target = config.target
        self.findings = []

    def run(self, crawl_data=None):
        crawl_data = crawl_data or {}

        # ── Custom checks ──────────────────────────────────────────────────
        Console.subsection("Custom Vulnerability Checks")
        self._check_security_headers()
        self._check_sensitive_files()
        self._check_cors(crawl_data)
        self._check_clickjacking()
        self._check_ssl_tls()
        self._check_xss_params(crawl_data)
        self._check_sqli_params(crawl_data)
        self._check_open_redirect(crawl_data)
        self._check_info_disclosure(crawl_data)
        self._check_default_credentials()
        self._check_directory_listing()
        self._check_http_methods()

        # ── Nikto ─────────────────────────────────────────────────────────
        Console.subsection("Nikto Scan")
        if shutil.which("nikto"):
            self._run_nikto()
        else:
            Console.warning("nikto not found in PATH — skipping Nikto scan")
            Console.info("Install: sudo apt-get install nikto  |  brew install nikto")

        # ── Nuclei ────────────────────────────────────────────────────────
        Console.subsection("Nuclei Scan")
        if shutil.which("nuclei"):
            self._run_nuclei()
        else:
            Console.warning("nuclei not found in PATH — skipping Nuclei scan")
            Console.info("Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        # Summary
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        Console.info(f"Total findings: {len(self.findings)}")
        for sev, cnt in counts.items():
            if cnt:
                Console.finding(f"{cnt} {sev.upper()} findings", sev)

        return {
            "findings": self.findings,
            "summary": counts,
            "total": len(self.findings),
        }

    # ── Helper ───────────────────────────────────────────────────────────────
    def _add_finding(self, title, severity, description, url="", evidence="", remediation="", source="custom"):
        finding = {
            "title": title,
            "severity": severity,
            "description": description,
            "url": url or self.target.base_url,
            "evidence": evidence,
            "remediation": remediation,
            "source": source,
        }
        self.findings.append(finding)
        Console.finding(f"{title} — {url or self.target.base_url}", severity)
        if evidence:
            Console.info(f"  Evidence: {evidence[:100]}")

    def _get(self, url, **kwargs):
        if not HAS_REQUESTS:
            return None
        try:
            import requests
            return requests.get(
                url,
                headers=self.config.headers,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs
            )
        except Exception:
            return None

    # ── Security Headers Check ───────────────────────────────────────────────
    def _check_security_headers(self):
        resp = self._get(self.target.base_url)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            ("Strict-Transport-Security", "strict-transport-security", "high",
             "Missing HSTS header allows downgrade attacks.",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
            ("X-Content-Type-Options", "x-content-type-options", "medium",
             "Missing X-Content-Type-Options allows MIME sniffing attacks.",
             "Add: X-Content-Type-Options: nosniff"),
            ("X-Frame-Options", "x-frame-options", "medium",
             "Missing X-Frame-Options allows clickjacking.",
             "Add: X-Frame-Options: DENY or SAMEORIGIN"),
            ("Content-Security-Policy", "content-security-policy", "medium",
             "Missing CSP increases XSS risk.",
             "Define and implement a strict Content-Security-Policy header."),
            ("X-XSS-Protection", "x-xss-protection", "low",
             "Missing X-XSS-Protection (legacy browsers).",
             "Add: X-XSS-Protection: 1; mode=block"),
            ("Referrer-Policy", "referrer-policy", "low",
             "Missing Referrer-Policy may leak sensitive URL information.",
             "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin"),
            ("Permissions-Policy", "permissions-policy", "low",
             "Missing Permissions-Policy allows uncontrolled browser feature access.",
             "Add a Permissions-Policy header limiting camera, microphone, geolocation access."),
        ]

        for name, header_key, severity, desc, remediation in checks:
            if header_key not in headers:
                self._add_finding(
                    f"Missing Security Header: {name}",
                    severity, desc,
                    url=self.target.base_url,
                    remediation=remediation,
                )

    # ── Sensitive Files ───────────────────────────────────────────────────────
    def _check_sensitive_files(self):
        sensitive = [
            ("/.env", "critical", "Environment file exposed — may contain credentials/secrets"),
            ("/.git/HEAD", "critical", "Git repository exposed — source code may be downloadable"),
            ("/.git/config", "critical", "Git configuration exposed"),
            ("/config.php", "high", "PHP config file exposed"),
            ("/wp-config.php", "critical", "WordPress config exposed — DB credentials at risk"),
            ("/phpinfo.php", "high", "phpinfo() exposed — server configuration disclosed"),
            ("/server-status", "medium", "Apache server-status exposed"),
            ("/server-info", "medium", "Apache server-info exposed"),
            ("/web.config", "high", "ASP.NET web.config exposed"),
            ("/backup.zip", "high", "Backup archive found — may contain source code"),
            ("/backup.sql", "high", "SQL backup file exposed"),
            ("/database.sql", "critical", "Database dump exposed"),
            ("/.htpasswd", "critical", ".htpasswd file exposed — password hashes at risk"),
            ("/package.json", "low", "Node.js package.json exposed — discloses dependencies"),
            ("/composer.json", "low", "PHP composer.json exposed — discloses dependencies"),
            ("/Dockerfile", "medium", "Dockerfile exposed — infrastructure info disclosed"),
            ("/docker-compose.yml", "high", "docker-compose.yml exposed — credentials may be inside"),
            ("/credentials.xml", "critical", "Credentials file exposed"),
            ("/id_rsa", "critical", "SSH private key exposed"),
        ]

        def check(item):
            path, severity, desc = item
            url = self.target.base_url + path
            resp = self._get(url, allow_redirects=False)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                return path, severity, desc, url, resp.text[:100]
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(check, item) for item in sensitive]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    path, severity, desc, url, evidence = result
                    self._add_finding(
                        f"Sensitive File Exposed: {path}",
                        severity, desc,
                        url=url,
                        evidence=evidence,
                        remediation="Restrict access to this file or remove it from the web root.",
                    )

    # ── CORS Misconfiguration ────────────────────────────────────────────────
    def _check_cors(self, crawl_data):
        resp = self._get(
            self.target.base_url,
            headers={**self.config.headers, "Origin": "https://evil.com"}
        )
        if not resp:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self._add_finding(
                "CORS Wildcard Origin",
                "medium",
                "Access-Control-Allow-Origin: * allows any origin to read responses.",
                url=self.target.base_url,
                evidence=f"ACAO: {acao}",
                remediation="Restrict CORS to specific trusted origins.",
            )
        elif "evil.com" in acao:
            sev = "high" if acac.lower() == "true" else "medium"
            self._add_finding(
                "CORS Origin Reflection" + (" with Credentials" if acac.lower() == "true" else ""),
                sev,
                "Server reflects arbitrary Origin header in ACAO response." +
                (" Credentials flag allows authentication bypass." if acac.lower() == "true" else ""),
                url=self.target.base_url,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Validate the Origin header against a strict whitelist.",
            )

    # ── Clickjacking ─────────────────────────────────────────────────────────
    def _check_clickjacking(self):
        resp = self._get(self.target.base_url)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        if not xfo and "frame-ancestors" not in csp:
            self._add_finding(
                "Clickjacking Vulnerability",
                "medium",
                "No X-Frame-Options or CSP frame-ancestors directive. Page can be embedded in iframes.",
                url=self.target.base_url,
                remediation="Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
            )

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    def _check_ssl_tls(self):
        if self.target.scheme != "https":
            self._add_finding(
                "No HTTPS",
                "high",
                "Target does not use HTTPS. Traffic is transmitted in plaintext.",
                url=self.target.base_url,
                remediation="Obtain a TLS certificate and enforce HTTPS with HSTS.",
            )
            return

        # Check if HTTP redirects to HTTPS
        http_url = "http://" + self.target.host
        try:
            import requests
            resp = requests.get(http_url, timeout=self.config.timeout, verify=False, allow_redirects=False)
            if resp.status_code not in [301, 302, 307, 308]:
                self._add_finding(
                    "HTTP Not Redirected to HTTPS",
                    "medium",
                    f"HTTP returns {resp.status_code} instead of redirecting to HTTPS.",
                    url=http_url,
                    remediation="Configure a 301 redirect from HTTP to HTTPS.",
                )
        except Exception:
            pass

    # ── XSS Parameter Testing ─────────────────────────────────────────────────
    def _check_xss_params(self, crawl_data):
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1)//",
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
        ]

        urls_with_params = [
            u for u in crawl_data.get("urls", [])
            if "?" in u and self._is_in_scope_url(u)
        ][:20]  # Limit to first 20

        tested = 0
        for url in urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in list(params.keys())[:3]:  # Test first 3 params per URL
                for payload in payloads[:2]:  # 2 payloads per param
                    test_params = {**{k: v[0] for k, v in params.items()}}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    resp = self._get(test_url)
                    if resp and payload in resp.text:
                        self._add_finding(
                            "Reflected XSS",
                            "high",
                            f"Reflected XSS in parameter '{param_name}'. Payload reflected unencoded in response.",
                            url=test_url,
                            evidence=f"Param: {param_name}, Payload: {payload[:50]}",
                            remediation="Implement output encoding and Content-Security-Policy.",
                        )
                        break
                    tested += 1

        if tested:
            Console.info(f"XSS: tested {tested} parameter/payload combinations")

    # ── SQLi Parameter Testing ────────────────────────────────────────────────
    def _check_sqli_params(self, crawl_data):
        payloads = ["'", '"', "' OR '1'='1", "1 AND 1=1", "1' AND '1'='2"]
        error_patterns = [
            "sql syntax", "mysql_fetch", "ora-", "sqlite_",
            "pg_query", "sqlstate", "syntax error", "unclosed quotation",
            "invalid query", "warning: mysql", "supplied argument is not a valid",
        ]

        urls_with_params = [
            u for u in crawl_data.get("urls", [])
            if "?" in u and self._is_in_scope_url(u)
        ][:15]

        tested = 0
        for url in urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in list(params.keys())[:2]:
                for payload in payloads[:3]:
                    test_params = {**{k: v[0] for k, v in params.items()}}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    resp = self._get(test_url)
                    if resp:
                        body_lower = resp.text.lower()
                        for pattern in error_patterns:
                            if pattern in body_lower:
                                self._add_finding(
                                    "SQL Injection (Error-Based)",
                                    "critical",
                                    f"SQL error triggered in parameter '{param_name}'. Database error disclosed.",
                                    url=test_url,
                                    evidence=f"Error pattern '{pattern}' found after payload: {payload}",
                                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                )
                                break
                    tested += 1

        if tested:
            Console.info(f"SQLi: tested {tested} parameter/payload combinations")

    # ── Open Redirect ─────────────────────────────────────────────────────────
    def _check_open_redirect(self, crawl_data):
        redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto",
                           "redirect_uri", "redirectTo", "return_url", "destination"]
        payload = "https://evil.com"

        for url in crawl_data.get("urls", [])[:30]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in redirect_params:
                if param in params or param.lower() in [p.lower() for p in params]:
                    test_params = {**{k: v[0] for k, v in params.items()}}
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        import requests
                        resp = requests.get(
                            test_url,
                            headers=self.config.headers,
                            timeout=self.config.timeout,
                            verify=False,
                            allow_redirects=False,
                        )
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "evil.com" in location:
                                self._add_finding(
                                    "Open Redirect",
                                    "medium",
                                    f"Parameter '{param}' allows redirection to arbitrary URLs.",
                                    url=test_url,
                                    evidence=f"Location: {location}",
                                    remediation="Validate redirect URLs against a whitelist of allowed domains.",
                                )
                    except Exception:
                        pass

    # ── Information Disclosure ────────────────────────────────────────────────
    def _check_info_disclosure(self, crawl_data):
        resp = self._get(self.target.base_url)
        if not resp:
            return

        # Server version disclosure
        server = resp.headers.get("Server", "")
        if server and any(c.isdigit() for c in server):
            self._add_finding(
                "Server Version Disclosure",
                "low",
                f"Server header discloses version information: {server}",
                url=self.target.base_url,
                evidence=f"Server: {server}",
                remediation="Configure web server to hide version details (e.g., ServerTokens Prod in Apache).",
            )

        x_powered = resp.headers.get("X-Powered-By", "")
        if x_powered:
            self._add_finding(
                "Technology Disclosure via X-Powered-By",
                "low",
                f"X-Powered-By header reveals backend technology: {x_powered}",
                url=self.target.base_url,
                evidence=f"X-Powered-By: {x_powered}",
                remediation="Remove or obfuscate the X-Powered-By header.",
            )

        # Stack traces in crawled pages
        error_patterns = [
            ("Traceback (most recent call last)", "Python stack trace"),
            ("at System.Web.", "ASP.NET stack trace"),
            ("java.lang.", "Java stack trace"),
            ("Fatal error:", "PHP fatal error"),
            ("Notice:", "PHP notice"),
            ("Warning: mysql_", "PHP MySQL warning"),
        ]
        for url in crawl_data.get("urls", [])[:10]:
            page_resp = self._get(url)
            if page_resp:
                for pattern, desc in error_patterns:
                    if pattern in page_resp.text:
                        self._add_finding(
                            f"Error/Stack Trace Disclosure: {desc}",
                            "medium",
                            f"{desc} found in page response.",
                            url=url,
                            evidence=pattern,
                            remediation="Disable detailed error messages in production. Log errors server-side only.",
                        )
                        break

    # ── Default Credentials ───────────────────────────────────────────────────
    def _check_default_credentials(self):
        admin_paths = [
            ("/admin", "admin", "admin"),
            ("/admin", "admin", "password"),
            ("/wp-login.php", "admin", "admin"),
            ("/wp-login.php", "admin", "password"),
            ("/phpmyadmin", "root", ""),
            ("/phpmyadmin", "root", "root"),
            ("/phpmyadmin", "admin", "admin"),
        ]

        for path, user, password in admin_paths:
            url = self.target.base_url + path
            check_resp = self._get(url, allow_redirects=False)
            if not check_resp or check_resp.status_code not in [200, 401]:
                continue

            try:
                import requests
                resp = requests.post(
                    url,
                    data={"username": user, "password": password, "log": user, "pwd": password},
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if resp.status_code == 200 and any(
                    term in resp.text.lower()
                    for term in ["dashboard", "logout", "welcome", "signed in"]
                ):
                    self._add_finding(
                        "Default Credentials",
                        "critical",
                        f"Admin login succeeded with default credentials: {user}/{password}",
                        url=url,
                        evidence=f"Credentials: {user}/{password}",
                        remediation="Change all default credentials immediately.",
                    )
            except Exception:
                pass

    # ── Directory Listing ─────────────────────────────────────────────────────
    def _check_directory_listing(self):
        dirs = ["/images", "/uploads", "/files", "/assets", "/static",
                "/css", "/js", "/scripts", "/backup", "/logs"]

        for path in dirs:
            url = self.target.base_url + path
            resp = self._get(url, allow_redirects=False)
            if resp and resp.status_code == 200:
                if any(indicator in resp.text.lower() for indicator in
                       ["index of /", "parent directory", "<title>directory listing"]):
                    self._add_finding(
                        "Directory Listing Enabled",
                        "medium",
                        f"Directory listing is enabled at {path}",
                        url=url,
                        evidence="'Index of' or 'Parent Directory' found in response",
                        remediation="Disable directory listing in web server configuration.",
                    )

    # ── HTTP Methods ──────────────────────────────────────────────────────────
    def _check_http_methods(self):
        if not HAS_REQUESTS:
            return

        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        try:
            import requests
            resp = requests.options(
                self.target.base_url,
                headers=self.config.headers,
                timeout=self.config.timeout,
                verify=False,
            )
            allow = resp.headers.get("Allow", "")
            for method in dangerous:
                if method in allow:
                    sev = "high" if method in ["PUT", "DELETE"] else "medium"
                    self._add_finding(
                        f"Dangerous HTTP Method Enabled: {method}",
                        sev,
                        f"HTTP {method} method is allowed. This may allow unauthorized file modification or deletion.",
                        url=self.target.base_url,
                        evidence=f"Allow: {allow}",
                        remediation=f"Disable the {method} method unless explicitly required.",
                    )
        except Exception:
            pass

    # ── Nikto ─────────────────────────────────────────────────────────────────
    def _run_nikto(self):
        url = self.target.base_url
        output_file = os.path.join(self.config.output_dir, "nikto_raw.txt")

        cmd = [
            "nikto",
            "-h", url,
            "-nointeractive",
            "-maxtime", "120",
            "-output", output_file,
            "-Format", "txt",
        ]

        if self.config.timeout:
            cmd += ["-timeout", str(self.config.timeout)]

        Console.info(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )

            # Parse nikto output
            output = proc.stdout + proc.stderr
            if os.path.exists(output_file):
                with open(output_file) as f:
                    output = f.read()

            self._parse_nikto_output(output)

        except subprocess.TimeoutExpired:
            Console.warning("Nikto scan timed out (180s)")
        except FileNotFoundError:
            Console.warning("nikto binary not found")
        except Exception as e:
            Console.error(f"Nikto error: {e}")

    def _parse_nikto_output(self, output):
        """Parse Nikto text output and add findings."""
        vuln_pattern = re.compile(r'^\+\s+(.+)', re.MULTILINE)
        for match in vuln_pattern.finditer(output):
            line = match.group(1).strip()
            if not line or line.startswith("Target") or line.startswith("Start Time"):
                continue

            # Skip purely informational lines
            if line.startswith("Server:") or line.startswith("Retrieved"):
                severity = "info"
            elif any(kw in line.lower() for kw in
                     ["dangerous", "critical", "remote command", "rce", "injection"]):
                severity = "high"
            elif any(kw in line.lower() for kw in
                     ["xss", "sql", "cross-site", "directory listing", "default credential"]):
                severity = "medium"
            else:
                severity = "low"

            self._add_finding(
                f"Nikto: {line[:80]}",
                severity,
                line,
                url=self.target.base_url,
                source="nikto",
            )

        Console.info(f"Nikto: parsed {len([f for f in self.findings if f.get('source') == 'nikto'])} findings")

    # ── Nuclei ────────────────────────────────────────────────────────────────
    def _run_nuclei(self):
        url = self.target.base_url
        output_file = os.path.join(self.config.output_dir, "nuclei_raw.jsonl")

        cmd = [
            "nuclei",
            "-u", url,
            "-json-export", output_file,
            "-silent",
            "-timeout", str(self.config.timeout),
            "-c", str(min(self.config.threads, 25)),
            "-severity", "critical,high,medium,low,info",
            "-etags", "intrusive",  # Skip intrusive templates to avoid DoS
        ]

        # Use common/recommended templates
        cmd += ["-t", "http/"]

        Console.info(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            self._parse_nuclei_output(output_file)

        except subprocess.TimeoutExpired:
            Console.warning("Nuclei scan timed out (300s)")
        except FileNotFoundError:
            Console.warning("nuclei binary not found")
        except Exception as e:
            Console.error(f"Nuclei error: {e}")

    def _parse_nuclei_output(self, output_file):
        """Parse Nuclei JSONL output."""
        if not os.path.exists(output_file):
            Console.warning("Nuclei output file not found")
            return

        count = 0
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    self._add_finding(
                        title=f"Nuclei: {info.get('name', 'Unknown')}",
                        severity=info.get("severity", "info").lower(),
                        description=info.get("description", ""),
                        url=data.get("matched-at", self.target.base_url),
                        evidence=data.get("extracted-results", [""])[0] if data.get("extracted-results") else "",
                        remediation=info.get("remediation", ""),
                        source="nuclei",
                    )
                    count += 1
                except json.JSONDecodeError:
                    pass

        Console.info(f"Nuclei: parsed {count} findings")

    def _is_in_scope_url(self, url):
        try:
            return urlparse(url).hostname == self.target.host
        except Exception:
            return False
