# 🔍 AutoRecon — Automated Reconnaissance & Vulnerability Scanner

> A modular, CLI-based web security assessment tool that automates reconnaissance, attack surface discovery, web crawling, and vulnerability scanning — producing structured reports in JSON, text, and HTML.

---

## ⚠️ Legal & Ethical Notice

**Only scan targets you are explicitly authorized to test.**  
Unauthorized scanning is illegal under laws such as the CFAA (US) and Computer Misuse Act (UK).  
This tool is intended for:
- Your own infrastructure
- Dedicated lab environments (HackTheBox, TryHackMe, DVWA, etc.)
- Bug bounty programs that explicitly permit automated scanning

---

## Features

| Category | Capability |
|---|---|
| **Reconnaissance** | DNS records, subdomains (brute + crt.sh), open ports, HTTP headers, SSL/TLS |
| **Technology Detection** | 25+ frameworks/servers (WordPress, Laravel, React, Angular, Nginx, etc.) |
| **Crawling** | Recursive BFS crawler, JS analysis, form extraction, parameter discovery |
| **Vulnerability Scanning** | Custom checks + Nikto + Nuclei integration |
| **Custom Checks** | XSS, SQLi, CORS, open redirect, security headers, sensitive files, default creds |
| **Reporting** | JSON, plain-text, and rich HTML dashboard |
| **Bonus** | Multi-threading, stealth mode, recursive crawl, Docker support, HTML report |

---

## Installation

### Option A — Direct (Python 3.8+)

```bash
git clone https://github.com/yourname/autorecon
cd autorecon
pip install -r requirements.txt

# Optional but recommended: install external scanners
sudo apt-get install nikto           # Debian/Ubuntu
brew install nikto                   # macOS
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Option B — Docker

```bash
docker build -t autorecon .
docker run --rm -v $(pwd)/reports:/autorecon/reports autorecon -t example.com --html
```

### Option C — Docker Compose

```bash
docker compose run autorecon -t example.com --html --threads 20
```

---

## Usage

```
python main.py -t <target> [options]
```

### Basic Examples

```bash
# Full scan with HTML report
python main.py -t https://example.com --html

# Recon only (no crawl, no vuln scan)
python main.py -t example.com --recon-only

# Skip vuln scanning (recon + crawl only)
python main.py -t 192.168.1.100 --no-vuln

# Stealth mode (rate-limited, random delays)
python main.py -t example.com --stealth --delay 2

# Deep recursive crawl, more threads
python main.py -t example.com --depth 5 --threads 30 --html

# Custom output directory
python main.py -t example.com --output /tmp/scans --html
```

### All Options

```
Target:
  -t, --target         Domain, subdomain, URL, or IP address (required)

Scan Modes:
  --full               Full scan (default behavior)
  --recon-only         Reconnaissance only
  --no-vuln            Skip vulnerability scanning
  --no-crawl           Skip web crawling
  --no-subdomains      Skip subdomain enumeration
  --no-ports           Skip port scanning

Crawler Options:
  --depth N            Crawl depth (default: 2)
  --threads N          Concurrent threads (default: 10)

Stealth Options:
  --stealth            Enable stealth mode (rate limiting, UA rotation)
  --timeout N          Request timeout in seconds (default: 10)
  --delay N            Delay between requests in seconds (default: 0)

Output Options:
  --output, -o DIR     Output directory (default: reports/)
  --html               Generate HTML report
  --quiet, -q          Suppress banner
  --no-color           Disable colored output
```

---

## Project Structure

```
autorecon/
├── main.py                     # CLI entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── modules/
    ├── __init__.py
    ├── console.py              # Colored terminal output
    ├── config.py               # Central configuration object
    ├── target.py               # Target parsing & validation
    ├── recon.py                # Reconnaissance engine
    │                           #   DNS, subdomains, ports, headers,
    │                           #   technologies, SSL, interesting paths
    ├── crawler.py              # Recursive web crawler
    │                           #   BFS crawl, JS analysis, form/param extraction
    ├── vuln_scanner.py         # Vulnerability scanner
    │                           #   Custom checks + Nikto + Nuclei
    └── report_generator.py     # Report output (JSON / TXT / HTML)
```

---

## Reconnaissance Modules

| Module | Description |
|---|---|
| DNS Lookup | A, PTR, MX, NS, TXT records via `socket` + `nslookup` |
| Subdomain Enumeration | 75 common subdomain wordlist + crt.sh certificate transparency |
| Port Scanning | 80 common ports with concurrent socket checking |
| HTTP Headers | Fetches and parses all response headers |
| Technology Detection | 25+ tech signatures matched against response body + headers |
| SSL/TLS Analysis | Certificate chain, SAN extraction, TLS version, cipher |
| Interesting Paths | 30+ sensitive paths checked (`.env`, `.git`, `phpinfo`, etc.) |
| Robots.txt | Parses and reports `Disallow` paths |

---

## Vulnerability Checks

### Custom Checks (No External Tools Required)
| Check | Severity |
|---|---|
| Missing Security Headers (HSTS, CSP, X-Frame-Options, etc.) | Medium–High |
| Sensitive Files Exposed (.env, .git, wp-config.php, etc.) | Critical–High |
| CORS Misconfiguration (wildcard, reflected origin with credentials) | Medium–High |
| Clickjacking | Medium |
| No HTTPS / HTTP not redirecting | High |
| Reflected XSS (parameter injection) | High |
| SQL Injection — Error-Based | Critical |
| Open Redirect | Medium |
| Server/Technology Version Disclosure | Low |
| Stack Trace / Error Disclosure | Medium |
| Default Credentials (admin panels) | Critical |
| Directory Listing | Medium |
| Dangerous HTTP Methods (PUT, DELETE, TRACE) | Medium–High |

### External Tool Integration
- **Nikto** — comprehensive web server scanner (2,600+ checks)
- **Nuclei** — template-based scanner (thousands of community templates)

---

## Reports

Each scan creates a timestamped directory under `reports/`:

```
reports/
└── example_com_20240115_143022/
    ├── report.json         # Full machine-readable results
    ├── report.txt          # Human-readable text report
    ├── report.html         # Interactive HTML dashboard (with --html)
    ├── nikto_raw.txt       # Raw Nikto output
    └── nuclei_raw.jsonl    # Raw Nuclei output (JSONL)
```

### HTML Report Sections
- Executive Summary with severity-colored stat cards
- Detected technologies
- HTTP headers table
- Open ports table
- Subdomains list
- Crawled URLs & endpoints
- JavaScript files
- Discovered parameters
- All vulnerability findings with evidence and remediation guidance

---

## Architecture

```
main.py
  │
  ├── TargetParser      validates & normalizes input
  ├── Config            central config object
  │
  ├── ReconEngine       modular reconnaissance
  │     ├── _dns_lookup()
  │     ├── _fetch_headers_and_detect_tech()
  │     ├── _certificate_info()
  │     ├── _enumerate_subdomains()
  │     ├── _port_scan()
  │     └── _check_interesting_paths()
  │
  ├── Crawler           recursive BFS web crawler
  │     ├── _crawl_page()
  │     ├── _extract_forms()
  │     └── _analyze_js_files()
  │
  ├── VulnScanner       vulnerability assessment
  │     ├── Custom checks (13 checks)
  │     ├── _run_nikto()
  │     └── _run_nuclei()
  │
  └── ReportGenerator
        ├── generate_json()
        ├── generate_text()
        └── generate_html()
```

---

## Ethical Guidelines

1. **Authorization** — Always obtain written permission before scanning.
2. **No DoS** — Thread limits and delays prevent server overload.
3. **No Destruction** — The tool reads only; it never modifies or deletes data.
4. **Rate Limiting** — Use `--stealth` and `--delay` on production systems.
5. **Responsible Disclosure** — Report findings to the system owner.

---

## License

MIT License — for educational and authorized security testing only.
