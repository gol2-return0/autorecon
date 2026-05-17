"""
modules/report_generator.py - Generate JSON, text, and HTML reports
"""

import json
import os
from datetime import datetime


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#ff4757",
    "high":     "#ff6b35",
    "medium":   "#ffd32a",
    "low":      "#2ed573",
    "info":     "#1e90ff",
}


class ReportGenerator:
    def __init__(self, config, results):
        self.config = config
        self.results = results
        self.target = config.target
        self.out = config.output_dir

    def _safe_filename(self, ext):
        host = self.target.host.replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.out, f"report_{host}_{ts}.{ext}")

    # ── JSON Report ───────────────────────────────────────────────────────────
    def generate_json(self):
        path = os.path.join(self.out, "report.json")
        with open(path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        return path

    # ── Text Report ───────────────────────────────────────────────────────────
    def generate_text(self):
        path = os.path.join(self.out, "report.txt")
        r = self.results
        t = r.get("target", {})
        recon = r.get("recon", {})
        crawl = r.get("crawl", {})
        vuln = r.get("vuln", {})
        findings = sorted(
            vuln.get("findings", []),
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info").lower(), 4)
        )

        lines = []
        def ln(s=""): lines.append(s)
        def sep(): lines.append("=" * 70)
        def sub(): lines.append("-" * 70)

        sep()
        ln("  AUTORECON - VULNERABILITY ASSESSMENT REPORT")
        sep()
        ln(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        ln(f"  Target    : {t.get('base_url', '')}")
        ln(f"  Host      : {t.get('host', '')}")
        ln(f"  Type      : {t.get('type', '')}")
        ln(f"  Duration  : {r.get('scan_duration_seconds', 0):.1f}s")
        sep()

        # ── Executive Summary
        ln()
        ln("EXECUTIVE SUMMARY")
        sub()
        counts = vuln.get("summary", {})
        total = vuln.get("total", 0)
        ln(f"  Total Vulnerabilities : {total}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = counts.get(sev, 0)
            if c:
                ln(f"  {sev.capitalize():<22}: {c}")
        ln(f"  Subdomains Found      : {len(recon.get('subdomains', []))}")
        ln(f"  Open Ports            : {len(recon.get('ports', []))}")
        ln(f"  Technologies          : {len(recon.get('technologies', []))}")
        ln(f"  URLs Discovered       : {len(crawl.get('urls', []))}")
        ln(f"  JS Files              : {len(crawl.get('js_files', []))}")
        ln(f"  Parameters            : {len(crawl.get('parameters', []))}")
        ln()

        # ── DNS
        ln("DNS INFORMATION")
        sub()
        dns = recon.get("dns", {})
        for record_type, values in dns.items():
            if isinstance(values, list):
                for v in values[:3]:
                    ln(f"  {record_type:<10}: {v}")
            else:
                ln(f"  {record_type:<10}: {values}")
        ln()

        # ── Subdomains
        subdomains = recon.get("subdomains", [])
        if subdomains:
            ln(f"SUBDOMAINS ({len(subdomains)} found)")
            sub()
            for sd in sorted(subdomains)[:50]:
                ln(f"  {sd}")
            if len(subdomains) > 50:
                ln(f"  ... and {len(subdomains) - 50} more (see report.json)")
            ln()

        # ── Open Ports
        ports = recon.get("ports", [])
        if ports:
            ln(f"OPEN PORTS ({len(ports)} found)")
            sub()
            for p in ports:
                ln(f"  {p['port']:<6} ({p['service']})")
            ln()

        # ── Technologies
        techs = recon.get("technologies", [])
        if techs:
            ln(f"DETECTED TECHNOLOGIES")
            sub()
            for t in techs:
                ln(f"  + {t}")
            ln()

        # ── HTTP Headers
        headers = recon.get("headers", {})
        if headers:
            ln("HTTP HEADERS")
            sub()
            interesting = [
                "Server", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
                "Content-Security-Policy", "Strict-Transport-Security",
                "X-Content-Type-Options", "Access-Control-Allow-Origin",
            ]
            for h in interesting:
                val = headers.get(h, headers.get(h.lower()))
                if val:
                    ln(f"  {h:<35}: {val[:60]}")
            ln()

        # ── Interesting Files
        ifiles = recon.get("interesting_files", [])
        if ifiles:
            ln(f"INTERESTING PATHS ({len(ifiles)} found)")
            sub()
            for f in ifiles:
                ln(f"  [{f['status']}] {f['url']}")
            ln()

        # ── Endpoints
        urls = crawl.get("urls", [])
        if urls:
            ln(f"DISCOVERED ENDPOINTS ({len(urls)} total)")
            sub()
            for u in sorted(urls)[:100]:
                ln(f"  {u}")
            if len(urls) > 100:
                ln(f"  ... and {len(urls) - 100} more (see report.json)")
            ln()

        # ── JS Files
        js_files = crawl.get("js_files", [])
        if js_files:
            ln(f"JAVASCRIPT FILES ({len(js_files)} found)")
            sub()
            for js in sorted(js_files)[:30]:
                ln(f"  {js}")
            ln()

        # ── Parameters
        params = crawl.get("parameters", [])
        if params:
            ln(f"DISCOVERED PARAMETERS ({len(params)} found)")
            sub()
            ln("  " + ", ".join(sorted(params)[:100]))
            ln()

        # ── Forms
        forms = crawl.get("forms", [])
        if forms:
            ln(f"FORMS ({len(forms)} found)")
            sub()
            for form in forms[:20]:
                ln(f"  [{form['method']}] {form['action']}")
                for inp in form.get("inputs", []):
                    ln(f"    - {inp['name']} ({inp['type']})")
            ln()

        # ── Vulnerability Findings
        ln(f"VULNERABILITY FINDINGS ({len(findings)} total)")
        sep()
        if not findings:
            ln("  No vulnerabilities found.")
        else:
            for i, finding in enumerate(findings, 1):
                sev = finding.get("severity", "info").upper()
                ln(f"\n[{i}] [{sev}] {finding.get('title', 'Unknown')}")
                ln(f"  URL         : {finding.get('url', '')}")
                ln(f"  Source      : {finding.get('source', 'custom')}")
                desc = finding.get("description", "")
                if desc:
                    ln(f"  Description : {desc[:200]}")
                evidence = finding.get("evidence", "")
                if evidence:
                    ln(f"  Evidence    : {evidence[:150]}")
                remediation = finding.get("remediation", "")
                if remediation:
                    ln(f"  Remediation : {remediation[:200]}")
                sub()

        ln()
        sep()
        ln("  END OF REPORT — AutoRecon v1.0.0")
        sep()

        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    # ── HTML Report ───────────────────────────────────────────────────────────
    def generate_html(self):
        path = os.path.join(self.out, "report.html")
        r = self.results
        t = r.get("target", {})
        recon = r.get("recon", {})
        crawl = r.get("crawl", {})
        vuln = r.get("vuln", {})
        findings = sorted(
            vuln.get("findings", []),
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info").lower(), 4)
        )
        counts = vuln.get("summary", {})

        def badge(severity):
            color = SEVERITY_COLORS.get(severity.lower(), "#888")
            return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'

        def escape(s):
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Build findings HTML
        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info").lower()
            color = SEVERITY_COLORS.get(sev, "#888")
            findings_html += f"""
            <div class="finding-card" style="border-left:4px solid {color}">
              <div class="finding-header">
                <span class="finding-num">#{i}</span>
                {badge(sev)}
                <span class="finding-title">{escape(f.get('title',''))}</span>
                <span class="finding-source tag">{escape(f.get('source','custom'))}</span>
              </div>
              <div class="finding-body">
                <div class="finding-field"><b>URL</b> <code>{escape(f.get('url',''))}</code></div>
                {f'<div class="finding-field"><b>Description</b> {escape(f.get("description",""))}</div>' if f.get("description") else ""}
                {f'<div class="finding-field"><b>Evidence</b> <code>{escape(f.get("evidence",""))}</code></div>' if f.get("evidence") else ""}
                {f'<div class="finding-field remediation"><b>Remediation</b> {escape(f.get("remediation",""))}</div>' if f.get("remediation") else ""}
              </div>
            </div>"""

        # Stat cards
        total_vulns = len(findings)
        stat_cards = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = counts.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, "#888")
            stat_cards += f'<div class="stat-card" style="border-top:3px solid {color}"><div class="stat-num" style="color:{color}">{c}</div><div class="stat-label">{sev.capitalize()}</div></div>'

        # Subdomains list
        subdomains = recon.get("subdomains", [])
        sd_html = "".join(f'<div class="list-item">{escape(sd)}</div>' for sd in sorted(subdomains)[:100])

        # Ports table
        ports = recon.get("ports", [])
        ports_html = "".join(f'<tr><td>{p["port"]}</td><td>TCP</td><td>{escape(p["service"])}</td></tr>' for p in ports)

        # Technologies
        techs = recon.get("technologies", [])
        techs_html = "".join(f'<span class="tag tech-tag">{escape(t)}</span>' for t in techs)

        # Endpoints
        urls = crawl.get("urls", [])
        urls_html = "".join(f'<div class="list-item url-item">{escape(u)}</div>' for u in sorted(urls)[:200])

        # JS Files
        js_files = crawl.get("js_files", [])
        js_html = "".join(f'<div class="list-item">{escape(j)}</div>' for j in sorted(js_files)[:50])

        # Parameters
        params = crawl.get("parameters", [])
        params_html = "".join(f'<span class="tag">{escape(p)}</span>' for p in sorted(params)[:200])

        # Headers table
        headers = recon.get("headers", {})
        interesting = ["Server","X-Powered-By","X-Frame-Options","X-XSS-Protection",
                       "Content-Security-Policy","Strict-Transport-Security","X-Content-Type-Options","Access-Control-Allow-Origin"]
        headers_html = ""
        for h in interesting:
            val = headers.get(h, headers.get(h.lower()))
            if val:
                headers_html += f'<tr><td>{escape(h)}</td><td><code>{escape(str(val)[:80])}</code></td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoRecon Report — {escape(t.get('host',''))}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 14px; line-height: 1.6; }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: var(--surface2); padding: 1px 4px; border-radius: 3px; word-break: break-all; }}

  .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 1px solid var(--border); padding: 40px 48px; }}
  .header h1 {{ font-size: 28px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }}
  .header .subtitle {{ color: var(--text-dim); margin-top: 8px; font-size: 13px; }}
  .meta-row {{ display: flex; gap: 32px; margin-top: 20px; flex-wrap: wrap; }}
  .meta-item {{ display: flex; flex-direction: column; }}
  .meta-label {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }}
  .meta-value {{ font-size: 14px; font-weight: 600; color: var(--text); }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 48px; }}
  .section {{ margin-bottom: 40px; }}
  .section-title {{ font-size: 18px; font-weight: 700; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }}

  .stats-grid {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px 28px; flex: 1; min-width: 120px; text-align: center; }}
  .stat-num {{ font-size: 36px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
  .stat-label {{ font-size: 12px; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat-total {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px 28px; text-align: center; border-top: 3px solid var(--accent); }}

  .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; padding: 14px 18px; background: var(--surface2); flex-wrap: wrap; }}
  .finding-num {{ font-family: 'JetBrains Mono', monospace; color: var(--text-dim); font-size: 12px; min-width: 24px; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-body {{ padding: 16px 18px; display: flex; flex-direction: column; gap: 8px; }}
  .finding-field {{ font-size: 13px; }}
  .finding-field b {{ color: var(--text-dim); margin-right: 8px; font-size: 11px; text-transform: uppercase; }}
  .remediation {{ background: rgba(63,185,80,0.08); border-radius: 4px; padding: 8px 12px; border-left: 2px solid var(--green); }}

  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #000; letter-spacing: 0.5px; }}
  .tag {{ display: inline-block; background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 12px; margin: 2px; }}
  .tech-tag {{ border-color: var(--accent); color: var(--accent); }}
  .finding-source {{ font-size: 11px; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--surface2); padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; color: var(--text-dim); border-bottom: 1px solid var(--border); }}
  td {{ padding: 9px 14px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}

  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  .list-item {{ padding: 6px 14px; border-bottom: 1px solid var(--border); font-size: 12px; font-family: 'JetBrains Mono', monospace; }}
  .list-item:last-child {{ border-bottom: none; }}
  .url-item {{ word-break: break-all; }}
  .scroll-box {{ max-height: 400px; overflow-y: auto; }}

  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  @media(max-width: 900px) {{ .grid-2 {{ grid-template-columns: 1fr; }} .container {{ padding: 20px; }} }}

  .no-findings {{ text-align: center; padding: 48px; color: var(--text-dim); }}
  .no-findings .icon {{ font-size: 48px; margin-bottom: 12px; }}

  nav {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 48px; display: flex; gap: 0; overflow-x: auto; }}
  nav a {{ padding: 14px 18px; color: var(--text-dim); text-decoration: none; font-size: 13px; font-weight: 500; border-bottom: 2px solid transparent; white-space: nowrap; }}
  nav a:hover {{ color: var(--text); }}
  nav a.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 AutoRecon Assessment Report</h1>
  <div class="subtitle">Automated Reconnaissance &amp; Vulnerability Scan</div>
  <div class="meta-row">
    <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{escape(t.get('base_url',''))}</span></div>
    <div class="meta-item"><span class="meta-label">Host</span><span class="meta-value">{escape(t.get('host',''))}</span></div>
    <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{escape(t.get('type',''))}</span></div>
    <div class="meta-item"><span class="meta-label">Scan Start</span><span class="meta-value">{escape(r.get('scan_start',''))}</span></div>
    <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{r.get('scan_duration_seconds',0):.1f}s</span></div>
    <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span></div>
  </div>
</div>

<nav>
  <a href="#summary" class="active">Summary</a>
  <a href="#recon">Reconnaissance</a>
  <a href="#crawl">Crawl Results</a>
  <a href="#vulns">Vulnerabilities</a>
</nav>

<div class="container">

  <!-- SUMMARY -->
  <div class="section" id="summary">
    <div class="section-title">Executive Summary</div>
    <div class="stats-grid">
      <div class="stat-total stat-card">
        <div class="stat-num" style="color:var(--accent)">{total_vulns}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      {stat_cards}
    </div>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-num">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>
      <div class="stat-card"><div class="stat-num">{len(ports)}</div><div class="stat-label">Open Ports</div></div>
      <div class="stat-card"><div class="stat-num">{len(techs)}</div><div class="stat-label">Technologies</div></div>
      <div class="stat-card"><div class="stat-num">{len(urls)}</div><div class="stat-label">URLs Found</div></div>
      <div class="stat-card"><div class="stat-num">{len(js_files)}</div><div class="stat-label">JS Files</div></div>
      <div class="stat-card"><div class="stat-num">{len(params)}</div><div class="stat-label">Parameters</div></div>
    </div>
  </div>

  <!-- RECONNAISSANCE -->
  <div class="section" id="recon">
    <div class="section-title">Reconnaissance Findings</div>

    <!-- Technologies -->
    <div style="margin-bottom:24px">
      <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">DETECTED TECHNOLOGIES</h3>
      <div>{techs_html if techs_html else '<span style="color:var(--text-dim)">None detected</span>'}</div>
    </div>

    <div class="grid-2">
      <!-- HTTP Headers -->
      <div>
        <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">HTTP HEADERS</h3>
        <div class="card">
          <table>
            <thead><tr><th>Header</th><th>Value</th></tr></thead>
            <tbody>{headers_html if headers_html else '<tr><td colspan="2" style="color:var(--text-dim)">No interesting headers</td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <!-- Open Ports -->
      <div>
        <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">OPEN PORTS ({len(ports)})</h3>
        <div class="card">
          <table>
            <thead><tr><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
            <tbody>{ports_html if ports_html else '<tr><td colspan="3" style="color:var(--text-dim)">No open ports found</td></tr>'}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Subdomains -->
    {'<div style="margin-top:24px"><h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">SUBDOMAINS (' + str(len(subdomains)) + ')</h3><div class="card scroll-box">' + sd_html + '</div></div>' if subdomains else ''}
  </div>

  <!-- CRAWL RESULTS -->
  <div class="section" id="crawl">
    <div class="section-title">Crawl &amp; Endpoint Discovery</div>

    <!-- Parameters -->
    <div style="margin-bottom:24px">
      <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">DISCOVERED PARAMETERS ({len(params)})</h3>
      <div>{params_html if params_html else '<span style="color:var(--text-dim)">None found</span>'}</div>
    </div>

    <div class="grid-2">
      <!-- URLs -->
      <div>
        <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">URLS / ENDPOINTS ({len(urls)})</h3>
        <div class="card scroll-box">{urls_html if urls_html else '<div class="list-item" style="color:var(--text-dim)">None found</div>'}</div>
      </div>
      <!-- JS Files -->
      <div>
        <h3 style="margin-bottom:12px;font-size:14px;color:var(--text-dim)">JAVASCRIPT FILES ({len(js_files)})</h3>
        <div class="card scroll-box">{js_html if js_html else '<div class="list-item" style="color:var(--text-dim)">None found</div>'}</div>
      </div>
    </div>
  </div>

  <!-- VULNERABILITIES -->
  <div class="section" id="vulns">
    <div class="section-title">Vulnerability Findings ({len(findings)} total)</div>
    {''.join([findings_html]) if findings_html else '<div class="no-findings"><div class="icon">✅</div><div>No vulnerabilities found — great job!</div></div>'}
  </div>

</div>
<script>
  // Smooth scroll for nav links
  document.querySelectorAll('nav a').forEach(a => {{
    a.addEventListener('click', e => {{
      e.preventDefault();
      document.querySelector(a.getAttribute('href')).scrollIntoView({{behavior:'smooth'}});
      document.querySelectorAll('nav a').forEach(x => x.classList.remove('active'));
      a.classList.add('active');
    }});
  }});
</script>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path
