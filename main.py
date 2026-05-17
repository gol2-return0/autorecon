#!/usr/bin/env python3
"""
AutoRecon - Automated Reconnaissance & Vulnerability Scanner
CLI entry point
"""

import argparse
import sys
import os
import time
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.console import Console
from modules.target import TargetParser
from modules.recon import ReconEngine
from modules.crawler import Crawler
from modules.vuln_scanner import VulnScanner
from modules.report_generator import ReportGenerator
from modules.config import Config


BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗║
║   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝║
║   ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║     ║
║   ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║     ║
║   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╗║
║   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝║
║                                                               ║
║         Automated Reconnaissance & Vulnerability Scanner      ║
║                        Version 1.0.0                         ║
╚═══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="autorecon",
        description="AutoRecon - Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t https://example.com --full
  python main.py -t 192.168.1.1 --no-vuln --output /tmp/reports
  python main.py -t example.com --threads 20 --depth 3 --html
  python main.py -t example.com --stealth --timeout 30
        """
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain, subdomain, URL, or IP address"
    )

    # Scan modes
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--full",
        action="store_true",
        help="Run full scan (recon + crawl + vuln scan)"
    )
    scan_group.add_argument(
        "--recon-only",
        action="store_true",
        help="Run reconnaissance only (no crawling or vuln scan)"
    )
    scan_group.add_argument(
        "--no-vuln",
        action="store_true",
        help="Skip vulnerability scanning"
    )
    scan_group.add_argument(
        "--no-crawl",
        action="store_true",
        help="Skip web crawling"
    )
    scan_group.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Skip subdomain enumeration"
    )
    scan_group.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip port scanning"
    )

    # Crawler options
    crawl_group = parser.add_argument_group("Crawler Options")
    crawl_group.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Crawl depth (default: 2)"
    )
    crawl_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    # Stealth options
    stealth_group = parser.add_argument_group("Stealth Options")
    stealth_group.add_argument(
        "--stealth",
        action="store_true",
        help="Enable stealth mode (rate limiting, random delays)"
    )
    stealth_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    stealth_group.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (default: 0)"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        default="reports",
        help="Output directory for reports (default: reports/)"
    )
    output_group.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report"
    )
    output_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and minimal output"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    return parser.parse_args()


def confirm_authorization(target, quiet=False):
    """Require user to confirm they are authorized to scan the target."""
    if quiet:
        return True

    Console.warning(f"\n⚠  LEGAL & ETHICAL NOTICE")
    print("  You must have explicit authorization to scan this target.")
    print(f"  Target: {target}")
    print("  Unauthorized scanning is illegal and unethical.\n")

    try:
        answer = input("  Do you confirm you are authorized to scan this target? [y/N]: ").strip().lower()
        if answer != 'y':
            Console.error("Scan aborted. Authorization not confirmed.")
            sys.exit(0)
        print()
    except (KeyboardInterrupt, EOFError):
        print()
        Console.error("\nScan aborted.")
        sys.exit(0)

    return True


def main():
    args = parse_args()

    # Setup console
    Console.setup(no_color=args.no_color)

    # Print banner
    if not args.quiet:
        Console.print_raw(BANNER, color="cyan")
        Console.print_raw(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", color="dim")

    # Authorization check
    confirm_authorization(args.target, args.quiet)

    # Parse and validate target
    Console.section("Target Validation")
    target = TargetParser(args.target)
    if not target.is_valid():
        Console.error(f"Invalid target: {args.target}")
        sys.exit(1)

    Console.success(f"Target   : {target.raw}")
    Console.info(f"Type     : {target.target_type}")
    Console.info(f"Host     : {target.host}")
    Console.info(f"Scheme   : {target.scheme}")
    Console.info(f"Base URL : {target.base_url}")

    # Build config
    config = Config(
        target=target,
        threads=args.threads,
        depth=args.depth,
        timeout=args.timeout,
        delay=args.delay,
        stealth=args.stealth,
        output_dir=args.output,
        html_report=args.html,
        no_subdomains=args.no_subdomains,
        no_ports=args.no_ports,
    )

    # Ensure output directory
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    scan_start = time.time()
    results = {
        "target": target.to_dict(),
        "scan_start": datetime.now().isoformat(),
        "recon": {},
        "crawl": {},
        "vuln": {},
    }

    # ─── RECONNAISSANCE ────────────────────────────────────────────────────────
    if not (args.no_crawl and args.no_vuln) or args.recon_only or True:
        Console.section("Reconnaissance")
        recon = ReconEngine(config)
        recon_data = recon.run()
        results["recon"] = recon_data

    # ─── CRAWLING ──────────────────────────────────────────────────────────────
    crawl_data = {}
    if not args.no_crawl and not args.recon_only:
        Console.section("Web Crawling & Endpoint Discovery")
        crawler = Crawler(config)
        crawl_data = crawler.run()
        results["crawl"] = crawl_data

    # ─── VULNERABILITY SCANNING ────────────────────────────────────────────────
    vuln_data = {}
    if not args.no_vuln and not args.recon_only:
        Console.section("Vulnerability Scanning")
        vuln_scanner = VulnScanner(config)
        vuln_data = vuln_scanner.run(crawl_data)
        results["vuln"] = vuln_data

    # ─── REPORT GENERATION ─────────────────────────────────────────────────────
    Console.section("Report Generation")
    scan_duration = time.time() - scan_start
    results["scan_end"] = datetime.now().isoformat()
    results["scan_duration_seconds"] = round(scan_duration, 2)

    reporter = ReportGenerator(config, results)
    json_path = reporter.generate_json()
    Console.success(f"JSON report saved: {json_path}")

    txt_path = reporter.generate_text()
    Console.success(f"Text report saved: {txt_path}")

    if args.html:
        html_path = reporter.generate_html()
        Console.success(f"HTML report saved: {html_path}")

    # ─── SUMMARY ───────────────────────────────────────────────────────────────
    Console.section("Scan Summary")
    Console.info(f"Duration       : {scan_duration:.1f}s")
    Console.info(f"Subdomains     : {len(results['recon'].get('subdomains', []))}")
    Console.info(f"Open Ports     : {len(results['recon'].get('ports', []))}")
    Console.info(f"Technologies   : {len(results['recon'].get('technologies', []))}")
    Console.info(f"Endpoints      : {len(results['crawl'].get('urls', []))}")
    Console.info(f"JS Files       : {len(results['crawl'].get('js_files', []))}")
    Console.info(f"Parameters     : {len(results['crawl'].get('parameters', []))}")

    total_vulns = len(results["vuln"].get("findings", []))
    critical = sum(1 for v in results["vuln"].get("findings", []) if v.get("severity","").lower() == "critical")
    high = sum(1 for v in results["vuln"].get("findings", []) if v.get("severity","").lower() == "high")
    medium = sum(1 for v in results["vuln"].get("findings", []) if v.get("severity","").lower() == "medium")

    Console.info(f"Vulnerabilities: {total_vulns} total")
    if total_vulns > 0:
        if critical: Console.error(f"  ├─ Critical: {critical}")
        if high:     Console.warning(f"  ├─ High    : {high}")
        if medium:   Console.info(f"  └─ Medium  : {medium}")

    Console.print_raw(f"\n  ✔  Scan complete. Reports saved to: {config.output_dir}/\n", color="green")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Console.error("\n\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        Console.error(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
