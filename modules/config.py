"""
modules/config.py - Central configuration object
"""

import os
from datetime import datetime


class Config:
    def __init__(
        self,
        target,
        threads=10,
        depth=2,
        timeout=10,
        delay=0.0,
        stealth=False,
        output_dir="reports",
        html_report=False,
        no_subdomains=False,
        no_ports=False,
    ):
        self.target = target
        self.threads = threads
        self.depth = depth
        self.timeout = timeout
        self.delay = delay if not stealth else max(delay, 1.0)
        self.stealth = stealth
        self.html_report = html_report
        self.no_subdomains = no_subdomains
        self.no_ports = no_ports

        # Build timestamped output dir per scan
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_host = target.host.replace(".", "_").replace(":", "_")
        self.output_dir = os.path.join(output_dir, f"{safe_host}_{ts}")
        os.makedirs(self.output_dir, exist_ok=True)

        # Common headers for requests
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        if stealth:
            self.headers["User-Agent"] = (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/16.0 Safari/605.1.15"
            )
