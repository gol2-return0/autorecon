"""
modules/target.py - Parse and validate scan targets
"""

import re
import socket
from urllib.parse import urlparse


class TargetParser:
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self._parsed = self._parse()

    def _parse(self):
        raw = self.raw

        # Add scheme if missing
        if not raw.startswith(("http://", "https://")):
            # Check if it's an IP
            if self._is_ip(raw.split(":")[0]):
                raw = "http://" + raw
            else:
                raw = "https://" + raw

        parsed = urlparse(raw)
        return parsed

    def _is_ip(self, s):
        try:
            socket.inet_aton(s)
            return True
        except socket.error:
            return False

    @property
    def host(self):
        return self._parsed.hostname or ""

    @property
    def port(self):
        return self._parsed.port

    @property
    def scheme(self):
        return self._parsed.scheme or "https"

    @property
    def path(self):
        return self._parsed.path or "/"

    @property
    def base_url(self):
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port_str}"

    @property
    def target_type(self):
        if self._is_ip(self.host):
            return "IP Address"
        parts = self.host.split(".")
        if len(parts) > 2:
            return "Subdomain"
        return "Domain"

    def is_valid(self):
        if not self.host:
            return False
        # Basic domain/IP validation
        if self._is_ip(self.host):
            return True
        domain_re = re.compile(
            r"^(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )
        return bool(domain_re.match(self.host))

    def to_dict(self):
        return {
            "raw": self.raw,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "base_url": self.base_url,
            "type": self.target_type,
        }
