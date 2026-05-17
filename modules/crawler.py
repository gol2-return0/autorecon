"""
modules/crawler.py - Recursive web crawler with endpoint & parameter discovery
"""

import re
import time
import json
import concurrent.futures
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urldefrag

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from modules.console import Console


# Regex patterns
RE_JS_FILE      = re.compile(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', re.I)
RE_HREF         = re.compile(r'href=["\']([^"\']+)["\']', re.I)
RE_ACTION       = re.compile(r'action=["\']([^"\']+)["\']', re.I)
RE_ENDPOINT_JS  = re.compile(r'["\'](/[a-zA-Z0-9_/.-]+(?:\?[^"\']*)?)["\']')
RE_API_ENDPOINT = re.compile(r'(?:fetch|axios|http)\s*\(\s*["\']([^"\']+)["\']', re.I)
RE_PARAM        = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=')
RE_EMAIL        = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_COMMENT_URL  = re.compile(r'<!--.*?(https?://[^\s>"]+).*?-->', re.DOTALL)
RE_FORM_INPUT   = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
RE_INLINE_JS    = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.I)


class Crawler:
    def __init__(self, config):
        self.config = config
        self.target = config.target
        self.base_url = config.target.base_url
        self.host = config.target.host

        self.visited = set()
        self.queued  = set()
        self.urls    = set()
        self.js_files = set()
        self.parameters = set()
        self.forms   = []
        self.emails  = set()
        self.api_endpoints = set()
        self.comments = []

        self._session = None

    def _get_session(self):
        if self._session is None and HAS_REQUESTS:
            import requests
            s = requests.Session()
            s.headers.update(self.config.headers)
            s.verify = False
            self._session = s
        return self._session

    def run(self):
        if not HAS_REQUESTS:
            Console.warning("requests not installed; skipping crawl")
            return self._empty_result()

        Console.subsection("Recursive Crawling")
        Console.info(f"Start URL  : {self.base_url}")
        Console.info(f"Max depth  : {self.config.depth}")
        Console.info(f"Threads    : {self.config.threads}")

        # BFS crawl queue: (url, depth)
        queue = deque([(self.base_url, 0)])
        self.queued.add(self.base_url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            while queue:
                batch = []
                # Grab up to threads-many items
                while queue and len(batch) < self.config.threads:
                    batch.append(queue.popleft())

                futures = {
                    executor.submit(self._crawl_page, url, depth): (url, depth)
                    for url, depth in batch
                    if url not in self.visited
                }

                for future in concurrent.futures.as_completed(futures):
                    url, depth = futures[future]
                    self.visited.add(url)
                    try:
                        new_links = future.result()
                    except Exception:
                        new_links = []

                    # Enqueue new links within depth limit
                    if depth < self.config.depth:
                        for link in new_links:
                            if link not in self.queued and self._is_in_scope(link):
                                self.queued.add(link)
                                queue.append((link, depth + 1))

                    if self.config.stealth:
                        time.sleep(self.config.delay)

        Console.info(f"Pages crawled    : {len(self.visited)}")
        Console.info(f"URLs discovered  : {len(self.urls)}")
        Console.info(f"JS files found   : {len(self.js_files)}")
        Console.info(f"Parameters found : {len(self.parameters)}")
        Console.info(f"Forms found      : {len(self.forms)}")
        Console.info(f"API endpoints    : {len(self.api_endpoints)}")

        # Also analyze JS files for more endpoints
        self._analyze_js_files()

        return {
            "urls": sorted(self.urls),
            "js_files": sorted(self.js_files),
            "parameters": sorted(self.parameters),
            "forms": self.forms,
            "emails": sorted(self.emails),
            "api_endpoints": sorted(self.api_endpoints),
            "comments": self.comments[:20],
            "pages_crawled": len(self.visited),
        }

    def _crawl_page(self, url, depth):
        """Fetch a page, extract all links and interesting data."""
        session = self._get_session()
        if session is None:
            return []

        try:
            resp = session.get(url, timeout=self.config.timeout, allow_redirects=True)
        except Exception:
            return []

        # Track this URL
        self.urls.add(url)

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type and "javascript" not in content_type:
            return []

        body = resp.text
        links = set()

        # ── Extract hrefs
        for href in RE_HREF.findall(body):
            full = self._resolve(url, href)
            if full:
                links.add(full)
                self.urls.add(full)

        # ── Extract form actions
        for action in RE_ACTION.findall(body):
            full = self._resolve(url, action)
            if full:
                links.add(full)
                self.urls.add(full)

        # ── Extract JS files
        for src in RE_JS_FILE.findall(body):
            full = self._resolve(url, src)
            if full:
                self.js_files.add(full)

        # ── Extract parameters from URLs
        for found_url in list(links) + [url]:
            params = RE_PARAM.findall(found_url)
            self.parameters.update(params)

        # ── Extract forms and inputs
        self._extract_forms(body, url)

        # ── Extract emails
        self.emails.update(RE_EMAIL.findall(body))

        # ── Extract HTML comments with URLs
        for comment_url in RE_COMMENT_URL.findall(body):
            self.comments.append({"url": url, "found": comment_url})

        # ── Extract API endpoints from inline JS
        for js_block in RE_INLINE_JS.findall(body):
            for endpoint in RE_API_ENDPOINT.findall(js_block):
                full = self._resolve(url, endpoint)
                if full:
                    self.api_endpoints.add(full)
            # Extract path-like strings
            for path in RE_ENDPOINT_JS.findall(js_block):
                if len(path) > 2 and not path.startswith("//"):
                    full = self._resolve(url, path)
                    if full and self._is_in_scope(full):
                        self.urls.add(full)

        in_scope = [l for l in links if self._is_in_scope(l)]
        Console.info(f"[d{depth}] {url[:70]:<70} → {len(in_scope)} links")

        return in_scope

    def _extract_forms(self, body, page_url):
        """Extract form details including method, action, and inputs."""
        form_re = re.compile(r'<form([^>]*)>(.*?)</form>', re.DOTALL | re.I)
        method_re = re.compile(r'method=["\']([^"\']+)["\']', re.I)
        action_re = re.compile(r'action=["\']([^"\']+)["\']', re.I)
        input_re  = re.compile(r'<input([^>]*)>', re.I)
        name_re   = re.compile(r'name=["\']([^"\']+)["\']', re.I)
        type_re   = re.compile(r'type=["\']([^"\']+)["\']', re.I)

        for form_attrs, form_body in form_re.findall(body):
            method = (method_re.search(form_attrs) or type('', (), {'group': lambda s, i="GET": i})()).group(1).upper()
            action_m = action_re.search(form_attrs)
            action = self._resolve(page_url, action_m.group(1)) if action_m else page_url

            inputs = []
            for inp_attrs in input_re.findall(form_body):
                name_m = name_re.search(inp_attrs)
                type_m = type_re.search(inp_attrs)
                if name_m:
                    inputs.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                    })
                    self.parameters.add(name_m.group(1))

            if action:
                self.forms.append({
                    "page": page_url,
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                })

    def _analyze_js_files(self):
        """Fetch and analyze collected JS files for API endpoints."""
        if not self.js_files:
            return

        Console.subsection("JavaScript File Analysis")
        Console.info(f"Analyzing {len(self.js_files)} JS files...")

        session = self._get_session()
        if not session:
            return

        def analyze_js(js_url):
            try:
                resp = session.get(js_url, timeout=self.config.timeout)
                found = []
                for endpoint in RE_API_ENDPOINT.findall(resp.text):
                    full = self._resolve(js_url, endpoint)
                    if full:
                        found.append(full)
                for path in RE_ENDPOINT_JS.findall(resp.text):
                    if len(path) > 3 and path.startswith("/") and not path.startswith("//"):
                        full = self._resolve(self.base_url, path)
                        if full and self._is_in_scope(full):
                            found.append(full)
                return js_url, found
            except Exception:
                return js_url, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(analyze_js, js) for js in list(self.js_files)[:50]]
            for future in concurrent.futures.as_completed(futures):
                js_url, endpoints = future.result()
                if endpoints:
                    Console.success(f"JS: {js_url[:60]} → {len(endpoints)} endpoints")
                    self.api_endpoints.update(endpoints)
                    self.urls.update(endpoints)

    def _resolve(self, base, href):
        """Resolve a URL relative to base, return None if out of scope or invalid."""
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        try:
            full, _ = urldefrag(urljoin(base, href))
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                return None
            return full
        except Exception:
            return None

    def _is_in_scope(self, url):
        """Only crawl URLs belonging to the same host."""
        try:
            parsed = urlparse(url)
            return parsed.hostname == self.host or (
                parsed.hostname and parsed.hostname.endswith("." + self.host)
            )
        except Exception:
            return False

    def _empty_result(self):
        return {
            "urls": [], "js_files": [], "parameters": [],
            "forms": [], "emails": [], "api_endpoints": [],
            "comments": [], "pages_crawled": 0,
        }
