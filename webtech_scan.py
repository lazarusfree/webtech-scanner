#!/usr/bin/env python3
"""
webtech_scan.py - Async web technology scanner with JA3S + color output.
For authorized security testing / responsible disclosure only.
"""

import re
import ssl
import sys#!/usr/bin/env python3
"""
webtech_scan_v2.py - Async web technology scanner with JA3S + color output.
For authorized security testing / responsible disclosure only.

Changes from v1:
  * JA3S: correct SNI/supported_groups, key_share (no HelloRetryRequest),
    hand-rolled ServerHello parser (no scapy), standard legacy_version.
  * Probes run against the origin of the FINAL url, with a soft-404 baseline
    and per-path content validators. Confidence level on every finding.
  * Cookies checked per cookie, across the whole redirect chain.
  * Certificate parsed from DER (needs `cryptography`; optional).
  * Legacy TLS (1.0/1.1) detected with pinned-version probes.
  * Honest User-Agent by default; --verify, --user-agent, --delay flags.
"""

import re
import ssl
import warnings
import sys
import json
import uuid
import socket
import asyncio
import argparse
import hashlib
import os
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

USER_AGENT = "webtech-scan/2.0 (authorized security testing)"

CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


# ======================================================================
# COLORS
# ======================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls):
        for k in dir(cls):
            if k.isupper():
                setattr(cls, k, "")


def c(text, *styles):
    return "".join(styles) + str(text) + C.RESET


# ======================================================================
# TLS / JA3S (no scapy)
# ======================================================================
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


def _ext(etype, body):
    return etype.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def build_client_hello(host):
    """
    Fixed, documented ClientHello. JA3S depends on the ClientHello, so hashes
    are only comparable between scans that use THIS hello.
    """
    sni = host.encode("idna")
    sni_entry = b"\x00" + len(sni).to_bytes(2, "big") + sni          # type=host_name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry

    key_share_entry = b"\x00\x1d" + (32).to_bytes(2, "big") + os.urandom(32)  # x25519
    key_share = len(key_share_entry).to_bytes(2, "big") + key_share_entry

    exts = (
        _ext(0x0000, sni_list)                                       # server_name
        + _ext(0x000a, b"\x00\x04\x00\x1d\x00\x17")                  # groups: x25519, secp256r1
        + _ext(0x000b, b"\x01\x00")                                  # ec_point_formats
        + _ext(0x000d, b"\x00\x06\x04\x03\x08\x04\x04\x01")          # sig algs
        + _ext(0x002b, b"\x04\x03\x04\x03\x03")                      # supported_versions 1.3,1.2
        + _ext(0x0033, key_share)                                    # key_share
    )
    cipher_suites = (
        b"\x13\x01\x13\x02\x13\x03"
        b"\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
        b"\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"
    )
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x00"
        + len(cipher_suites).to_bytes(2, "big") + cipher_suites
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big") + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading TLS record")
        buf += chunk
    return buf


def read_server_hello(sock, max_records=8):
    """Read TLS records until a full ServerHello handshake message is assembled."""
    hs = b""
    for _ in range(max_records):
        hdr = _recv_exact(sock, 5)
        rtype, length = hdr[0], int.from_bytes(hdr[3:5], "big")
        body = _recv_exact(sock, length)
        if rtype == 0x15:  # alert
            level, desc = (body[0], body[1]) if len(body) >= 2 else (0, 0)
            raise RuntimeError(f"server sent TLS alert level={level} desc={desc}")
        if rtype != 0x16:
            continue
        hs += body
        if len(hs) >= 4:
            if hs[0] != 2:
                raise RuntimeError(f"first handshake message type {hs[0]}, expected ServerHello")
            need = 4 + int.from_bytes(hs[1:4], "big")
            if len(hs) >= need:
                return hs[:need]
    raise RuntimeError("ServerHello not received")


def parse_server_hello(hs):
    """hs = full handshake message incl. 4-byte header. -> dict."""
    m = hs[4:]
    version = int.from_bytes(m[0:2], "big")
    random = m[2:34]
    sid_len = m[34]
    p = 35 + sid_len
    cipher = int.from_bytes(m[p:p + 2], "big")
    p += 3  # cipher + compression
    exts = []
    ext_data = {}
    if p + 2 <= len(m):
        total = int.from_bytes(m[p:p + 2], "big")
        p += 2
        end = min(p + total, len(m))
        while p + 4 <= end:
            etype = int.from_bytes(m[p:p + 2], "big")
            elen = int.from_bytes(m[p + 2:p + 4], "big")
            exts.append(etype)
            ext_data[etype] = m[p + 4:p + 4 + elen]
            p += 4 + elen
    negotiated = version
    if 0x002b in ext_data and len(ext_data[0x002b]) == 2:
        negotiated = int.from_bytes(ext_data[0x002b], "big")
    return {
        "legacy_version": version,
        "negotiated_version": negotiated,
        "cipher": cipher,
        "extensions": exts,
        "is_hrr": random == HRR_RANDOM,
    }


def compute_ja3s(legacy_version, cipher, extensions):
    """JA3S = MD5("Version,Cipher,Ext-Ext-...") using ServerHello legacy_version."""
    s = f"{legacy_version},{cipher},{'-'.join(str(e) for e in extensions)}"
    return s, hashlib.md5(s.encode()).hexdigest()


TLS_VERSION_NAMES = {
    0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}


# ======================================================================
# HTML parsing (stdlib)
# ======================================================================
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta = []        # list of dict(attrs)
        self.assets = []      # script src / link href
        self.comments = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            self.meta.append(a)
        elif tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.assets.append(a["href"])

    def handle_comment(self, data):
        self.comments.append(data)


HTML_SIGNATURES = {
    "CMS": {
        "WordPress": [r"/wp-content/", r"/wp-includes/"],
        "Drupal": [r"drupal\.js", r"sites/default/files"],
        "Joomla": [r"/media/system/js/"],
        "Magento": [r"/skin/frontend/", r"/static/version\d+/frontend/"],
        "Shopify": [r"cdn\.shopify\.com"],
    },
    "JavaScript Framework": {
        "React": [r"data-reactroot", r"react-dom"],
        "Angular": [r"ng-version="],
        "Vue.js": [r"data-v-[0-9a-f]{8}", r"__vue__"],
        "Next.js": [r"__next_data__", r"/_next/static/"],
        "Nuxt.js": [r"__nuxt", r"/_nuxt/"],
        "Svelte": [r"svelte-[a-z0-9]{4,}"],
    },
    "Analytics/Marketing": {
        "Google Analytics": [r"google-analytics\.com/(?:analytics|ga)\.js", r"gtag/js"],
        "Google Tag Manager": [r"googletagmanager\.com"],
        "Facebook Pixel": [r"connect\.facebook\.net"],
    },
}

# library name -> filename/path hint used on <script>/<link> URLs
LIB_ASSETS = {
    "jQuery": r"jquery",
    "Bootstrap": r"bootstrap",
    "Vue.js": r"(?<![a-z])vue",
    "AngularJS": r"angular(?:\.min)?\.js|angularjs",
    "Font Awesome": r"font-?awesome",
}
VERSION_RE = re.compile(r"(?<![\d.])(\d+\.\d+(?:\.\d+)?)(?![\d])")


# ======================================================================
# Path probes: (path, label, validator(status, text, headers) -> bool, confidence)
# ======================================================================
def _json_has(key):
    def v(status, text, headers):
        if status != 200:
            return False
        try:
            return key in json.loads(text)
        except Exception:
            return False
    return v


PROBES = [
    ("/wp-login.php", "WordPress",
     lambda s, t, h: s == 200 and ("user_login" in t or "wp-submit" in t), "high"),
    ("/wp-admin/", "WordPress",
     lambda s, t, h: s in (301, 302) and "wp-login" in h.get("location", ""), "high"),
    ("/administrator/", "Joomla",
     lambda s, t, h: s == 200 and "joomla" in t.lower(), "medium"),
    ("/user/login", "Drupal",
     lambda s, t, h: s == 200 and "drupal" in t.lower(), "medium"),
    ("/.git/HEAD", "Exposed .git",
     lambda s, t, h: s == 200 and t.lstrip().startswith("ref:"), "high"),
    ("/.env", "Exposed .env (CRITICAL)",
     lambda s, t, h: s == 200 and re.search(r"^[A-Z][A-Z0-9_]*\s*=", t, re.M) is not None, "high"),
    ("/server-status", "Apache server-status exposed",
     lambda s, t, h: s == 200 and "Apache Server Status" in t, "high"),
    ("/phpinfo.php", "phpinfo exposed",
     lambda s, t, h: s == 200 and "PHP Version" in t, "high"),
    ("/actuator", "Spring Boot Actuator", _json_has("_links"), "high"),
    ("/actuator/env", "Spring Boot Actuator env (CRITICAL)", _json_has("propertySources"), "high"),
    ("/robots.txt", "robots.txt",
     lambda s, t, h: s == 200 and re.search(r"(?i)^\s*(user-agent|disallow|sitemap)\s*:", t, re.M) is not None, "high"),
    ("/sitemap.xml", "sitemap.xml",
     lambda s, t, h: s == 200 and ("<urlset" in t or "<sitemapindex" in t), "high"),
    ("/readme.html", "WordPress readme",
     lambda s, t, h: s == 200 and "wordpress" in t.lower(), "medium"),
]


# ======================================================================
# SCANNER
# ======================================================================
class WebTechScanner:
    def __init__(self, url, timeout=10, concurrency=10, verify=False,
                 user_agent=USER_AGENT, delay=0.0, do_paths=True, do_ja3s=True):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.verify = verify
        self.user_agent = user_agent
        self.delay = delay
        self.do_paths = do_paths
        self.do_ja3s = do_ja3s
        self.sem = asyncio.Semaphore(concurrency)
        self.findings = {}    # category -> tech -> {evidence: confidence}
        self.version_hits = {}
        self.tls_info = {}
        self.ja3s_info = {}
        self.origin = None

    # ---------- findings ----------
    def _add(self, category, tech, evidence, conf="medium"):
        ev = self.findings.setdefault(category, {}).setdefault(tech, {})
        if CONF_ORDER[conf] >= CONF_ORDER.get(ev.get(evidence, "low"), 0):
            ev[evidence] = conf

    def _add_version(self, tech, version, evidence, conf="medium"):
        self.version_hits.setdefault(tech, set()).add(version)
        self._add("Version", f"{tech} {version}", evidence, conf)

    # ==================================================================
    # HEADERS
    # ==================================================================
    def check_headers(self, url, resp):
        where = f"GET {url} → response headers"
        h = {k.lower(): v for k, v in resp.headers.items()}

        if "server" in h:
            server = h["server"]
            self._add("Server", server, where, "high")
            for m in re.finditer(r"([A-Za-z][\w-]*)/(\d+(?:\.\d+)*)", server):
                self._add_version(m.group(1), m.group(2),
                                  f"{where} → Server: {server}", "high")

        if "x-powered-by" in h:
            xpb = h["x-powered-by"]
            self._add("Framework", xpb, where, "high")
            m = re.match(r"\s*([A-Za-z][\w.-]*?)[ /]v?(\d+(?:\.\d+)*)", xpb)
            if m:
                self._add_version(m.group(1), m.group(2),
                                  f"{where} → X-Powered-By: {xpb}", "high")

        for hdr, tech in {
            "x-aspnet-version": "ASP.NET",
            "x-aspnetmvc-version": "ASP.NET MVC",
            "x-generator": "Generator",
        }.items():
            if hdr in h:
                self._add_version(tech, h[hdr], f"{where} → {hdr}: {h[hdr]}", "high")

        for key, tech in {
            "cf-ray": "Cloudflare",
            "x-akamai-transformed": "Akamai",
            "x-cache": "CDN (generic)",
            "x-amz-cf-id": "AWS CloudFront",
            "x-fastly-request-id": "Fastly",
            "x-sucuri-id": "Sucuri",
            "x-azure-ref": "Azure",
            "x-vercel-id": "Vercel",
        }.items():
            if key in h:
                self._add("CDN/Proxy", tech, f"{where} → {key}: {h[key]}", "high")

        if url.startswith("https"):
            for sec, label in [
                ("strict-transport-security", "HSTS"),
                ("content-security-policy", "CSP"),
                ("x-frame-options", "X-Frame-Options"),
                ("x-content-type-options", "X-Content-Type-Options"),
                ("referrer-policy", "Referrer-Policy"),
                ("permissions-policy", "Permissions-Policy"),
            ]:
                if sec not in h:
                    self._add("Missing Security Header", label,
                              f"{where} → {sec} absent", "high")

    # ==================================================================
    # COOKIES (per cookie, across redirect chain)
    # ==================================================================
    COOKIE_MAP = {
        "PHPSESSID": "PHP", "JSESSIONID": "Java (Servlet)",
        "ASP.NET_SessionId": "ASP.NET", "laravel_session": "Laravel",
        "ci_session": "CodeIgniter", "sessionid": "Django (probable)",
        "csrftoken": "Django (probable)", "wordpress_": "WordPress",
        "wp-settings": "WordPress", "_shopify_s": "Shopify",
        "AWSALB": "AWS ALB", "connect.sid": "Express (Node.js)",
        "_rails": "Ruby on Rails", "_session_id": "Ruby on Rails (probable)",
    }

    def check_cookies(self, url, resp):
        https = url.startswith("https")
        for raw in resp.headers.get_list("set-cookie"):
            parts = [p.strip() for p in raw.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0]
            attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
            where = f"GET {url} → Set-Cookie: {name}"

            for needle, tech in self.COOKIE_MAP.items():
                if name.lower().startswith(needle.lower()):
                    self._add("Framework", tech, f"{where} (cookie name)", "medium")
            if "httponly" not in attrs:
                self._add("Cookie Issue", f"{name}: missing HttpOnly", where, "high")
            if "secure" not in attrs and https:
                self._add("Cookie Issue", f"{name}: missing Secure", where, "high")
            if "samesite" not in attrs:
                self._add("Cookie Issue", f"{name}: missing SameSite", where, "high")

    # ==================================================================
    # HTML
    # ==================================================================
    def check_html(self, url, body):
        where = f"GET {url} → body"
        body_l = body.lower()
        parser = PageParser()
        try:
            parser.feed(body)
        except Exception:
            pass

        for category, techs in HTML_SIGNATURES.items():
            for tech, regexes in techs.items():
                for rx in regexes:
                    if re.search(rx, body_l):
                        self._add(category, tech, f"{where} → /{rx}/", "medium")
                        break

        # Angular exposes version in ng-version attribute
        m = re.search(r'ng-version="([\d.]+)"', body_l)
        if m:
            self._add_version("Angular", m.group(1), f"{where} → ng-version", "high")

        # Library versions from asset URLs (handles ?ver= and multiple copies)
        for src in parser.assets:
            s = src.lower()
            for lib, hint in LIB_ASSETS.items():
                if re.search(hint, s):
                    self._add("Library", lib, f"{where} → asset {src[:100]}", "medium")
                    for vm in VERSION_RE.finditer(s):
                        self._add_version(lib, vm.group(1),
                                          f"{where} → asset {src[:100]}", "medium")
                        break

        # <meta name=generator>, any attribute order, original casing
        for a in parser.meta:
            if a.get("name", "").lower() == "generator" and a.get("content"):
                content = a["content"]
                self._add("Generator", content, f"{where} → <meta generator>", "high")
                m = re.match(r"\s*([A-Za-z][\w .-]*?)\s+v?(\d+(?:\.\d+)+)", content)
                if m:
                    self._add_version(m.group(1).strip(), m.group(2),
                                      f"{where} → meta generator", "high")

        # HTML comments: low confidence, skip IE conditionals and copyright noise
        for comment in parser.comments:
            cs = comment.strip()
            if len(cs) > 200 or cs.lower().startswith(("[if", "<![endif", "copyright")):
                continue
            m = re.search(r"\b([A-Za-z][\w.-]{2,})\s+(?:v|version\s+)?(\d+\.\d+(?:\.\d+)?)\b", cs, re.I)
            if m and m.group(1).lower() not in ("copyright", "version", "since", "year"):
                self._add_version(m.group(1), m.group(2),
                                  f"{where} → HTML comment: <!--{cs[:80]}-->", "low")

    # ==================================================================
    # PATH PROBING (soft-404 baseline + validators)
    # ==================================================================
    async def _fetch_small(self, client, target):
        """GET without following redirects, reading at most 8 KiB."""
        async with self.sem:
            if self.delay:
                await asyncio.sleep(self.delay)
            try:
                async with client.stream("GET", target, follow_redirects=False) as r:
                    data = b""
                    async for chunk in r.aiter_bytes():
                        data += chunk
                        if len(data) >= 8192:
                            break
                    return r.status_code, data.decode("utf-8", "replace"), dict(
                        (k.lower(), v) for k, v in r.headers.items())
            except httpx.HTTPError:
                return None

    async def check_paths(self, client):
        base = self.origin
        # Baseline: what does this server say for something that can't exist?
        junk = await self._fetch_small(client, f"{base}/{uuid.uuid4().hex}")
        base_status = junk[0] if junk else None
        base_hash = hashlib.sha1(junk[1].encode()).hexdigest() if junk else None
        if base_status in (200, 401, 403):
            self._add("Notes", f"Catch-all behaviour: random path returns HTTP {base_status}",
                      f"GET {base}/<random> → HTTP {base_status} (soft-404 / WAF / SPA)", "high")

        async def probe(path, label, validator, conf):
            target = base + path
            res = await self._fetch_small(client, target)
            if not res:
                return
            status, text, headers = res
            same_as_baseline = (
                status == base_status
                and hashlib.sha1(text.encode()).hexdigest() == base_hash
            )
            if validator(status, text, headers) and not same_as_baseline:
                self._add("Path Found", label, f"GET {target} → HTTP {status}", conf)
                if "readme" in path.lower():
                    m = re.search(r"Version\s+([\d.]+)", text, re.I)
                    if m:
                        self._add_version("WordPress", m.group(1),
                                          f"GET {target} → 'Version {m.group(1)}'", "medium")
            elif status in (401, 403) and status != base_status and path != "/robots.txt":
                self._add("Path Restricted", label,
                          f"GET {target} → HTTP {status} (exists but restricted, or WAF rule)",
                          "low")

        await asyncio.gather(*(probe(*p) for p in PROBES))

    # ==================================================================
    # TLS metadata
    # ==================================================================
    def tls_fingerprint(self, host, port=443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    der = ssock.getpeercert(binary_form=True)

            info = {
                "tls_version": version,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "cert_sha256": hashlib.sha256(der).hexdigest() if der else None,
            }
            where = f"TLS handshake {host}:{port}"
            self._add("TLS", f"Version {version}", where, "high")
            if cipher:
                self._add("TLS", f"Cipher {cipher[0]} ({cipher[2]} bits)", where, "high")

            if der and HAVE_CRYPTO:
                cert = x509.load_der_x509_certificate(der)
                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["not_before"] = cert.not_valid_before_utc.isoformat() \
                    if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
                info["not_after"] = cert.not_valid_after_utc.isoformat() \
                    if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    info["san"] = san.value.get_values_for_type(x509.DNSName)[:20]
                except Exception:
                    pass
                self._add("TLS", f"Cert issuer: {info['issuer']}",
                          f"{where} → cert SHA256 {info['cert_sha256'][:16]}…", "high")
                if cert.issuer == cert.subject:
                    self._add("TLS Issue", "Self-signed certificate", where, "high")
            elif der and not HAVE_CRYPTO:
                info["note"] = "pip install cryptography for subject/issuer/expiry"
            self.tls_info = info
        except Exception as e:
            self._add("TLS", f"Error: {type(e).__name__}", f"{host}:{port} → {e}", "low")

        self._probe_legacy_tls(host, port)

    def _probe_legacy_tls(self, host, port):
        """Pinned-version handshakes: report only if the server accepts them."""
        for name, ver in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
            except (ssl.SSLError, ValueError):
                self._add("Notes", f"Could not test {name}", "local OpenSSL has it disabled", "low")
                continue
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as s:
                        if s.version() == name:
                            self._add("TLS Issue", f"Server accepts deprecated {name}",
                                      f"pinned {name} handshake to {host}:{port} succeeded", "high")
            except (ssl.SSLError, OSError):
                pass

    # ==================================================================
    # JA3S
    # ==================================================================
    def ja3s_fingerprint(self, host, port=443):
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(build_client_hello(host))
                hs = read_server_hello(sock)
            sh = parse_server_hello(hs)
            ja3s_str, md5 = compute_ja3s(sh["legacy_version"], sh["cipher"], sh["extensions"])
            self.ja3s_info = {
                "ja3s_string": ja3s_str,
                "ja3s_hash": md5,
                "legacy_version": f"0x{sh['legacy_version']:04x}",
                "negotiated": TLS_VERSION_NAMES.get(sh["negotiated_version"],
                                                    f"0x{sh['negotiated_version']:04x}"),
                "cipher_suite": f"0x{sh['cipher']:04x}",
                "extensions": sh["extensions"],
                "hello_retry_request": sh["is_hrr"],
                "note": "Valid only for this tool's fixed ClientHello",
            }
            where = f"JA3S handshake {host}:{port} → ServerHello"
            conf = "low" if sh["is_hrr"] else "high"
            self._add("JA3S", md5, where, conf)
            self._add("JA3S", f"raw: {ja3s_str}", where, conf)
        except Exception as e:
            self.ja3s_info = {"error": f"{type(e).__name__}: {e}"}

    # ==================================================================
    # MAIN
    # ==================================================================
    async def run(self):
        print(c(f"[*] Scanning {self.url}", C.CYAN, C.BOLD))

        async with httpx.AsyncClient(
            headers={"User-Agent": self.user_agent},
            timeout=self.timeout,
            verify=self.verify,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=self.concurrency),
        ) as client:
            try:
                resp = await client.get(self.url)
            except httpx.HTTPError as e:
                print(c(f"[!] Connection failed: {e}", C.RED))
                return None

            final_url = str(resp.url)
            fp = urlparse(final_url)
            self.origin = f"{fp.scheme}://{fp.netloc}"
            print(c(f"[*] HTTP {resp.status_code}, {len(resp.content)} bytes", C.GREEN))
            if final_url.rstrip("/") != self.url:
                print(c(f"[*] Redirected to: {final_url}", C.GRAY))

            for hop in resp.history:
                self.check_cookies(str(hop.url), hop)
            self.check_headers(final_url, resp)
            self.check_cookies(final_url, resp)
            self.check_html(final_url, resp.text[:200000])

            if fp.scheme == "https":
                host, port = fp.hostname, fp.port or 443
                print(c(f"[*] TLS fingerprint ({host}:{port})…", C.GRAY))
                await asyncio.to_thread(self.tls_fingerprint, host, port)
                if self.do_ja3s:
                    await asyncio.to_thread(self.ja3s_fingerprint, host, port)

            if self.do_paths:
                print(c("[*] Probing well-known paths…", C.GRAY))
                await self.check_paths(client)

        return resp.status_code

    # ==================================================================
    # REPORTING
    # ==================================================================
    def report(self):
        if not self.findings and not self.tls_info:
            print(c("\n[!] No technologies identified (or WAF blocking).", C.YELLOW))
            return

        line = "=" * 78
        print("\n" + c(line, C.CYAN))
        print(c("TECHNOLOGY FINGERPRINT", C.CYAN, C.BOLD))
        print(c(line, C.CYAN))

        category_colors = {
            "Server": C.GREEN, "Framework": C.GREEN, "CMS": C.MAGENTA,
            "JavaScript Framework": C.MAGENTA, "Library": C.BLUE,
            "CDN/Proxy": C.CYAN, "TLS": C.YELLOW, "TLS Issue": C.RED,
            "JA3S": C.MAGENTA, "Path Found": C.GREEN, "Path Restricted": C.YELLOW,
            "Cookie Issue": C.YELLOW, "Missing Security Header": C.YELLOW,
            "Version": C.BLUE, "Analytics/Marketing": C.DIM, "Generator": C.DIM,
            "Notes": C.GRAY,
        }
        conf_color = {"high": C.GREEN, "medium": C.YELLOW, "low": C.RED}

        for category in sorted(self.findings):
            color = category_colors.get(category, C.WHITE)
            print("\n" + c(f"[{category}]", color, C.BOLD))
            for tech, evidence in sorted(self.findings[category].items()):
                best = max(evidence.values(), key=lambda x: CONF_ORDER[x])
                print("  " + c(f"• {tech}", C.BOLD) + " " + c(f"[{best}]", conf_color[best]))
                for ev in sorted(evidence):
                    print("      " + c(f"└─ {ev}", C.GRAY))

        if self.tls_info:
            print("\n" + c("[TLS Details]", C.YELLOW, C.BOLD))
            for k, v in self.tls_info.items():
                print("  " + c(f"• {k}: {v}", C.YELLOW))

        if self.ja3s_info:
            print("\n" + c("[JA3S Fingerprint]", C.MAGENTA, C.BOLD))
            for k, v in self.ja3s_info.items():
                if k == "extensions" and isinstance(v, list):
                    v = ", ".join(str(x) for x in v)
                print("  " + c(f"• {k}: {v}", C.MAGENTA))

        if self.version_hits:
            print("\n" + c("[Version Summary]", C.BLUE, C.BOLD))
            for tech, versions in sorted(self.version_hits.items()):
                print("  " + c(f"• {tech}: {', '.join(sorted(versions))}", C.BLUE))

    def to_dict(self):
        return {
            "target": self.url,
            "origin": self.origin,
            "findings": {
                cat: {
                    tech: [{"evidence": e, "confidence": cf} for e, cf in sorted(ev.items())]
                    for tech, ev in techs.items()
                }
                for cat, techs in self.findings.items()
            },
            "versions": {t: sorted(v) for t, v in self.version_hits.items()},
            "tls": self.tls_info,
            "ja3s": self.ja3s_info,
        }


async def main():
    ap = argparse.ArgumentParser(
        description="Async web tech scanner with JA3S for responsible disclosure."
    )
    ap.add_argument("url")
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("-c", "--concurrency", type=int, default=10)
    ap.add_argument("-o", "--output")
    ap.add_argument("--no-paths", action="store_true", help="Skip path probing (passive only)")
    ap.add_argument("--no-ja3s", action="store_true", help="Skip JA3S")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verify", action="store_true", help="Verify TLS certificates for HTTP requests")
    ap.add_argument("--user-agent", default=USER_AGENT)
    ap.add_argument("--delay", type=float, default=0.0, help="Seconds to wait before each probe")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if "://" not in args.url:
        args.url = "https://" + args.url

    scanner = WebTechScanner(
        args.url, timeout=args.timeout, concurrency=args.concurrency,
        verify=args.verify, user_agent=args.user_agent, delay=args.delay,
        do_paths=not args.no_paths, do_ja3s=not args.no_ja3s,
    )
    code = await scanner.run()
    if code is None:
        sys.exit(1)

    scanner.report()
    if args.output:
        with open(args.output, "w") as f:
            json.dump(scanner.to_dict(), f, indent=2)
        print("\n" + c(f"[+] JSON report saved to {args.output}", C.GREEN))


if __name__ == "__main__":
    asyncio.run(main())
import json
import socket
import asyncio
import argparse
import hashlib
import os
from urllib.parse import urlparse

import httpx

try:
    from scapy.all import TLS, Raw, IP, TCP, conf
    from scapy.layers.tls.record import TLSHandshake
    from scapy.layers.tls.handshake import TLSServerHello
    from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_SH
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)


# ======================================================================
# COLORS (no external deps — plain ANSI)
# ======================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls):
        for k in dir(cls):
            if k.isupper():
                setattr(cls, k, "")


def c(text, *styles):
    return "".join(styles) + str(text) + C.RESET


# ======================================================================
# JA3S
# ======================================================================
def compute_ja3s(tls_version, cipher, extensions):
    """
    JA3S = MD5( TLSVersion,Cipher,Extensions )
    All values are decimal. Extensions are the extension TYPE ids in
    the order they appear in ServerHello (GREASE stripped).
    """
    # Strip GREASE values (0x?a?a pattern, per RFC 8701)
    def is_grease(v):
        return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)

    if is_grease(cipher):
        cipher = 0
    ext_ids = [e for e in extensions if not is_grease(e)]

    ja3s_str = f"{tls_version},{cipher},{'-'.join(str(e) for e in ext_ids)}"
    md5 = hashlib.md5(ja3s_str.encode()).hexdigest()
    return ja3s_str, md5


def parse_server_hello(record_bytes):
    """
    Extract (tls_version, cipher_suite, extension_ids) from raw
    TLS records captured off the socket.
    Returns None if ServerHello wasn't found.
    """
    if not HAVE_SCAPY:
        return None

    # scapy can dissect a bare TLS record stream
    try:
        pkt = TLS(record_bytes)
    except Exception:
        return None

    # Walk handshake messages looking for ServerHello
    layer = pkt
    while layer:
        if layer.haslayer(TLSServerHello):
            sh = layer[TLSServerHello]
            tls_version = sh.version
            cipher = sh.cipher
            ext_ids = []
            if sh.ext:
                for e in sh.ext:
                    try:
                        ext_ids.append(int(e.type))
                    except Exception:
                        pass
            # Prefer supported_versions extension (TLS 1.3) when present
            for e in (sh.ext or []):
                if isinstance(e, TLS_Ext_SupportedVersion_SH):
                    try:
                        tls_version = int(e.version)
                    except Exception:
                        pass
            return tls_version, cipher, ext_ids
        layer = layer.payload
    return None


# ======================================================================
# SCANNER
# ======================================================================
class WebTechScanner:
    def __init__(self, url, timeout=10, concurrency=10):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)
        self.findings = {}    # category -> tech -> set(evidence)
        self.version_hits = {}
        self.tls_info = {}
        self.ja3s_info = {}

    # ---------- findings ----------
    def _add(self, category, tech, evidence):
        self.findings.setdefault(category, {}).setdefault(tech, set()).add(evidence)

    def _add_version(self, tech, version, evidence):
        self.version_hits.setdefault(tech, set()).add(version)
        self._add("Version", f"{tech} {version}", evidence)

    # ==================================================================
    # HEADERS
    # ==================================================================
    def check_headers(self, url, resp):
        where = f"GET {url} → response headers"
        h = {k.lower(): v for k, v in resp.headers.items()}

        if "server" in h:
            server = h["server"]
            self._add("Server", server, where)
            m = re.search(r"([A-Za-z][\w-]*?)/(\d+(?:\.\d+)*)", server)
            if m:
                self._add_version(m.group(1), m.group(2),
                                  f"{where} → Server: {server}")

        if "x-powered-by" in h:
            xpb = h["x-powered-by"]
            self._add("Framework", xpb, where)
            m = re.search(r"([A-Za-z][\w.-]*?)[ /]?v?(\d+(?:\.\d+)*)", xpb)
            if m and not m.group(1).isdigit():
                self._add_version(m.group(1), m.group(2),
                                  f"{where} → X-Powered-By: {xpb}")

        for hdr, tech in {
            "x-aspnet-version": "ASP.NET",
            "x-aspnetmvc-version": "ASP.NET MVC",
            "x-generator": "Generator",
        }.items():
            if hdr in h:
                self._add_version(tech, h[hdr], f"{where} → {hdr}: {h[hdr]}")

        for key, tech in {
            "cf-ray": "Cloudflare",
            "x-akamai-transformed": "Akamai",
            "x-cache": "CDN (generic)",
            "x-amz-cf-id": "AWS CloudFront",
            "x-fastly-request-id": "Fastly",
            "x-sucuri-id": "Sucuri",
            "x-azure-ref": "Azure",
            "x-vercel-id": "Vercel",
        }.items():
            if key in h:
                self._add("CDN/Proxy", tech, f"{where} → {key}: {h[key]}")

        for sec, label in [
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "CSP"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("referrer-policy", "Referrer-Policy"),
            ("permissions-policy", "Permissions-Policy"),
        ]:
            if sec not in h and url.startswith("https"):
                self._add("Missing Security Header", label,
                          f"{where} → {sec} absent")

    # ==================================================================
    # COOKIES
    # ==================================================================
    def check_cookies(self, url, resp):
        where = f"GET {url} → Set-Cookie"
        raw = resp.headers.get("set-cookie", "")
        if not raw:
            return
        cookie_map = {
            "PHPSESSID": "PHP", "JSESSIONID": "Java (Servlet)",
            "ASP.NET_SessionId": "ASP.NET", "laravel_session": "Laravel",
            "ci_session": "CodeIgniter", "django_session": "Django",
            "wordpress_": "WordPress", "_shopify_s": "Shopify",
            "AWSALB": "AWS ALB",
        }
        for needle, tech in cookie_map.items():
            if needle.lower() in raw.lower():
                self._add("Framework", tech, f"{where} → '{needle}'")
        lowered = raw.lower()
        if "httponly" not in lowered:
            self._add("Cookie Issue", "Missing HttpOnly", where)
        if "secure" not in lowered and url.startswith("https"):
            self._add("Cookie Issue", "Missing Secure flag", where)
        if "samesite" not in lowered:
            self._add("Cookie Issue", "Missing SameSite", where)

    # ==================================================================
    # HTML
    # ==================================================================
    def check_html(self, url, body):
        where = f"GET {url} → body"
        body_l = body.lower()
        patterns = {
            "CMS": {
                "WordPress": [(r"/wp-content/", None), (r"/wp-includes/", None)],
                "Drupal": [(r"drupal\.js", None), (r"sites/default/files", None)],
                "Joomla": [(r"/media/system/js/", None)],
                "Magento": [(r"/skin/frontend/", None)],
                "Shopify": [(r"cdn\.shopify\.com", None)],
            },
            "JavaScript Framework": {
                "React": [(r"react-dom", None), (r"data-reactroot", None)],
                "Angular": [(r'ng-version="([\d.]+)"', 1)],
                "Vue.js": [(r"vue[@.]([\d.]+)\.js", 1)],
                "Next.js": [(r"__next_data__", None)],
                "Nuxt.js": [(r"__nuxt__", None)],
                "Svelte": [(r"svelte-[a-z0-9]+", None)],
            },
            "Analytics/Marketing": {
                "Google Analytics": [(r"google-analytics\.com/analytics\.js", None)],
                "Google Tag Manager": [(r"googletagmanager\.com", None)],
                "Facebook Pixel": [(r"connect\.facebook\.net", None)],
            },
            "Library": {
                "jQuery": [(r"jquery[.-]([\d.]+)(?:\.min)?\.js", 1)],
                "Bootstrap": [(r"bootstrap[.-](\d+\.\d+\.\d+)", 1)],
                "Font Awesome": [(r"font-awesome/([\d.]+)", 1)],
            },
        }
        for category, techs in patterns.items():
            for tech, regexes in techs.items():
                for rx, group in regexes:
                    m = re.search(rx, body_l)
                    if m:
                        if group and m.lastindex and m.group(group):
                            self._add_version(tech, m.group(group),
                                              f"{where} → /{rx}/")
                        else:
                            self._add(category, tech, f"{where} → /{rx}/")
                        break

        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            body_l,
        )
        if gen:
            content = gen.group(1)
            self._add("Generator", content,
                      f"{where} → <meta generator='{content}'>")
            m = re.search(r"([A-Za-z][\w .-]*?)\s+(\d+(?:\.\d+)*)", content)
            if m:
                self._add_version(m.group(1).strip(), m.group(2),
                                  f"{where} → meta generator")

        for comment in re.findall(r"<!--(.*?)-->", body, re.S):
            m = re.search(
                r"(\w[\w.-]*)\s+(?:v|version\s+)?(\d+\.\d+(?:\.\d+)?)",
                comment, re.I,
            )
            if m and len(comment) < 200:
                self._add_version(
                    m.group(1), m.group(2),
                    f"{where} → HTML comment: <!--{comment.strip()[:80]}-->",
                )

    # ==================================================================
    # PATH PROBING
    # ==================================================================
    async def check_paths(self, client):
        probes = {
            "/wp-login.php": "WordPress",
            "/wp-admin/": "WordPress",
            "/administrator/": "Joomla",
            "/user/login": "Drupal",
            "/.git/HEAD": "Exposed .git",
            "/.env": "Exposed .env (CRITICAL)",
            "/server-status": "Apache server-status",
            "/phpinfo.php": "phpinfo exposed",
            "/actuator": "Spring Boot Actuator",
            "/actuator/env": "Spring Boot Actuator env",
            "/robots.txt": "robots.txt",
            "/sitemap.xml": "sitemap.xml",
            "/readme.html": "WordPress readme",
        }

        async def probe(path, label):
            target = self.url + path
            async with self.sem:
                try:
                    r = await client.get(target, follow_redirects=False)
                except httpx.HTTPError:
                    return
            if r.status_code in (200, 401, 403) and not (
                r.status_code == 200 and len(r.content) < 20
            ):
                self._add("Path Found", label,
                          f"GET {target} → HTTP {r.status_code}")
                if "readme" in path.lower():
                    m = re.search(r"Version\s+([\d.]+)", r.text, re.I)
                    if m:
                        self._add_version(label.split()[0], m.group(1),
                                          f"GET {target} → 'Version {m.group(1)}'")

        await asyncio.gather(*(probe(p, l) for p, l in probes.items()))

    # ==================================================================
    # TLS + JA3S
    # ==================================================================
    def tls_fingerprint(self, host, port=443):
        """Synchronous TLS cert info (metadata only, no raw bytes)."""
        if not self.url.startswith("https"):
            return
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    der = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()

            info = {
                "tls_version": version,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "cert_sha256": hashlib.sha256(der).hexdigest() if der else None,
            }
            if cert:
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["not_after"] = cert.get("notAfter")
            self.tls_info = info

            where = f"TLS handshake {host}:{port}"
            self._add("TLS", f"Version {version}", where)
            if cipher:
                self._add("TLS", f"Cipher {cipher[0]} ({cipher[2]} bits)", where)
            if cert and cert.get("issuer"):
                issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "?")
                self._add("TLS", f"Cert issuer: {issuer}",
                          f"{where} → cert SHA256 {info['cert_sha256'][:16]}…")
            if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                self._add("TLS Issue", f"Deprecated {version}",
                          f"{where} → negotiated {version}")
        except Exception as e:
            self._add("TLS", f"Error: {type(e).__name__}", f"{host}:{port} → {e}")

    def ja3s_fingerprint(self, host, port=443):
        """
        Real JA3S. We open a raw socket, perform a minimal ClientHello
        by hand so we control the byte stream, capture the ServerHello,
        and run it through scapy's TLS dissector.
        """
        if not self.url.startswith("https"):
            return
        if not HAVE_SCAPY:
            self.ja3s_info = {"error": "scapy not installed (pip install scapy)"}
            return

        try:
            # --- Build a minimal ClientHello by hand ---
            # This is standard boilerplate: TLS 1.2 + SNI. We don't need a
            # full handshake — we just want the raw ServerHello bytes.
            sni = host.encode()

            def ext(etype, body):
                return etype.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

            # supported_versions: TLS1.2, TLS1.3
            sv = b"\x04\x03\x04\x03\x03"
            exts = (
                ext(0x0000, len(sni).to_bytes(2, "big") + sni)          # SNI
                + ext(0x000a, b"\x00\x04\x00\x1f\x00\x17")              # groups
                + ext(0x000b, b"\x01\x00")                              # EC point formats
                + ext(0x002b, sv)                                       # supported versions
                + ext(0x000d, b"\x00\x04\x04\x03\x08\x04")              # sig algs
            )

            cipher_suites = (
                b"\x13\x01\x13\x02\x13\x03"       # TLS 1.3 suites
                b"\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
                b"\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"
            )

            client_hello_body = (
                b"\x03\x03"                                  # client_version TLS1.2
                + os.urandom(32)                             # random
                + b"\x00"                                    # session id len
                + len(cipher_suites).to_bytes(2, "big") + cipher_suites
                + b"\x01\x00"                                # compression
                + len(exts).to_bytes(2, "big") + exts
            )
            handshake = (
                b"\x01"                                      # ClientHello
                + len(client_hello_body).to_bytes(3, "big")
                + client_hello_body
            )
            record = (
                b"\x16"                                      # handshake
                + b"\x03\x01"                                # record version
                + len(handshake).to_bytes(2, "big")
                + handshake
            )

            # --- Send and collect the server's response ---
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.sendall(record)
                data = b""
                # Read enough bytes to cover a few records (ServerHello is
                # usually inside the first 2 records; cert can follow).
                while len(data) < 16384:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # Stop early once we have a complete handshake record set
                    # that likely contains ServerHello
                    if len(data) > 100 and (
                        data[5:6] == b"\x02" or  # ServerHello msg type
                        b"\x02\x00\x00" in data[:1024]
                    ):
                        # Let it read one more chunk then bail
                        try:
                            sock.settimeout(0.5)
                            data += sock.recv(4096)
                        except socket.timeout:
                            pass
                        break

            result = parse_server_hello(data)
            if not result:
                self.ja3s_info = {"error": "ServerHello not parsed"}
                return

            tls_version, cipher, ext_ids = result
            ja3s_str, md5 = compute_ja3s(tls_version, cipher, ext_ids)
            self.ja3s_info = {
                "ja3s_string": ja3s_str,
                "ja3s_hash": md5,
                "tls_version": f"0x{tls_version:04x}",
                "cipher_suite": f"0x{cipher:04x}",
                "extensions": ext_ids,
            }

            where = f"JA3S handshake {host}:{port} → ServerHello"
            self._add("JA3S", md5, where)
            self._add("JA3S", f"raw: {ja3s_str}", where)

        except Exception as e:
            self.ja3s_info = {"error": f"{type(e).__name__}: {e}"}

    # ==================================================================
    # MAIN
    # ==================================================================
    async def run(self):
        print(c(f"[*] Scanning {self.url}", C.CYAN, C.BOLD))
        parsed = urlparse(self.url)
        host = parsed.hostname

        if parsed.scheme == "https":
            port = parsed.port or 443
            print(c("[*] TLS + JA3S fingerprint…", C.GRAY))
            await asyncio.to_thread(self.tls_fingerprint, host, port)
            await asyncio.to_thread(self.ja3s_fingerprint, host, port)

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            try:
                resp = await client.get(self.url)
            except httpx.HTTPError as e:
                print(c(f"[!] Connection failed: {e}", C.RED))
                return None

            print(c(f"[*] HTTP {resp.status_code}, {len(resp.content)} bytes", C.GREEN))
            final_url = str(resp.url)
            if final_url != self.url:
                print(c(f"[*] Redirected to: {final_url}", C.GRAY))

            self.check_headers(final_url, resp)
            self.check_cookies(final_url, resp)
            self.check_html(final_url, resp.text[:200000])

            print(c("[*] Probing well-known paths…", C.GRAY))
            await self.check_paths(client)

        return resp.status_code

    # ==================================================================
    # REPORTING (colored)
    # ==================================================================
    def report(self):
        if not self.findings and not self.tls_info:
            print(c("\n[!] No technologies identified (or WAF blocking).", C.YELLOW))
            return

        line = "=" * 78
        print("\n" + c(line, C.CYAN))
        print(c("TECHNOLOGY FINGERPRINT", C.CYAN, C.BOLD))
        print(c(line, C.CYAN))

        category_colors = {
            "Server": C.GREEN,
            "Framework": C.GREEN,
            "CMS": C.MAGENTA,
            "JavaScript Framework": C.MAGENTA,
            "Library": C.BLUE,
            "CDN/Proxy": C.CYAN,
            "TLS": C.YELLOW,
            "TLS Issue": C.RED,
            "JA3S": C.MAGENTA,
            "Path Found": C.GREEN,
            "Cookie Issue": C.YELLOW,
            "Missing Security Header": C.YELLOW,
            "Version": C.BLUE,
            "Analytics/Marketing": C.DIM,
            "Generator": C.DIM,
        }

        for category in sorted(self.findings):
            color = category_colors.get(category, C.WHITE)
            print("\n" + c(f"[{category}]", color, C.BOLD))
            for tech, evidence in sorted(self.findings[category].items()):
                print("  " + c(f"• {tech}", C.BOLD))
                for ev in sorted(evidence):
                    print("      " + c(f"└─ {ev}", C.GRAY))

        if self.tls_info:
            print("\n" + c("[TLS Fingerprint]", C.YELLOW, C.BOLD))
            for k, v in self.tls_info.items():
                print("  " + c(f"• {k}: {v}", C.YELLOW))

        if self.ja3s_info:
            print("\n" + c("[JA3S Fingerprint]", C.MAGENTA, C.BOLD))
            for k, v in self.ja3s_info.items():
                if k == "extensions" and isinstance(v, list):
                    v = ", ".join(str(x) for x in v)
                print("  " + c(f"• {k}: {v}", C.MAGENTA))
            if self.ja3s_info.get("error"):
                print("  " + c("(JA3S unavailable — see error above)", C.RED))

        if self.version_hits:
            print("\n" + c("[Version Summary]", C.BLUE, C.BOLD))
            for tech, versions in sorted(self.version_hits.items()):
                print("  " + c(f"• {tech}: {', '.join(sorted(versions))}", C.BLUE))

    def to_dict(self):
        return {
            "target": self.url,
            "findings": {
                cat: {tech: sorted(ev) for tech, ev in techs.items()}
                for cat, techs in self.findings.items()
            },
            "versions": {t: sorted(v) for t, v in self.version_hits.items()},
            "tls": self.tls_info,
            "ja3s": self.ja3s_info,
        }


async def main():
    ap = argparse.ArgumentParser(
        description="Async web tech scanner with JA3S for responsible disclosure."
    )
    ap.add_argument("url")
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("-c", "--concurrency", type=int, default=10)
    ap.add_argument("-o", "--output")
    ap.add_argument("--no-paths", action="store_true")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI colors (auto if piped)")
    ap.add_argument("--no-ja3s", action="store_true",
                    help="Skip JA3S (useful if scapy parsing fails)")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if not urlparse(args.url).scheme:
        args.url = "https://" + args.url

    if not HAVE_SCAPY and not args.no_ja3s:
        print(c("[!] scapy not installed — JA3S disabled (pip install scapy)",
                C.YELLOW))

    scanner = WebTechScanner(args.url, timeout=args.timeout,
                             concurrency=args.concurrency)
    if args.no_paths:
        scanner.check_paths = lambda client: asyncio.sleep(0)
    if args.no_ja3s:
        scanner.ja3s_fingerprint = lambda host, port=443: None

    code = await scanner.run()
    if code is None:
        sys.exit(1)

    scanner.report()
    if args.output:
        with open(args.output, "w") as f:
            json.dump(scanner.to_dict(), f, indent=2)
        print("\n" + c(f"[+] JSON report saved to {args.output}", C.GREEN))


if __name__ == "__main__":
    asyncio.run(main())
