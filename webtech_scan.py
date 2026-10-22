#!/usr/bin/env python3
"""
webtech_scan.py - Async web technology scanner with JA3S + color output.
For authorized security testing / responsible disclosure only.
"""

import re
import ssl
import sys
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