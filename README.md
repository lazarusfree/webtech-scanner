# webtech-scan

Async web technology fingerprinter for **authorized security testing and responsible disclosure only**.

It identifies the technologies behind a website from response headers, cookies, page HTML and asset URLs, well-known paths, and TLS (including a JA3S server fingerprint). Every finding shows the evidence behind it.

Two versions are included:

| File                 | Summary                                                                                         |
|----------------------|-------------------------------------------------------------------------------------------------|
| `webtech_scan.py`    | v1. Headers, cookies, HTML, path probes, TLS, JA3S via scapy.                                   |
| `webtech_scan_v2.py` | v2 (recommended). Confidence-rated findings, soft-404-aware path probing, dependency-free JA3S. |

## v2 (recommended)

- Each finding is rated **high / medium / low** confidence.
- **Path probing** validates response content and compares against a random-path baseline, so single-page apps and WAFs don't produce false positives (e.g. a fake exposed `.env`). Paths that return 401/403 are reported as "restricted" at low confidence.
- **JA3S** uses a hand-built ClientHello and ServerHello parser (no scapy), with a correct SNI, a `key_share` to avoid HelloRetryRequest, and the standard `legacy_version`.
- **Cookies** are checked one by one, including cookies set during redirects.
- **TLS** details are parsed from the certificate (needs `cryptography`), and servers that accept TLS 1.0/1.1 are detected with pinned-version handshakes.
- Probes run against the **final origin** after redirects.
- Honest User-Agent by default.

### Install

```bash
pip install httpx cryptography   # cryptography is optional (certificate details)
```

### Usage

```bash
python webtech_scan_v2.py https://example.com
python webtech_scan_v2.py example.com -o report.json
python webtech_scan_v2.py example.com --no-paths            # passive only
python webtech_scan_v2.py example.com --delay 0.5 --verify
```

| Option              | Description                                |
|---------------------|--------------------------------------------|
| `-t, --timeout`     | Request timeout in seconds (default 10)    |
| `-c, --concurrency` | Max concurrent requests (default 10)       |  
| `-o, --output`      | Write a JSON report                        |
| `--no-paths`        | Skip path probing (passive only)           |
| `--no-ja3s`         | Skip JA3S                                  |
| `--no-color`        | Disable ANSI colors (automatic when piped) |
| `--verify`          | Verify TLS certificates for HTTP requests  |
| `--user-agent`      | Custom User-Agent                          |
| `--delay`           | Seconds to wait before each probe          |

### Notes

- JA3S hashes are only comparable between scans that use this tool's fixed ClientHello. They will not match public JA3S datasets built from other clients.
- Certificate verification is off by default, so HTTP requests accept invalid certificates unless `--verify` is passed.
- Findings are fingerprints, not proof of vulnerability. Check low-confidence results manually.

## Responsible use

Only scan systems you own or have explicit permission to test. Path probing sends requests to sensitive-looking paths, so use `--no-paths` and `--delay` where appropriate.
