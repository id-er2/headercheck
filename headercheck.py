#!/usr/bin/env python3
"""headercheck - inspect the HTTP security headers of a URL.

Sends a single GET request to a URL you provide, reads the response
headers, and reports which security headers are present, which are
missing, and what each one is for. Read-only: it never sends anything
but that one request.

Usage:
    python headercheck.py https://example.com
    python headercheck.py https://example.com --json
"""

import argparse
import ipaddress
import http.client
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager

USER_AGENT = "headercheck/1.0 (+https://github.com/id-er2/headercheck)"
REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 5

# Grade thresholds, applied to the final score out of 100.
GRADES = [
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (55, "D"),
    (0, "F"),
]

HSTS_ONE_YEAR = 31536000
HSTS_SIX_MONTHS = 15552000

# ANSI escape sequences (CSI, plus two-character ESC sequences).
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")


def _strip_ctl(text):
    """Remove ANSI escapes and control characters from untrusted text.

    Response header values come from the server being checked and can
    contain terminal escape sequences or raw control characters. They are
    stripped at the text-report boundary so a crafted server response
    cannot rewrite, clear or recolor the terminal that displays the
    report. JSON output keeps the raw values.
    """
    text = _ANSI_RE.sub("", str(text))
    return "".join(ch for ch in text if ch >= " " and ch != "\x7f")


class Check:
    """One header check result."""

    def __init__(self, name, status, weight, earned, summary, detail, fix):
        self.name = name
        self.status = status  # "pass", "warn", "fail", "info"
        self.weight = weight
        self.earned = earned
        self.summary = summary
        self.detail = detail
        self.fix = fix

    def as_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "weight": self.weight,
            "earned": self.earned,
            "summary": self.summary,
            "detail": self.detail,
            "fix": self.fix,
        }


class FetchPolicyError(RuntimeError):
    """The URL or a redirect target violates the fetch policy."""


def _check_fetch_url(url, initial=False):
    """Validate a URL the tool is about to fetch.

    Only http and https are ever fetched (no file:, ftp: or other
    schemes urllib would happily open). Redirect targets must also
    resolve to public addresses only, so a server cannot bounce the
    checker at loopback, link-local or private-network services. The
    address the user typed is exempt from the address check: inspecting
    one's own internal site is a legitimate use.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchPolicyError(
            "refusing to fetch scheme %r: only http and https"
            % (parts.scheme or "(none)"))
    host = parts.hostname
    if not host:
        raise FetchPolicyError("URL has no host: %r" % url)
    if initial:
        return
    try:
        infos = socket.getaddrinfo(
            host,
            parts.port or (443 if parts.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchPolicyError(
            "redirect target %r does not resolve: %s" % (host, exc))
    if not infos:
        raise FetchPolicyError("redirect target has no addresses")
    for info in infos:
        addr = info[4][0].split("%")[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise FetchPolicyError(
                "cannot parse resolved address %r" % (addr,))
        if not ip.is_global or ip.is_multicast:
            raise FetchPolicyError(
                "refusing redirect to a non-public address: "
                "%r resolves to %s" % (host, addr))

    return infos


def normalize_url(url):
    """Add a scheme when the user leaves it out."""
    url = url.strip()
    if not url:
        raise ValueError("empty URL")
    if "://" not in url:
        url = "https://" + url
    return url


def _connect_validated(infos, port, timeout):
    """Connect directly to a validated sockaddr without a second DNS lookup."""
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect((sockaddr[0], port) + sockaddr[2:])
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError("no validated address available")


@contextmanager
def _open_response(url, timeout, infos=None):
    parts = urllib.parse.urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, port, timeout=timeout,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
    if infos is not None:
        # Keep the original host for Host, TLS SNI and certificate checks;
        # only the TCP connection uses the previously validated address.
        conn._create_connection = lambda address, timeout, source_address=None: (
            _connect_validated(infos, port, timeout))
    path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT})
        response = conn.getresponse()
        try:
            yield response
        finally:
            response.close()
    finally:
        conn.close()


def fetch_headers(url, timeout=REQUEST_TIMEOUT):
    """GET headers, manually validating each redirect before connecting.

    Direct connections avoid proxy and automatic redirect behavior. The
    user-selected first target may be internal. Redirect addresses must
    all be public and are pinned for the connection, including HTTPS.
    """
    current = url
    for redirects in range(MAX_REDIRECTS + 1):
        infos = _check_fetch_url(current, initial=(redirects == 0))
        with _open_response(current, timeout, infos) as response:
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if location:
                    if redirects >= MAX_REDIRECTS:
                        raise FetchPolicyError("too many redirects (limit %d)" % MAX_REDIRECTS)
                    current = urllib.parse.urljoin(current, location)
                    continue
            return current, _headers_dict(response.headers)


def _headers_dict(message):
    """Flatten an email.message.Message into a lower-case dict.

    set-cookie is also kept as a list under 'set-cookie-list' because a
    dict would collapse multiple Set-Cookie headers into one.
    """
    headers = {}
    cookies = []
    for key, value in message.items():
        key = key.lower()
        if key == "set-cookie":
            cookies.append(value)
        headers[key] = value
    if cookies:
        headers["set-cookie-list"] = cookies
    return headers


def _parse_csp(csp):
    """Split a CSP value into {directive: [values]}."""
    directives = {}
    for part in csp.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def check_csp(headers):
    weight = 25
    value = headers.get("content-security-policy")
    if not value:
        return Check(
            "Content-Security-Policy", "fail", weight, 0,
            "missing",
            "CSP limits which scripts, styles and other resources the page "
            "may load. It is the main defense against content injection (XSS).",
            "Add a Content-Security-Policy header, starting restrictive "
            "(for example: default-src 'self') and loosening only as needed.",
        )
    directives = _parse_csp(value)
    problems = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src:
        problems.append("allows inline scripts ('unsafe-inline')")
    if "'unsafe-eval'" in script_src:
        problems.append("allows eval() ('unsafe-eval')")
    if "*" in script_src:
        problems.append("allows scripts from any origin (*)")
    if problems:
        return Check(
            "Content-Security-Policy", "warn", weight, weight // 2,
            "present but permissive: " + "; ".join(problems),
            "The policy exists, which is good, but these allowances remove "
            "most of its protection.",
            "Drop 'unsafe-inline'/'unsafe-eval' where possible; prefer "
            "nonces or hashes for the inline code you must keep.",
        )
    return Check(
        "Content-Security-Policy", "pass", weight, weight,
        "present",
        "A policy is set without unsafe-inline, unsafe-eval or a wildcard "
        "script source.",
        "",
    )


def check_hsts(headers, url):
    weight = 15
    if not url.lower().startswith("https://"):
        return Check(
            "Strict-Transport-Security", "info", weight, 0,
            "not evaluated - the URL is plain HTTP",
            "HSTS only applies to HTTPS. Serving the site over plain HTTP "
            "is itself the bigger problem.",
            "Serve the site over HTTPS, then add Strict-Transport-Security.",
        )
    value = headers.get("strict-transport-security")
    if not value:
        return Check(
            "Strict-Transport-Security", "fail", weight, 0,
            "missing",
            "HSTS tells the browser to always use HTTPS for this host, "
            "blocking downgrade attacks on first and later visits.",
            "Add Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains (add ; preload only if you mean it).",
        )
    directives = [p.strip().lower() for p in value.split(";")]
    max_age = None
    for d in directives:
        if d.startswith("max-age"):
            try:
                max_age = int(d.split("=", 1)[1].strip().strip('"'))
            except (ValueError, IndexError):
                max_age = -1
    if max_age is None or max_age < 0:
        return Check(
            "Strict-Transport-Security", "warn", weight, weight // 2,
            "present but max-age is missing or invalid",
            "Without a usable max-age the browser cannot remember the policy.",
            "Set max-age to at least 15552000 (180 days).",
        )
    notes = []
    earned = weight
    status = "pass"
    if max_age < HSTS_SIX_MONTHS:
        status = "warn"
        earned = weight // 2
        notes.append("max-age %d is short" % max_age)
    elif max_age < HSTS_ONE_YEAR:
        notes.append("max-age below one year")
    if "includesubdomains" not in directives:
        notes.append("no includeSubDomains")
    summary = "max-age=%d" % max_age + ("; " + "; ".join(notes) if notes else "")
    return Check(
        "Strict-Transport-Security", status, weight, earned,
        summary,
        "HSTS is set. includeSubDomains extends it to subdomains; "
        "preload asks browsers to ship the rule built in.",
        "" if status == "pass" else "Raise max-age and consider "
        "includeSubDomains.",
    )


def check_x_content_type_options(headers):
    weight = 10
    value = headers.get("x-content-type-options", "")
    if value.strip().lower() == "nosniff":
        return Check(
            "X-Content-Type-Options", "pass", weight, weight,
            "nosniff",
            "The browser will not guess content types, so an uploaded file "
            "cannot be reinterpreted as a script or page.",
            "",
        )
    return Check(
        "X-Content-Type-Options", "fail", weight, 0,
        "missing" if not value else "unexpected value: %s" % value,
        "Without nosniff the browser may MIME-sniff responses, which can "
        "turn uploaded content into active script.",
        "Add X-Content-Type-Options: nosniff.",
    )


def check_clickjacking(headers):
    weight = 15
    xfo = headers.get("x-frame-options", "").strip().upper()
    csp = headers.get("content-security-policy", "")
    frame_ancestors = _parse_csp(csp).get("frame-ancestors") if csp else None
    if xfo in ("DENY", "SAMEORIGIN"):
        return Check(
            "Clickjacking protection", "pass", weight, weight,
            "X-Frame-Options: %s" % xfo.title(),
            "The page cannot be framed by other sites, so it cannot be "
            "overlaid to trick users into clicking hidden controls.",
            "",
        )
    if frame_ancestors:
        return Check(
            "Clickjacking protection", "pass", weight, weight,
            "CSP frame-ancestors is set",
            "frame-ancestors is the modern replacement for X-Frame-Options "
            "and controls who may embed this page.",
            "",
        )
    if xfo:
        return Check(
            "Clickjacking protection", "warn", weight, weight // 2,
            "X-Frame-Options: %s (unusual value)" % xfo,
            "ALLOW-FROM is obsolete and unsupported by modern browsers.",
            "Use DENY or SAMEORIGIN, or CSP frame-ancestors.",
        )
    return Check(
        "Clickjacking protection", "fail", weight, 0,
        "missing",
        "Any site can embed this page in an invisible frame and hijack "
        "clicks meant for it.",
        "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP "
        "frame-ancestors 'self'.",
    )


def check_referrer_policy(headers):
    weight = 10
    # A comma-separated list is allowed as a fallback chain; the last
    # recognized value wins in browsers.
    raw = headers.get("referrer-policy", "").strip().lower()
    value = raw.split(",")[-1].strip() if raw else ""
    good = {
        "no-referrer", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if value in good:
        return Check(
            "Referrer-Policy", "pass", weight, weight,
            value,
            "Limits how much of the URL (which can carry tokens or query "
            "data) leaks to third parties through the Referer header.",
            "",
        )
    if value:
        return Check(
            "Referrer-Policy", "warn", weight, weight // 2,
            "weak value: %s" % value,
            "This value can leak the full URL, including query strings, "
            "to other origins.",
            "Use strict-origin-when-cross-origin or stricter.",
        )
    return Check(
        "Referrer-Policy", "warn", weight, weight // 2,
        "missing",
        "The browser default applies, which is reasonable but not stated; "
        "being explicit avoids surprises.",
        "Add Referrer-Policy: strict-origin-when-cross-origin.",
    )


def check_permissions_policy(headers):
    weight = 10
    value = headers.get("permissions-policy") or headers.get("feature-policy")
    if value:
        return Check(
            "Permissions-Policy", "pass", weight, weight,
            "present",
            "Restricts which browser features (camera, microphone, "
            "geolocation, ...) the page and its frames may use.",
            "",
        )
    return Check(
        "Permissions-Policy", "warn", weight, weight // 2,
        "missing",
        "Without it, any script that lands on the page can ask for "
        "sensitive browser features.",
        "Add Permissions-Policy, denying what the site does not use, "
        "e.g. camera=(), microphone=(), geolocation=().",
    )


def check_info_disclosure(headers):
    weight = 5
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = headers.get(name, "")
        # A bare product name is normal; a version number is the leak.
        if value and any(ch.isdigit() for ch in value):
            leaks.append("%s: %s" % (name, value))
    if leaks:
        return Check(
            "Version disclosure", "warn", weight, 0,
            "; ".join(leaks),
            "Exact software versions help an attacker pick known exploits.",
            "Configure the server/framework to omit version numbers.",
        )
    return Check(
        "Version disclosure", "pass", weight, weight,
        "no version numbers exposed",
        "Server headers name the software but no exact versions.",
        "",
    )


def check_cookies(headers, raw_headers):
    weight = 10
    cookies = raw_headers.get("set-cookie")
    if not cookies:
        return Check(
            "Cookie security", "pass", weight, weight,
            "no cookies set by this response",
            "Nothing to evaluate: the page does not set cookies.",
            "",
        )
    problems = []
    for cookie in cookies:
        attrs = [a.strip().lower() for a in cookie.split(";")[1:]]
        name = cookie.split("=", 1)[0].strip()
        if "secure" not in attrs:
            problems.append("%s: no Secure" % name)
        if "httponly" not in attrs:
            problems.append("%s: no HttpOnly" % name)
        if not any(a.startswith("samesite") for a in attrs):
            problems.append("%s: no SameSite" % name)
    if problems:
        return Check(
            "Cookie security", "warn", weight, weight // 2,
            "; ".join(problems),
            "Secure keeps cookies on HTTPS, HttpOnly keeps them out of "
            "JavaScript, SameSite limits cross-site sending.",
            "Set Secure, HttpOnly and SameSite on session cookies.",
        )
    return Check(
        "Cookie security", "pass", weight, weight,
        "%d cookie(s) with Secure, HttpOnly, SameSite" % len(cookies),
        "All cookies carry the expected flags.",
        "",
    )


def check_cors(headers):
    value = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    if value == "*" and credentials == "true":
        return Check(
            "CORS", "warn", 0, 0,
            "Access-Control-Allow-Origin: * with credentials",
            "Wildcard origin combined with credentials is contradictory "
            "and usually a misconfiguration.",
            "Allow-list specific origins instead of *.",
        )
    if value == "*":
        return Check(
            "CORS", "info", 0, 0,
            "Access-Control-Allow-Origin: *",
            "Any site may read this response. Fine for public static "
            "content; a problem for anything private.",
            "If the content is public, no action needed.",
        )
    return None


def analyze(final_url, headers):
    """Run every check. Returns (checks, score, grade)."""
    raw = {"set-cookie": headers.get("set-cookie-list", [])}
    checks = [
        check_csp(headers),
        check_hsts(headers, final_url),
        check_x_content_type_options(headers),
        check_clickjacking(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
        check_info_disclosure(headers),
        check_cookies(headers, raw),
    ]
    cors = check_cors(headers)
    if cors:
        checks.append(cors)
    scored = [c for c in checks if c.weight > 0]
    total = sum(c.weight for c in scored)
    earned = sum(c.earned for c in scored)
    score = round(100 * earned / total) if total else 0
    grade = next(g for threshold, g in GRADES if score >= threshold)
    return checks, score, grade


def format_report(url, final_url, status_checks, score, grade):
    lines = []
    lines.append("headercheck report")
    lines.append("  URL:   %s" % url)
    if final_url != url:
        lines.append("  Final: %s (after redirects)" % final_url)
    lines.append("  Score: %d/100 (%s)" % (score, grade))
    lines.append("")
    symbols = {"pass": "[ok]  ", "warn": "[warn]", "fail": "[fail]",
               "info": "[info]"}
    for c in status_checks:
        lines.append("%s %s: %s" % (symbols[c.status], c.name, c.summary))
        lines.append("        %s" % c.detail)
        if c.fix:
            lines.append("        Fix: %s" % c.fix)
        lines.append("")
    return "\n".join(_strip_ctl(line) for line in lines).rstrip() + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inspect the HTTP security headers of a URL."
    )
    parser.add_argument("url", help="URL to check (https:// is assumed)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT,
                        help="request timeout in seconds (default 15)")
    args = parser.parse_args(argv)

    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    try:
        final_url, headers = fetch_headers(url, timeout=args.timeout)
    except (urllib.error.URLError, RuntimeError, FetchPolicyError,
            ssl.SSLError, OSError, ValueError, http.client.HTTPException) as exc:
        print("error: could not fetch %s: %s" % (url, exc), file=sys.stderr)
        return 1

    checks, score, grade = analyze(final_url, headers)
    if args.json:
        print(json.dumps({
            "url": url,
            "final_url": final_url,
            "score": score,
            "grade": grade,
            "checks": [c.as_dict() for c in checks],
        }, indent=2))
    else:
        print(format_report(url, final_url, checks, score, grade), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
