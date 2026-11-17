import io
import json
import unittest
from email.message import Message
from unittest import mock

import headercheck as hc


HTTPS = "https://example.com/"


def analyze(headers, url=HTTPS):
    return hc.analyze(url, headers)


def check_by_name(checks, name):
    return next(c for c in checks if c.name == name)


class NormalizeUrlTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(hc.normalize_url("example.com"), "https://example.com")

    def test_keeps_existing_scheme(self):
        self.assertEqual(
            hc.normalize_url("http://example.com"), "http://example.com")

    def test_strips_whitespace(self):
        self.assertEqual(
            hc.normalize_url("  https://example.com  "), "https://example.com")

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            hc.normalize_url("   ")


class CspTests(unittest.TestCase):
    def test_missing_csp_fails(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "fail")
        self.assertEqual(c.earned, 0)

    def test_strict_csp_passes(self):
        checks, _, _ = analyze({"content-security-policy": "default-src 'self'"})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "pass")
        self.assertEqual(c.earned, c.weight)

    def test_unsafe_inline_warns(self):
        checks, _, _ = analyze({
            "content-security-policy":
                "default-src 'self'; script-src 'self' 'unsafe-inline'"})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "warn")
        self.assertIn("unsafe-inline", c.summary)

    def test_unsafe_eval_warns(self):
        checks, _, _ = analyze({
            "content-security-policy":
                "default-src 'self'; script-src 'unsafe-eval'"})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "warn")
        self.assertIn("unsafe-eval", c.summary)

    def test_wildcard_script_src_warns(self):
        checks, _, _ = analyze({
            "content-security-policy": "default-src 'self'; script-src *"})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "warn")

    def test_default_src_fallback_for_scripts(self):
        checks, _, _ = analyze({
            "content-security-policy": "default-src 'unsafe-inline'"})
        c = check_by_name(checks, "Content-Security-Policy")
        self.assertEqual(c.status, "warn")


class HstsTests(unittest.TestCase):
    def test_missing_hsts_fails_on_https(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Strict-Transport-Security")
        self.assertEqual(c.status, "fail")

    def test_strong_hsts_passes(self):
        checks, _, _ = analyze({
            "strict-transport-security":
                "max-age=31536000; includeSubDomains; preload"})
        c = check_by_name(checks, "Strict-Transport-Security")
        self.assertEqual(c.status, "pass")
        self.assertEqual(c.earned, c.weight)

    def test_short_max_age_warns(self):
        checks, _, _ = analyze({
            "strict-transport-security": "max-age=300"})
        c = check_by_name(checks, "Strict-Transport-Security")
        self.assertEqual(c.status, "warn")

    def test_invalid_max_age_warns(self):
        checks, _, _ = analyze({
            "strict-transport-security": "max-age=abc"})
        c = check_by_name(checks, "Strict-Transport-Security")
        self.assertEqual(c.status, "warn")

    def test_plain_http_is_info_not_fail(self):
        checks, _, _ = analyze({}, url="http://example.com/")
        c = check_by_name(checks, "Strict-Transport-Security")
        self.assertEqual(c.status, "info")


class XContentTypeOptionsTests(unittest.TestCase):
    def test_nosniff_passes(self):
        checks, _, _ = analyze({"x-content-type-options": "nosniff"})
        c = check_by_name(checks, "X-Content-Type-Options")
        self.assertEqual(c.status, "pass")

    def test_case_insensitive(self):
        checks, _, _ = analyze({"x-content-type-options": "NoSniff"})
        c = check_by_name(checks, "X-Content-Type-Options")
        self.assertEqual(c.status, "pass")

    def test_missing_fails(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "X-Content-Type-Options")
        self.assertEqual(c.status, "fail")


class ClickjackingTests(unittest.TestCase):
    def test_xfo_deny_passes(self):
        checks, _, _ = analyze({"x-frame-options": "DENY"})
        c = check_by_name(checks, "Clickjacking protection")
        self.assertEqual(c.status, "pass")

    def test_xfo_sameorigin_passes(self):
        checks, _, _ = analyze({"x-frame-options": "sameorigin"})
        c = check_by_name(checks, "Clickjacking protection")
        self.assertEqual(c.status, "pass")

    def test_frame_ancestors_passes(self):
        checks, _, _ = analyze({
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'"})
        c = check_by_name(checks, "Clickjacking protection")
        self.assertEqual(c.status, "pass")

    def test_missing_fails(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Clickjacking protection")
        self.assertEqual(c.status, "fail")


class ReferrerPolicyTests(unittest.TestCase):
    def test_good_value_passes(self):
        checks, _, _ = analyze({
            "referrer-policy": "strict-origin-when-cross-origin"})
        c = check_by_name(checks, "Referrer-Policy")
        self.assertEqual(c.status, "pass")

    def test_weak_value_warns(self):
        checks, _, _ = analyze({"referrer-policy": "unsafe-url"})
        c = check_by_name(checks, "Referrer-Policy")
        self.assertEqual(c.status, "warn")


    def test_comma_list_uses_last_value(self):
        checks, _, _ = analyze({
            "referrer-policy":
                "origin-when-cross-origin, strict-origin-when-cross-origin"})
        c = check_by_name(checks, "Referrer-Policy")
        self.assertEqual(c.status, "pass")

    def test_missing_warns(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Referrer-Policy")
        self.assertEqual(c.status, "warn")


class PermissionsPolicyTests(unittest.TestCase):
    def test_present_passes(self):
        checks, _, _ = analyze({"permissions-policy": "camera=(), microphone=()"})
        c = check_by_name(checks, "Permissions-Policy")
        self.assertEqual(c.status, "pass")

    def test_missing_warns(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Permissions-Policy")
        self.assertEqual(c.status, "warn")


class InfoDisclosureTests(unittest.TestCase):
    def test_version_number_warns(self):
        checks, _, _ = analyze({"server": "nginx/1.25.3"})
        c = check_by_name(checks, "Version disclosure")
        self.assertEqual(c.status, "warn")
        self.assertEqual(c.earned, 0)

    def test_bare_name_passes(self):
        checks, _, _ = analyze({"server": "GitHub.com"})
        c = check_by_name(checks, "Version disclosure")
        self.assertEqual(c.status, "pass")

    def test_no_server_header_passes(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Version disclosure")
        self.assertEqual(c.status, "pass")


class CookieTests(unittest.TestCase):
    def test_no_cookies_passes(self):
        checks, _, _ = analyze({})
        c = check_by_name(checks, "Cookie security")
        self.assertEqual(c.status, "pass")

    def test_flagless_cookie_warns(self):
        checks, _, _ = analyze({
            "set-cookie-list": ["session=abc; Path=/"]})
        c = check_by_name(checks, "Cookie security")
        self.assertEqual(c.status, "warn")
        self.assertIn("Secure", c.summary)

    def test_fully_flagged_cookie_passes(self):
        checks, _, _ = analyze({
            "set-cookie-list": [
                "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]})
        c = check_by_name(checks, "Cookie security")
        self.assertEqual(c.status, "pass")


class CorsTests(unittest.TestCase):
    def test_wildcard_is_info(self):
        checks, _, _ = analyze({"access-control-allow-origin": "*"})
        c = check_by_name(checks, "CORS")
        self.assertEqual(c.status, "info")

    def test_no_cors_header_no_check(self):
        checks, _, _ = analyze({})
        self.assertFalse(any(c.name == "CORS" for c in checks))


class ScoringTests(unittest.TestCase):
    FULLY_SECURED = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "server": "cdn",
    }

    def test_fully_secured_site_scores_a(self):
        _, score, grade = analyze(self.FULLY_SECURED)
        self.assertGreaterEqual(score, 90)
        self.assertIn(grade, ("A", "A+"))

    def test_bare_site_scores_low(self):
        _, score, grade = analyze({"server": "nginx"})
        self.assertLess(score, 55)
        self.assertIn(grade, ("D", "F"))

    def test_github_pages_like_headers(self):
        # Mirrors what GitHub Pages actually sends.
        _, score, grade = analyze({
            "server": "GitHub.com",
            "strict-transport-security": "max-age=31556952",
            "access-control-allow-origin": "*",
        })
        self.assertLess(score, 70)
        self.assertGreater(score, 0)


class HeadersDictTests(unittest.TestCase):
    def test_set_cookie_list_collected(self):
        msg = Message()
        msg.add_header("Set-Cookie", "a=1; Secure")
        msg.add_header("Set-Cookie", "b=2; HttpOnly")
        msg.add_header("Content-Type", "text/html")
        headers = hc._headers_dict(msg)
        self.assertEqual(headers["content-type"], "text/html")
        self.assertEqual(headers["set-cookie-list"], ["a=1; Secure", "b=2; HttpOnly"])


class CliTests(unittest.TestCase):
    def test_json_output_shape(self):
        fake = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
        }
        with mock.patch.object(
                hc, "fetch_headers", return_value=(HTTPS, fake)):
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = hc.main(["example.com", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["url"], "https://example.com")
        self.assertIn("score", data)
        self.assertIn("grade", data)
        self.assertTrue(any(
            c["name"] == "Content-Security-Policy" for c in data["checks"]))

    def test_text_report_runs(self):
        with mock.patch.object(hc, "fetch_headers", return_value=(HTTPS, {})):
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = hc.main(["example.com"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Score:", out)
        self.assertIn("[fail] Content-Security-Policy", out)

    def test_fetch_error_returns_1(self):
        with mock.patch.object(
                hc, "fetch_headers", side_effect=RuntimeError("boom")):
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = hc.main(["example.com"])
        self.assertEqual(rc, 1)
        self.assertIn("could not fetch", err.getvalue())

    def test_empty_url_returns_2(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            rc = hc.main(["   "])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
