# headercheck

Inspect the HTTP security headers of a URL.

`headercheck` sends a single GET request to a URL you give it, reads the
response headers, and reports which security headers are present, which
are missing, and what each one does. It prints a score out of 100 with a
letter grade.

It is read-only. It sends one request and nothing else: no scanning, no
probing, no brute forcing. Point it at sites you own or have permission
to test.

## Requirements

Python 3.8 or newer. No third-party packages.

## Usage

```
python headercheck.py https://example.com
python headercheck.py example.com --json
```

`--json` prints the report as JSON instead of text. `--timeout N` changes
the request timeout (default 15 seconds).

## What it checks

| Check | Weight | What it protects against |
| --- | --- | --- |
| Content-Security-Policy | 25 | Content injection (XSS). A present but permissive policy (`unsafe-inline`, `unsafe-eval`, wildcard script source) earns half. |
| Strict-Transport-Security | 15 | HTTPS downgrade attacks. Short or invalid `max-age` earns half. Plain-HTTP URLs are marked info, not failed. |
| Clickjacking protection | 15 | Framing attacks. `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors`. |
| X-Content-Type-Options | 10 | MIME sniffing. Only `nosniff` passes. |
| Referrer-Policy | 10 | URL leakage through the Referer header. Missing or weak values earn half. |
| Permissions-Policy | 10 | Unwanted access to camera, microphone, geolocation, etc. Missing earns half. |
| Cookie security | 10 | Cookies without `Secure`, `HttpOnly`, `SameSite`. Passes automatically when the response sets no cookies. |
| Version disclosure | 5 | Exact server/framework versions in headers, which help attackers pick known exploits. |

It also notes a wildcard `Access-Control-Allow-Origin: *` (fine for
public content, a problem for private content) without scoring it.

Grades: A+ 95, A 90, B 80, C 70, D 55, F below 55.

## Example

Running it against my own site (hosted on GitHub Pages):

```
$ python headercheck.py https://id-er2.github.io/
headercheck report
  URL:   https://id-er2.github.io/
  Score: 40/100 (F)

[fail] Content-Security-Policy: missing
[ok]   Strict-Transport-Security: max-age=31556952; no includeSubDomains
[fail] X-Content-Type-Options: missing
[fail] Clickjacking protection: missing
[warn] Referrer-Policy: missing
[warn] Permissions-Policy: missing
[ok]   Version disclosure: no version numbers exposed
[ok]   Cookie security: no cookies set by this response
[info] CORS: Access-Control-Allow-Origin: *
```

Worth knowing: GitHub Pages does not let you set custom response
headers, so most of these cannot be fixed while the site stays on that
host. The HSTS header above comes from GitHub itself. That limitation is
part of why I wrote the tool: the score tells you what your hosting
actually gives you, not what you configured yourself.

For comparison, `github.com` scores 90/100 (A).

## How it works

One GET request with a `headercheck` user agent. Redirects are followed
up to 5 times and the final URL is reported. The analysis is pure
functions over the response headers (`analyze()`), which is what the
tests exercise; the network part is a thin wrapper around
`urllib.request`.

## Tests

```
python -m unittest discover -s tests
```

44 tests covering each check, the scoring and grade boundaries,
multi-value headers (Set-Cookie, comma-separated Referrer-Policy), and
the CLI (text and JSON output, fetch errors, bad input).

## Exit codes

- `0` - report printed
- `1` - the URL could not be fetched
- `2` - bad arguments

## License

MIT
