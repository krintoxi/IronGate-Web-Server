#!/usr/bin/env python3
"""Smoke test for a running IronGate: serves the site, refuses what it must, runs PHP if php-cgi is there.

    python Tools/smoke-test.py http://127.0.0.1:8080 [--windows] [--php]

Each request comes from its own made-up address (X-Forwarded-For), so the refusals being tested do not add up to an
automatic ban of the test itself. Exits 1 if anything fails.
"""
import sys
import time
import urllib.error
import urllib.request

base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
windows = "--windows" in sys.argv
php = "--php" in sys.argv
failures = 0
n = 0


def get(path):
    global n
    n += 1
    req = urllib.request.Request(base + path, headers={"X-Forwarded-For": f"203.0.113.{n % 250 + 1}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check(path, ok, what):
    global failures
    code, body = get(path)
    good = ok(code, body)
    print(f"[{'PASS' if good else 'FAIL'}] {what:<52} {path!r} -> {code}")
    if not good:
        failures += 1


for _ in range(60):   # wait for the server to come up
    try:
        get("/")
        break
    except Exception:
        time.sleep(1)
else:
    print("[FAIL] server never answered at", base)
    sys.exit(1)

check("/", lambda c, b: c == 200, "home page")
check("/.htaccess", lambda c, b: c in (403, 404), "never serves .htaccess")
check("/../server.py", lambda c, b: c in (403, 404), "no way out of WWW")
check("/..%2f..%2fserver.py", lambda c, b: c in (403, 404), "no way out of WWW (encoded)")
check("/x.db", lambda c, b: c in (403, 404), "blocked extension")

if windows:
    check("/index.html.", lambda c, b: c == 403, "trailing dot refused")
    check("/index.html%20", lambda c, b: c in (403, 404), "trailing space refused")
    check("/index.html::$DATA", lambda c, b: c == 403, "alternate data stream refused")
    check("/CON", lambda c, b: c == 403, "device name refused")
    check("/nul.txt", lambda c, b: c == 403, "device name with extension refused")
    check("/..\\server.py", lambda c, b: c in (403, 404), "backslash traversal refused")
    check("/INDEX.HTML", lambda c, b: c == 200, "case-insensitive file found")

if php:
    check("/_smoke.php", lambda c, b: c == 200 and b"IRONGATE-PHP-OK" in b and b"<?php" not in b, "PHP runs")
    check("/_SMOKE.PHP", lambda c, b: b"<?php" not in b, "upper-case .PHP never leaks source")

print(f"\n{failures} failure(s)")
sys.exit(1 if failures else 0)
