#!/usr/bin/env python3
"""Scan the MoneyLeak public website source and deployed HTTPS legal pages.
Does not access bank records, accounts, or backend secrets.
"""
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen

BASE = "https://moneyleak-website.onrender.com/"
PAGES = ("index.html", "privacy.html", "terms.html", "deletion.html")
patterns = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_access_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{28,}"),
    "plaid_secret_assignment": re.compile(r"PLAID_SECRET\s*[=:]\s*[^\s<>{}]{16,}", re.I),
}

def source_scan():
    tracked = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\x00")
    forbidden = [name for name in tracked if Path(name).name.startswith(".env") and not name.endswith(".example")]
    if forbidden:
        raise RuntimeError("private .env files are tracked")
    for name in tracked:
        if not name:
            continue
        path = Path(name)
        if not path.is_file() or path.stat().st_size > 1_000_000 or path.suffix in (".png", ".jpg", ".zip"):
            continue
        value = path.read_text(errors="replace")
        for label, regex in patterns.items():
            if regex.search(value):
                raise RuntimeError("possible tracked secret pattern: " + label + " in " + name)
    scripts = [name for name in tracked if name.endswith((".js", ".mjs", ".cjs", "package.json", "package-lock.json"))]
    if scripts:
        raise RuntimeError("website now contains JS/npm dependencies; extend scanning to dependency CVEs first")
    for name in PAGES:
        if name not in tracked:
            raise RuntimeError("missing required policy/landing page: " + name)
    print(f"PASS: {len(tracked)} tracked files reviewed, zero high-risk secrets; static HTML/CSS with no executable JS/npm dependency tree")

def deployed_https_scan():
    for name in PAGES:
        url = BASE + name
        last_error = None
        for attempt in range(3):
            try:
                # urllib verifies the server certificate + hostname against system trust.
                request = Request(url, headers={"User-Agent": "MoneyLeak-Website-Security-CI/1.0"})
                with urlopen(request, timeout=35) as response:
                    actual = response.geturl()
                    code = response.status
                    body = response.read(140_000).decode("utf-8", "replace")
                if not actual.startswith(BASE) or code != 200:
                    raise RuntimeError("unexpected deployed website response")
                if "<h1" not in body.lower() or "MoneyLeak" not in body:
                    raise RuntimeError("deployed page is missing expected content")
                if name in ("privacy.html", "terms.html") and "KB SERVICES INT INC" not in body:
                    raise RuntimeError("deployed legal page omits operating business")
                print("PASS HTTPS/TLS and deployed page:", name)
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(3 * (attempt + 1))
        if last_error is not None:
            raise RuntimeError("deployment/TLS check failed on " + name) from last_error

if __name__ == "__main__":
    source_scan()
    deployed_https_scan()
    print("SCOPE: source secrets, static dependency inventory, TLS hostname verification, and published legal pages; no OS/workstation/DAST/pen-test assertions.")
