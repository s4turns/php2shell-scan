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
    workers: int = 10
    findings: list[Finding] = field(default_factory=list)
    _lock: object = field(default_factory=lambda: __import__("threading").Lock())

    def get(self, url: str, **kw):
        if self.delay:
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
        if self.delay:
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

    def fanout(self, urls, fn):
        """Fetch many URLs concurrently and call fn(url, response) for each."""
        with cf.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self.get, u): u for u in urls}
            for fut in cf.as_completed(futs):
                fn(futs[fut], fut.result())

    def add(self, f: Finding):
        with self._lock:
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
    urls = [urljoin(base + "/", p) for p in WEBSHELL_PATHS]

    def handle(url, r):
        if not r or r.status_code != 200 or not r.text:
            return
        for rx, label in WEBSHELL_SIGS:
            m = rx.search(r.text)
            if m:
                ctx.add(Finding(base, "webshell", SEV_HIGH,
                                f"Possible planted webshell ({label})",
                                url, m.group(0)[:120]))
                return
        if re.search(r"<form[^>]*method=['\"]?post", r.text, re.I) \
                and len(r.text) < 60000:
            ctx.add(Finding(base, "webshell", SEV_MED,
                            "Suspicious PHP file responds with a POST form",
                            url, f"{len(r.text)} bytes"))

    ctx.fanout(urls, handle)


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
        ("poc.pht", "image/jpeg", marker),                 # alt php ext (older Debian)
        ("poc.php5", "image/jpeg", marker),
        ("poc.php7", "image/jpeg", marker),
        ("poc.phar", "image/jpeg", marker),                # mapped to PHP in some setups
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

# Session file paths — relevant to the session.upload_progress → LFI chain.
# Reading one of these via LFI is the primitive that chain depends on.
SESSION_PATHS = [
    "/var/lib/php/sessions/",
    "/tmp/",
    "/var/lib/php5/",
    "/var/lib/php7/",
    "/var/lib/php8/",
]

PASSWD_RX = re.compile(r"root:.*:0:0:")
B64_PHP_RX = re.compile(r"PD9waHA|PCFET0NUWVBF")  # base64 of "<?php" / "<!DOCTYP"


def mod_lfi(ctx: Ctx, base: str):
    hit_params: set[str] = set()
    url_map = {f"{base}/?{p}={pl}": (p, pl)
               for p in LFI_PARAMS for pl in LFI_PAYLOADS}

    def handle(url, r):
        if not r or not r.text:
            return
        param, payload = url_map[url]
        if PASSWD_RX.search(r.text):
            ctx.add(Finding(base, "lfi", SEV_HIGH,
                            f"LFI: /etc/passwd via ?{param}=",
                            url, "root:...:0:0:"))
            hit_params.add(param)
        elif "php://filter" in payload and B64_PHP_RX.search(r.text):
            ctx.add(Finding(base, "lfi", SEV_HIGH,
                            f"LFI: php://filter leaks PHP source via ?{param}=",
                            url, "base64 of PHP returned"))
            hit_params.add(param)

    ctx.fanout(list(url_map), handle)

    # Session-file probe fires only if a basic LFI already landed. Primitive
    # for the session.upload_progress → RCE chain.
    if not hit_params:
        return
    session_urls = [f"{base}/?{param}={sdir}sess_probe"
                    for param in hit_params for sdir in SESSION_PATHS]

    def handle_sess(url, r):
        if not r or r.status_code != 200 or len(r.text or "") >= 50000:
            return
        body = r.text or ""
        if "php" in body.lower() or "upload_progress" in body:
            ctx.add(Finding(base, "lfi", SEV_HIGH,
                            "Session file reachable via LFI "
                            "(session.upload_progress → RCE chain primitive)",
                            url, "common session dir"))

    ctx.fanout(session_urls, handle_sess)


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

# Known-vulnerable PHP version ceilings (fixed in these, so < = vulnerable).
# CVE-2024-4577: PHP-CGI Windows argument injection (Best-Fit bypass of CVE-2012-1823)
CVE_2024_4577_FIXED = {(8, 1): 29, (8, 2): 20, (8, 3): 8}
# CVE-2019-11043: PHP-FPM nginx underflow
CVE_2019_11043_FIXED = {(7, 1): 33, (7, 2): 24, (7, 3): 11}
# "php2shell 2026" session.upload_progress claim from jackalsyn.com — the CVE
# IDs listed on that page (CVE-2026-109618 / 109619) do NOT match NVD numbering
# and are not corroborated by any upstream advisory I can verify. Treated as
# page-reported-unverified; included so coverage follows the user-supplied
# source material.
JACKALSYN_FIXED = {(8, 2): 34, (8, 3): 35, (8, 4): 26, (8, 5): 11}

# IOC: lab-marker string the page's PoC embeds in multipart boundaries.
JACKALSYN_IOC = "UctxPoc2026"

# Known RCE endpoints to probe (path-only, no exploit payload sent).
KNOWN_RCE_PATHS = {
    # CVE-2017-9841 — PHPUnit eval-stdin.php left in vendor dir
    "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php":
        ("PHPUnit eval-stdin.php exposed (CVE-2017-9841)", SEV_HIGH, "<?php"),
    "vendor/phpunit/phpunit/Util/PHP/eval-stdin.php":
        ("PHPUnit eval-stdin.php exposed (CVE-2017-9841)", SEV_HIGH, "<?php"),
    # CVE-2021-3129 — Laravel Ignition in debug mode
    "_ignition/execute-solution":
        ("Laravel Ignition endpoint reachable (CVE-2021-3129 if debug=on)",
         SEV_HIGH, "ignition"),
    "_ignition/health-check":
        ("Laravel Ignition health-check reachable",
         SEV_MED, "ignition"),
    # ThinkPHP ~5.0 RCE — endpoint presence only, no payload
    "index.php?s=/Index/\\think\\app/invokefunction":
        ("ThinkPHP invokefunction endpoint reachable (RCE class)",
         SEV_HIGH, "ThinkPHP"),
}


def mod_exposure(ctx: Ctx, base: str):
    exposure_urls = {urljoin(base + "/", p): p for p in EXPOSURE_PATHS}

    def handle_exp(url, r):
        if not r or r.status_code != 200 or not r.text:
            return
        p = exposure_urls[url]
        title, sev = EXPOSURE_PATHS[p]
        body = r.text
        if p in ("phpinfo.php", "info.php") and not PHPINFO_RX.search(body):
            return
        if p == ".env" and "=" not in body:
            return
        if p == ".git/config" and "[core]" not in body:
            return
        ctx.add(Finding(base, "exposure", sev, title, url,
                        body.strip().splitlines()[0][:100] if body.strip() else ""))

    ctx.fanout(list(exposure_urls), handle_exp)

    # known-RCE path probes (no exploit payload, just presence detection)
    rce_urls = {urljoin(base + "/", p): p for p in KNOWN_RCE_PATHS}

    def handle_rce(url, r):
        if not r or r.status_code not in (200, 405, 500):
            return
        p = rce_urls[url]
        title, sev, needle = KNOWN_RCE_PATHS[p]
        if needle.lower() in (r.text or "").lower() or r.status_code == 405:
            ctx.add(Finding(base, "exposure", sev, title, url,
                            f"HTTP {r.status_code}"))

    ctx.fanout(list(rce_urls), handle_rce)

    # version / header hygiene — folds in CVE-2024-4577 (Windows CGI) and
    # CVE-2019-11043 (nginx + PHP-FPM) banner-level detection
    r = ctx.get(base + "/")
    if r:
        server_hdr = r.headers.get("Server", "")
        powered_hdr = r.headers.get("X-Powered-By", "")
        hdr = powered_hdr + " " + server_hdr
        m = PHP_VER_HDR.search(hdr)
        if m:
            major, minor, patch = map(int, m.groups())
            branch = (major, minor)
            note = f"PHP {major}.{minor}.{patch} advertised in headers"
            if branch in EOL_BRANCHES:
                ctx.add(Finding(base, "exposure", SEV_MED,
                                f"End-of-life PHP branch ({major}.{minor})",
                                base, note + " — no security fixes"))
            else:
                ctx.add(Finding(base, "exposure", SEV_INFO,
                                "PHP version disclosed in headers", base, note))
            # CVE-2024-4577: Windows + PHP-CGI + vulnerable branch
            fixed_patch = CVE_2024_4577_FIXED.get(branch)
            windows_hint = ("microsoft-iis" in server_hdr.lower()
                            or "win" in server_hdr.lower())
            if fixed_patch is not None and patch < fixed_patch and windows_hint:
                ctx.add(Finding(base, "exposure", SEV_HIGH,
                                "CVE-2024-4577 candidate: vulnerable PHP + Windows",
                                base,
                                f"{note}; fixed in {branch[0]}.{branch[1]}.{fixed_patch}"))
            elif fixed_patch is not None and patch < fixed_patch:
                ctx.add(Finding(base, "exposure", SEV_LOW,
                                "CVE-2024-4577 patch missing (only exploitable on Windows CGI)",
                                base, note))
            # CVE-2019-11043: nginx + PHP-FPM vulnerable branch
            fpm_fixed = CVE_2019_11043_FIXED.get(branch)
            nginx_hint = "nginx" in server_hdr.lower()
            if fpm_fixed is not None and patch < fpm_fixed and nginx_hint:
                ctx.add(Finding(base, "exposure", SEV_HIGH,
                                "CVE-2019-11043 candidate: vulnerable PHP + nginx",
                                base,
                                f"{note}; fixed in {branch[0]}.{branch[1]}.{fpm_fixed}; "
                                "check nginx config for fastcgi_split_path_info"))
            ctx.add(Finding(base, "exposure", SEV_INFO,
                            "Check session.upload_progress on this host",
                            base, "php -i | grep upload_progress  (disable if unused)"))


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

def mod_php2shell(ctx: Ctx, base: str):
    """
    Coverage for the 'php2shell 2026' attack-surface claim (jackalsyn.com),
    all non-destructive:

      1. Behavioural probe for session.upload_progress handler being enabled
         (a benign multipart POST + PHP_SESSION_UPLOAD_PROGRESS -> PHPSESSID
         set in Set-Cookie).
      2. Severity escalation when banner suggests Apache prefork + mod_php
         (the only SAPI the page reports as affected).
      3. Version-ceiling check against the page's claimed "fixed in" releases
         (8.2.34 / 8.3.35 / 8.4.26 / 8.5.11). PHP 7.x is flagged permanently
         vulnerable per the page.
      4. IOC scan for the lab marker 'UctxPoc2026' in response bodies.

    What this module intentionally does NOT do:
      * Send oversized multipart POSTs or boundary-crafted requests designed
        to trigger memory exhaustion / SIGSEGV. That is a DoS probe at your
        live PHP, and the page itself contradicts whether that path yields
        code execution. Disable the handler as the page recommends; this
        scanner confirms whether disabling is needed, not whether a crash
        can be induced.
      * Fetch or run the 'PoC bundle' linked on that page.
    """
    tok = token(10)
    sid = token(26)
    headers = {"Cookie": f"PHPSESSID={sid}"}
    data = {"PHP_SESSION_UPLOAD_PROGRESS": f"probe-{tok}"}
    files = {"f": ("probe.txt", f"benign-{tok}".encode(), "text/plain")}
    r = ctx.post(base + "/", headers=headers, data=data, files=files)
    if not r:
        return

    server_hdr = r.headers.get("Server", "")
    powered_hdr = r.headers.get("X-Powered-By", "")
    body = r.text or ""

    # (1) handler-enabled behavioural tell
    saw_phpsessid = "PHPSESSID=" in r.headers.get("Set-Cookie", "")

    # (2) SAPI inference — mod_php on Apache (prefork or otherwise) is the
    # only SAPI the page reports as affected. FPM / CGI / nginx are reported
    # unaffected. We can only guess from headers.
    looks_apache = "apache" in server_hdr.lower()
    looks_nginx = "nginx" in server_hdr.lower()
    looks_php = "php" in powered_hdr.lower() or "php" in server_hdr.lower()
    sapi_note = ""
    if looks_apache and looks_php:
        sapi_note = "Apache + PHP in headers — mod_php/prefork plausible"
    elif looks_nginx:
        sapi_note = "nginx in Server header — likely FPM (page reports unaffected)"

    if saw_phpsessid:
        sev = SEV_HIGH if looks_apache and looks_php else SEV_MED
        ctx.add(Finding(base, "php2shell", sev,
                        "session.upload_progress handler appears enabled "
                        "(benign multipart POST triggered a PHPSESSID)",
                        base,
                        f"disable with session.upload_progress.enabled = Off"
                        + (f"; {sapi_note}" if sapi_note else "")))

    # (3) version-ceiling check against the page's claimed fixed releases
    m = PHP_VER_HDR.search(powered_hdr + " " + server_hdr)
    if m:
        major, minor, patch = map(int, m.groups())
        branch = (major, minor)
        if major == 7:
            ctx.add(Finding(base, "php2shell", SEV_HIGH,
                            "PHP 7.x: page claims no fix will ship for this branch",
                            base,
                            f"advertised PHP {major}.{minor}.{patch}; "
                            "page-reported, unverified"))
        else:
            fixed = JACKALSYN_FIXED.get(branch)
            if fixed is not None and patch < fixed:
                esc = SEV_HIGH if looks_apache and looks_php else SEV_MED
                ctx.add(Finding(base, "php2shell", esc,
                                f"PHP {branch[0]}.{branch[1]}.{patch} < "
                                f"page-reported fix {branch[0]}.{branch[1]}.{fixed}",
                                base,
                                "CVE IDs from the source page do not match NVD "
                                "numbering; treat as page-reported, unverified"
                                + (f"; {sapi_note}" if sapi_note else "")))

    # (4) IOC — if someone already ran that public PoC at this host, the lab
    # marker often shows up echoed in error pages / debug output / logs that
    # get served back.
    if JACKALSYN_IOC in body:
        ctx.add(Finding(base, "php2shell", SEV_HIGH,
                        f"IOC: lab-marker '{JACKALSYN_IOC}' appears in response "
                        "(indicates the public PoC was fired at this host)",
                        base, body[:120]))

    # Advisory: things only visible server-side
    ctx.add(Finding(base, "php2shell", SEV_INFO,
                    "Server-side checks the scanner can't do over HTTP",
                    base,
                    "grep PHP error log for 'Allowed memory size ... exhausted' "
                    "and 'open(... sess_...) failed'; watch for SIGSEGV in Apache "
                    "children; consider WAF rate-limit on multipart POSTs to "
                    "endpoints that don't take uploads"))


MODULES: dict[str, Callable] = {
    "webshell": mod_webshell,
    "lfi": mod_lfi,
    "exposure": mod_exposure,
    "php2shell": mod_php2shell,
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
    ap.add_argument("--delay", type=float, default=0.0,
                    help="per-request sleep (default 0; raise if the server protests)")
    ap.add_argument("--workers", type=int, default=10,
                    help="concurrent requests per module (default 10)")
    ap.add_argument("--target-workers", type=int, default=4,
                    help="concurrent targets scanned at once (default 4)")
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

    # Give the pooled session enough connections for the concurrency we want.
    for prefix in ("https://", "http://"):
        adapter = HTTPAdapter(pool_connections=args.workers * 2,
                              pool_maxsize=args.workers * 2,
                              max_retries=Retry(total=2, backoff_factor=0.3,
                                                status_forcelist=(502, 503, 504),
                                                allowed_methods=False))
        sess.mount(prefix, adapter)

    ctx = Ctx(session=sess, delay=args.delay, verbose=args.verbose,
              workers=args.workers)

    print(f"php2shell-scan — authorized self-test only "
          f"(workers={args.workers}, targets={args.target_workers}).")
    t0 = time.time()
    if args.target_workers > 1 and len(args.targets) > 1:
        with cf.ThreadPoolExecutor(max_workers=args.target_workers) as ex:
            list(ex.map(lambda t: scan_target(ctx, t, only, upload_cfg),
                        args.targets))
    else:
        for t in args.targets:
            scan_target(ctx, t, only, upload_cfg)
    print(f"\n({time.time()-t0:.1f}s elapsed)")

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
