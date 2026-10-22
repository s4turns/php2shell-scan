# php2shell-scan

Authorized PoC scanner for self-testing PHP sites. Run only against hosts you own.

Five non-destructive-by-default checks:

| Module | Behaviour |
|---|---|
| `webshell` | GETs common planted-shell paths and matches known banners/signatures. |
| `lfi` | Tries `../etc/passwd` and `php://filter` through common param names; matches `root:x:0:0:` or base64-encoded PHP in the response. On a hit, also probes `/var/lib/php/sessions/` etc. for session-file readability (the chain primitive). |
| `exposure` | phpinfo, `.env`, `*.bak`, `.git/config`, Adminer, server-status, plus PHP version / EOL from headers and known-RCE path probes (PHPUnit, Ignition, ThinkPHP). |
| `php2shell` | Safe behavioural probe for the `session.upload_progress` attack surface. Sends a benign multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and watches the response headers — if the server sets a fresh `PHPSESSID` cookie off that one request, the handler is enabled. **No crash probe, no exploit payload.** |
| `uploads` | **Opt-in.** POSTs a token-echo file (`<?php echo 'P2S-<token>'; ?>`) against an endpoint you give it, then fetches it back. If the token comes back *without* the `<?php` tag, the server executed it → HIGH finding, and the report tells you which URL to delete. Not a usable shell. |

### Speed

Scanning is concurrent per-module (`--workers`, default 10) and across targets (`--target-workers`, default 4). Default per-request delay is 0; raise it (`--delay 0.3`) if the server complains. A full read-only sweep of one target is typically <2s.

The uploads module is the only one that writes anything. Everything else is read-only GETs.

### Known-CVE coverage (banner / path fingerprinting, no exploit payloads)

| CVE | What it is | How this scanner checks |
|---|---|---|
| CVE-2024-4577 | PHP-CGI argument injection on Windows (Best-Fit bypass of CVE-2012-1823) | PHP version in headers + `Server` indicating Windows / IIS |
| CVE-2019-11043 | PHP-FPM buffer underflow via nginx `fastcgi_split_path_info` | PHP version in headers + `Server: nginx` |
| CVE-2017-9841 | PHPUnit `eval-stdin.php` left in `vendor/` | GET of the known paths, body matches `<?php` |
| CVE-2021-3129 | Laravel Ignition RCE in debug mode | GET `_ignition/execute-solution` presence |
| ThinkPHP ~5.0 RCE class | `invokefunction` endpoint reachable | GET of the endpoint path (no payload) |
| session.upload_progress → LFI | Chain that turns LFI into RCE via a crafted session file | If a basic LFI hits, probe common session dirs (`/var/lib/php/sessions/`, `/tmp/`, etc.) |

These are detection-only — none of them sends a working exploit.

## Install

```bash
pip install requests
```

## Use

```bash
# safe read-only sweep
python scanner.py https://your-site.example

# upload-fuzz an endpoint you own
python scanner.py https://your-site.example \
    --upload-url https://your-site.example/upload.php \
    --upload-field file

# limit to specific modules
python scanner.py https://a.example https://b.example --only webshell,exposure

# self-signed cert on a LAN host
python scanner.py https://192.168.0.177 --insecure

# politer: 1s between requests
python scanner.py https://your-site.example --delay 1.0
```

Exit code is `2` when any HIGH finding is recorded, so it can be wired into cron or CI.

## Notes

- A HIGH from `uploads` leaves a token-echo file on disk. The URL is printed; remove it.
- `EOL_BRANCHES` in `scanner.py` is a static snapshot. Bump it against php.net when a PHP branch ages out.
- `session.upload_progress` can't be probed over HTTP; the scanner just reminds you to check `php -i | grep upload_progress` on each host and set it to `Off` if you don't need upload-progress tracking.

## Only test what you own

The signatures and payloads here are deliberately defensive-focused (detection, not weaponization). Use it on your own infrastructure.
