# php2shell-scan

Authorized PoC scanner for self-testing PHP sites. Run only against hosts you own.

Four non-destructive-by-default checks:

| Module | Behaviour |
|---|---|
| `webshell` | GETs common planted-shell paths and matches known banners/signatures. |
| `lfi` | Tries `../etc/passwd` and `php://filter` through common param names; matches `root:x:0:0:` or base64-encoded PHP in the response. |
| `exposure` | phpinfo, `.env`, `*.bak`, `.git/config`, Adminer, server-status, plus PHP version / EOL from headers and a `session.upload_progress` hygiene note. |
| `uploads` | **Opt-in.** POSTs a token-echo file (`<?php echo 'P2S-<token>'; ?>`) against an endpoint you give it, then fetches it back. If the token comes back *without* the `<?php` tag, the server executed it → HIGH finding, and the report tells you which URL to delete. Not a usable shell. |

The uploads module is the only one that writes anything. Everything else is read-only GETs.

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
