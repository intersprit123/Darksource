# DarkSource UE

Terminal-first website resource mapper designed for Termux and Kali/Linux.

## Install in Termux
```bash
pkg update
pkg install python git curl
git clone https://github.com/intersprit123/Darksource.git
cd Darksource
python -m pip install -r requirements.txt
```
Or run `bash install_termux.sh`.

## Website mapping
```bash
python darksource.py https://example.com
python darksource.py https://example.com --max-pages 40 -o ./capture
python darksource.py https://your-own-site.example -A
python darksource.py https://example.com --include-external
```

The `-A` option offers a limited, non-destructive security review and asks for authorization first. It checks selected response headers and a short list of common public paths. HTTP 200 alone does not prove a vulnerability.

## Phone metadata
```bash
python darksource.py --phone +14155552671
python darksource.py --phone 02083661177 --region GB
```
Uses offline numbering-plan metadata via `phonenumbers`. It cannot find GPS/live location, identify a subscriber, reliably reveal the current carrier, or find accounts linked to a number.

## Email domain check
```bash
python darksource.py --email you@example.com
```
Performs a basic format/domain DNS check only. It does not verify a mailbox or enumerate accounts linked to an email/phone.

## Output
- `darksource-output/`: downloaded files
- `darksource-manifest.json`: resource URLs, response metadata, static references
- `REPORT.md`: summary and API-like URL hints
- `security-audit.json`: optional audit observations

The program creates discovered folders before downloads and saves files by URL-path depth.

## Current limitations
- No JavaScript execution, embedded browser, or browser-only request/WebSocket capture yet.
- URL paths are approximations of local paths, not the server's real filesystem.
- It cannot recover private server source, databases, or access-controlled files.
- API hints come from static references; state-changing requests are not replayed.
- Follow site terms, robots policy, privacy rules, and applicable law. Analyze only sites you own or are authorized to test.

Python 3.10+ recommended. The phone package is optional. No root access required.
