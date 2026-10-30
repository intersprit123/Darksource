#!/usr/bin/env python3
"""DarkSource UE: terminal website resource mapper plus privacy-safe metadata checks."""
import argparse, hashlib, json, re, sys, time
from collections import deque, defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, unquote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

VERSION = "0.1.0"
UA = "DarkSource-UE/0.1.0 (respectful resource mapper)"
MAX_BYTES = 20 * 1024 * 1024
AUDIT_PATHS = (".env", ".git/HEAD", "backup.zip", "config.json", "swagger.json",
               "openapi.json", "api-docs", "debug", ".well-known/security.txt")

def clean_url(url):
    url, _ = urldefrag(url.strip())
    p = urlparse(url)
    return p.geturl() if p.scheme in ("http", "https") and p.hostname else None

def origin(url):
    p = urlparse(url)
    return p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)

def fetch(url, limit=MAX_BYTES):
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urlopen(req, timeout=15) as r:
        body = r.read(limit + 1)
        if len(body) > limit: raise ValueError("response exceeds configured size limit")
        return r.geturl(), r.status, dict(r.headers.items()), body

def local_path(url, ctype=""):
    p = urlparse(url)
    parts = [re.sub(r"[^A-Za-z0-9._@+-]", "_", unquote(x))[:120]
             for x in (p.path or "/").split("/") if x not in ("", ".", "..")]
    if not parts: parts = ["index.html"]
    elif p.path.endswith("/") or "." not in parts[-1]:
        parts.append("index.html" if "html" in ctype else "resource")
    rel = Path(*parts)
    if p.query: rel = rel.with_name(rel.stem + "__" + hashlib.sha256(p.query.encode()).hexdigest()[:10] + rel.suffix)
    return rel

class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.values = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ("href", "src", "action", "poster", "data-src"):
            if a.get(key): self.values.append((a[key], tag + ":" + key))
        if a.get("srcset"):
            for x in a["srcset"].split(","):
                if x.strip(): self.values.append((x.strip().split()[0], "srcset"))

def references(url, body, ctype):
    text = body.decode("utf-8", "replace"); out = []
    if "html" in ctype:
        parser = Links()
        try: parser.feed(text)
        except Exception: pass
        out.extend((urljoin(url, v), k) for v, k in parser.values)
    if "css" in ctype or urlparse(url).path.endswith(".css"):
        for pat in (r"url\(\s*['\"]?([^)'\"\s]+)", r"@import\s+['\"]([^'\"]+)"):
            out.extend((urljoin(url, x), "css-reference") for x in re.findall(pat, text, re.I))
    if "javascript" in ctype or urlparse(url).path.endswith((".js", ".mjs")):
        pats = (r"""(?:import\s*(?:[^'"]*?\sfrom\s*)?|import\()\s*['"]([^'"]+)['"]""",
                r"""(?:fetch|axios\.get|axios\.post)\s*\(\s*['"]([^'"]+)['"]""",
                r"""sourceMappingURL\s*=\s*([^\s*]+)""")
        for pat in pats: out.extend((urljoin(url, x), "js-reference") for x in re.findall(pat, text))
    return out

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def audit(start, out, delay):
    print("\n-A requested. Only continue if you own this site or have permission.")
    try: ok = input("Confirm authorization? [y/N] ").strip().lower() == "y"
    except EOFError: ok = False
    if not ok: print("Security checks skipped."); return
    findings = []
    try:
        _, _, headers, _ = fetch(start)
        low = {k.lower(): v for k, v in headers.items()}
        for name in ("content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy"):
            findings.append({"check": name, "result": "present" if name in low else "not observed",
                             "note": "Missing header alone is not proof of a vulnerability."})
    except Exception as e: findings.append({"check": "headers", "error": str(e)})
    for path in AUDIT_PATHS:
        try:
            _, status, headers, _ = fetch(urljoin(start.rstrip("/") + "/", path), 512 * 1024)
            if status == 200:
                findings.append({"check": "known-path review", "path": path, "status": status,
                                 "content_type": headers.get("Content-Type", ""),
                                 "note": "Manually review; HTTP 200 alone is not a vulnerability."})
        except HTTPError: pass
        except Exception: pass
        time.sleep(max(0.25, delay))
    save_json(out / "security-audit.json", {"target": start, "checks": findings})
    print("Audit saved:", out / "security-audit.json")

def scan(args):
    start = clean_url(args.url)
    if not start: print("Use a valid http(s) URL.", file=sys.stderr); return 2
    base = origin(start); out = Path(args.output).expanduser().resolve(); out.mkdir(parents=True, exist_ok=True)
    queue, visited, records, bodies = deque([start]), set(), {}, {}
    print("DarkSource UE", VERSION, "| target:", start, "| output:", out)
    while queue and len(visited) < args.max_pages:
        page = queue.popleft()
        if page in visited or origin(page) != base: continue
        visited.add(page)
        try:
            final, status, headers, body = fetch(page, args.max_bytes)
            ctype = headers.get("Content-Type", "").lower()
            depth = max(0, len([x for x in urlparse(page).path.split("/") if x]) - 1)
            records.setdefault(page, {"url": page, "references": [], "depth": depth})
            records[page].update({"status": status, "content_type": ctype, "size": len(body), "error": None})
            bodies[page] = (body, ctype); print(f"[{status}] {page} ({len(body)} bytes)")
            for ref, kind in references(final, body, ctype):
                target = clean_url(ref)
                if not target or (not args.include_external and origin(target) != base): continue
                rec = records.setdefault(target, {"url": target, "references": [], "depth":
                    max(0, len([x for x in urlparse(target).path.split("/") if x]) - 1)})
                rec["referenced_from"] = page
                records[page]["references"].append({"url": target, "kind": kind})
                path = urlparse(target).path.lower()
                if origin(target) == base and (kind.startswith("html") or path.endswith(("/", ".html", ".htm"))):
                    if target not in visited and target not in queue: queue.append(target)
            time.sleep(args.delay)
        except Exception as e:
            records[page] = {"url": page, "error": str(e), "depth": 0, "references": []}
            print("[error]", page, e)
    destinations, used = {}, set()
    for url, rec in records.items():
        if rec.get("error"): continue
        dest = out / local_path(url, rec.get("content_type", ""))
        if str(dest) in used: dest = dest.with_name(dest.stem + "_" + hashlib.sha256(url.encode()).hexdigest()[:8] + dest.suffix)
        used.add(str(dest)); destinations[url] = dest
    # Create all directories before downloading any files.
    for dest in destinations.values(): dest.parent.mkdir(parents=True, exist_ok=True)
    layers = defaultdict(list)
    for url, dest in destinations.items(): layers[records[url].get("depth", 0)].append((url, dest))
    for depth in sorted(layers):
        print(f"\n[Layer {depth}] {len(layers[depth])} resources")
        for url, dest in layers[depth]:
            try:
                if url in bodies: body, ctype = bodies[url]
                else:
                    _, status, headers, body = fetch(url, args.max_bytes)
                    ctype = headers.get("Content-Type", "")
                    records[url].update({"status": status, "content_type": ctype, "size": len(body)})
                dest.write_bytes(body); records[url].update({"saved": True, "local_path": str(dest.relative_to(out))})
                print("  saved", dest.relative_to(out))
            except Exception as e:
                records[url]["download_error"] = str(e); print("  failed", url, e)
            time.sleep(args.delay)
    api_hints = sorted({r["url"] for rec in records.values() for r in rec.get("references", [])
                        if any(x in urlparse(r["url"]).path.lower() for x in ("/api/", "/graphql", "/v1/", "/v2/"))})
    save_json(out / "darksource-manifest.json", {"tool": "DarkSource UE", "version": VERSION,
        "target": start, "pages_visited": len(visited), "resource_count": len(records),
        "api_hints": api_hints, "resources": list(records.values())})
    report = ["# DarkSource UE report", "", f"- Target: {start}", f"- Pages visited: {len(visited)}",
        f"- Resources: {len(records)}", "", "## API-like references",
        *([f"- {x}" for x in api_hints] or ["- None detected from static references."]), "",
        "## Limitations", "- No JavaScript execution or browser-only network capture.",
        "- URL paths are approximations, not the server's actual filesystem.",
        "- Public availability alone does not prove a security vulnerability."]
    (out / "REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\nManifest:", out / "darksource-manifest.json"); print("Report:", out / "REPORT.md")
    if args.audit: audit(start, out, args.delay)
    return 0

def phone_lookup(number, region):
    try: import phonenumbers
    except ImportError:
        print("Install optional package: python -m pip install phonenumbers"); return 2
    try: n = phonenumbers.parse(number, region.upper() if region else None)
    except Exception as e: print("Could not parse number:", e); return 2
    from phonenumbers import geocoder, carrier, timezone
    print("Phone metadata from offline numbering-plan data")
    print("International:", phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    print("Possible:", phonenumbers.is_possible_number(n), "| valid by plan:", phonenumbers.is_valid_number(n))
    print("Region:", geocoder.description_for_number(n, "en") or n.country_code)
    print("Original-carrier metadata:", carrier.name_for_number(n, "en") or "not available")
    print("Possible time zones:", ", ".join(timezone.time_zones_for_number(n)) or "unknown")
    print("Cannot reveal GPS/live location, subscriber identity, current carrier reliably, or linked accounts.")
    return 0

def email_check(address):
    if address.count("@") != 1 or any(c.isspace() for c in address):
        print("Enter a valid email address."); return 2
    local, domain = address.rsplit("@", 1)
    if not local or "." not in domain: print("Email format looks invalid."); return 2
    import socket
    print(f"Email: {local[:1]}***@{domain.lower()}")
    try:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(domain, None)})
        print("Domain DNS resolves:", ", ".join(ips[:4]))
    except OSError: print("Domain DNS resolution unavailable or failed.")
    print("Does not verify mailbox ownership or enumerate accounts connected to this address.")
    return 0

def main():
    p = argparse.ArgumentParser(description="DarkSource UE — website mapping and privacy-safe metadata")
    p.add_argument("url", nargs="?", help="website URL")
    p.add_argument("-A", "--audit", action="store_true", help="optional authorized security checks")
    p.add_argument("-o", "--output", default="darksource-output")
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    p.add_argument("--delay", type=float, default=0.5)
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--phone", metavar="NUMBER")
    p.add_argument("--region", metavar="ISO", help="region for national phone format, e.g. IN")
    p.add_argument("--email", metavar="ADDRESS")
    a = p.parse_args()
    if a.phone: return phone_lookup(a.phone, a.region)
    if a.email: return email_check(a.email)
    if not a.url: p.print_help(); return 2
    if a.max_pages < 1 or a.max_bytes < 1024 or a.delay < 0: p.error("invalid limit or delay")
    return scan(a)

if __name__ == "__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: print("\nStopped."); raise SystemExit(130)
