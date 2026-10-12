#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subrecon.py - Subdomain enumeration pipeline with WHOIS and a styled Excel report.

Steps (per domain):
  1. Subfinder      2. Assetfinder   3. Findomain
  4. Chaos (API)    5. crt.sh        6. GitHub Dorking (token)
  then: merge + dedupe + sort -> DNS resolve + WHOIS -> Excel

Use ONLY on domains you own or are explicitly authorized to test.

Install:
  pip install requests python-whois openpyxl
  + tools in PATH: subfinder, assetfinder, findomain (and optionally chaos)

Examples:
  python subrecon.py -d example.com --chaos-key KEY --github-token TOKEN
  python subrecon.py -l domains.txt --chaos-key KEY --github-token TOKEN -o report.xlsx
"""

import argparse
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date

import requests

try:
    import whois  # python-whois
except ImportError:
    whois = None

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

# ----------------------------------------------------------------------------
# Pretty console output
# ----------------------------------------------------------------------------
C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m",
     "c": "\033[96m", "m": "\033[95m", "bold": "\033[1m", "end": "\033[0m"}


def log(msg, color="c"):
    print(f"{C[color]}{msg}{C['end']}", flush=True)


def step(domain_idx, domain_total, step_idx, step_total, name, domain):
    log(f"\n[Domain {domain_idx}/{domain_total}] [Step {step_idx}/{step_total}] "
        f"{C['bold']}{name}{C['end']}{C['b']} -> {domain}", "b")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def sub_regex(domain):
    return re.compile(
        r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*" + re.escape(domain),
        re.IGNORECASE)


def clean_hosts(items, domain):
    """Normalize and keep only valid hosts that belong to `domain`."""
    out = set()
    domain = domain.lower()
    for raw in items:
        h = raw.strip().lower().lstrip("*.").rstrip(".")
        if not h or " " in h:
            continue
        if h == domain or h.endswith("." + domain):
            if re.fullmatch(r"[a-z0-9_.-]+", h):
                out.add(h)
    return out


def run_cmd(cmd, timeout=900):
    """Run an external command and return its stdout lines."""
    exe = cmd[0]
    if shutil.which(exe) is None:
        log(f"   [!] '{exe}' not found in PATH - skipped", "y")
        return []
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        if p.returncode != 0 and not lines:
            err = (p.stderr or "").strip().splitlines()
            log(f"   [!] {exe} exited with {p.returncode}: "
                f"{err[-1] if err else 'no output'}", "y")
        return lines
    except subprocess.TimeoutExpired:
        log(f"   [!] {exe} timed out after {timeout}s", "y")
    except Exception as e:  # noqa
        log(f"   [!] {exe} failed: {e}", "r")
    return []


# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------
def src_subfinder(domain, **_):
    return run_cmd(["subfinder", "-d", domain, "-silent", "-all"])


def src_assetfinder(domain, **_):
    return run_cmd(["assetfinder", "--subs-only", domain])


def src_findomain(domain, **_):
    return run_cmd(["findomain", "-t", domain, "-q"])


def src_chaos(domain, chaos_key=None, **_):
    if not chaos_key:
        log("   [!] No Chaos API key provided - skipped", "y")
        return []
    # Prefer the official chaos-client if installed
    if shutil.which("chaos"):
        return run_cmd(["chaos", "-d", domain, "-key", chaos_key, "-silent"])
    # Fallback: direct API call
    try:
        r = requests.get(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                         headers={"Authorization": chaos_key}, timeout=60)
        if r.status_code != 200:
            log(f"   [!] Chaos API returned HTTP {r.status_code}", "y")
            return []
        data = r.json()
        return [f"{s}.{domain}" if s else domain for s in data.get("subdomains", [])]
    except Exception as e:  # noqa
        log(f"   [!] Chaos API error: {e}", "r")
        return []


def src_crtsh(domain, **_):
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    for attempt in range(1, 4):
        try:
            r = requests.get(url, params=params, timeout=90,
                             headers={"User-Agent": "Mozilla/5.0 subrecon"})
            if r.status_code == 200:
                out = []
                for row in r.json():
                    out.extend(row.get("name_value", "").split("\n"))
                return out
            log(f"   [!] crt.sh HTTP {r.status_code} (attempt {attempt}/3)", "y")
        except Exception as e:  # noqa
            log(f"   [!] crt.sh error (attempt {attempt}/3): {e}", "y")
        time.sleep(5 * attempt)
    return []


GITHUB_DORKS = [
    '"{d}"',
    '"{d}" api',
    '"{d}" internal',
    '"{d}" staging',
    '"{d}" dev',
    '"{d}" password',
    '"{d}" token',
    '"{d}" secret',
]


def src_github(domain, github_token=None, **_):
    if not github_token:
        log("   [!] No GitHub token provided - skipped", "y")
        return []
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.text-match+json",
        "User-Agent": "subrecon",
    }
    rx = sub_regex(domain)
    found = set()
    for i, dork in enumerate(GITHUB_DORKS, 1):
        q = dork.format(d=domain)
        for page in (1, 2, 3):
            try:
                r = requests.get("https://api.github.com/search/code",
                                 headers=headers, timeout=60,
                                 params={"q": q, "per_page": 100, "page": page})
            except Exception as e:  # noqa
                log(f"   [!] GitHub error: {e}", "r")
                break
            if r.status_code in (403, 429):
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(5, min(reset - int(time.time()) + 2, 90))
                log(f"   [!] GitHub rate limit - waiting {wait}s", "y")
                time.sleep(wait)
                continue
            if r.status_code == 401:
                log("   [!] GitHub token is invalid (401)", "r")
                return list(found)
            if r.status_code != 200:
                log(f"   [!] GitHub HTTP {r.status_code}", "y")
                break
            items = r.json().get("items", [])
            for it in items:
                for tm in it.get("text_matches", []):
                    found.update(m.group(0) for m in rx.finditer(tm.get("fragment", "")))
            log(f"   dork {i}/{len(GITHUB_DORKS)} page {page}: {len(items)} results "
                f"(total unique so far: {len(found)})", "c")
            if len(items) < 100:
                break
            time.sleep(2.5)
        time.sleep(2.5)  # code-search limit is ~30 req/min
    return list(found)


SOURCES = [
    ("Subfinder", src_subfinder),
    ("Assetfinder", src_assetfinder),
    ("Findomain", src_findomain),
    ("Chaos", src_chaos),
    ("crt.sh", src_crtsh),
    ("GitHub Dorking", src_github),
]


def enumerate_domain(domain, d_idx, d_total, opts):
    """Returns {subdomain: set(sources)}"""
    results = {}
    total = len(SOURCES)
    for i, (name, fn) in enumerate(SOURCES, 1):
        step(d_idx, d_total, i, total, name, domain)
        t0 = time.time()
        try:
            raw = fn(domain, chaos_key=opts.chaos_key, github_token=opts.github_token)
        except Exception as e:  # noqa
            log(f"   [!] {name} crashed: {e}", "r")
            raw = []
        hosts = clean_hosts(raw, domain)
        for h in hosts:
            results.setdefault(h, set()).add(name)
        log(f"   [+] {name}: {len(hosts)} unique results ({time.time() - t0:.1f}s)", "g")

    log(f"\n[Merge] Deduplicating & sorting for {domain} ...", "m")
    results = {h: results[h] for h in sorted(results)}
    log(f"   [+] Total unique subdomains: {len(results)}", "g")
    return results


# ----------------------------------------------------------------------------
# DNS + WHOIS
# ----------------------------------------------------------------------------
def fmt_val(v):
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        vals = [fmt_val(x) for x in v if x not in (None, "")]
        seen, out = set(), []
        for x in vals:
            if x.lower() not in seen:
                seen.add(x.lower())
                out.append(x)
        return ", ".join(out)
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    return str(v).strip()


def first_date(v):
    if isinstance(v, (list, tuple)):
        v = [x for x in v if x]
        v = min(v) if v else None
    return fmt_val(v)


def whois_lookup(host):
    if whois is None:
        return None
    try:
        w = whois.whois(host)
    except Exception:
        return None
    if not w:
        return None
    if not (w.get("registrar") or w.get("creation_date") or w.get("name_servers")):
        return None
    return {
        "registrar": fmt_val(w.get("registrar")),
        "org": fmt_val(w.get("org") or w.get("registrant_org") or w.get("name")),
        "country": fmt_val(w.get("country")),
        "created": first_date(w.get("creation_date")),
        "expires": first_date(w.get("expiration_date")),
        "updated": first_date(w.get("updated_date")),
        "ns": fmt_val([n.lower() for n in (w.get("name_servers") or [])]
                      if isinstance(w.get("name_servers"), (list, tuple, set))
                      else w.get("name_servers")),
        "emails": fmt_val(w.get("emails")),
        "status": fmt_val(w.get("status")),
    }


def resolve_ips(host):
    try:
        return ", ".join(sorted(set(socket.gethostbyname_ex(host)[2])))
    except Exception:
        return ""


def enrich(host, root, root_whois):
    ips = resolve_ips(host)
    info = whois_lookup(host) if host != root else None
    src = "subdomain"
    if info is None and root_whois:
        info, src = root_whois, "root domain (fallback)"
    elif info is None:
        info, src = {}, "not available"
    if host == root and root_whois:
        src = "root domain"
    return host, ips, src, info


def run_whois(root, subs, threads):
    log(f"\n[WHOIS] Collecting DNS + WHOIS for {len(subs)} hosts of {root} ...", "m")
    if whois is None:
        log("   [!] python-whois is not installed (pip install python-whois) - "
            "WHOIS columns will be empty", "y")
    root_whois = whois_lookup(root)
    out = {}
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(enrich, h, root, root_whois) for h in subs]
        for f in as_completed(futs):
            host, ips, src, info = f.result()
            out[host] = (ips, src, info)
            done += 1
            if done % 10 == 0 or done == len(subs):
                pct = done * 100 // len(subs)
                print(f"\r   progress: {done}/{len(subs)} ({pct}%)", end="", flush=True)
    print()
    return out


# ----------------------------------------------------------------------------
# Excel
# ----------------------------------------------------------------------------
FONT = "Arial"
NAVY = "1F3864"
BLUE = "2F5597"
LIGHT = "D9E2F3"
BAND = "F2F6FC"
thin = Side(style="thin", color="BFBFBF")
BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)

HEADERS = ["#", "Root Domain", "Subdomain", "IP Address(es)", "Sources", "Source Count",
           "WHOIS Source", "Registrar", "Organization", "Country", "Created",
           "Expires", "Updated", "Name Servers", "Emails", "Status"]
WIDTHS = [6, 22, 40, 24, 30, 13, 22, 28, 28, 10, 13, 13, 13, 40, 32, 36]


def style_header(ws, row, ncols, fill=NAVY):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = Font(name=FONT, bold=True, color="FFFFFF", size=11)
        cell.fill = PatternFill("solid", fgColor=fill)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER


def build_excel(all_data, path, tool_names):
    wb = Workbook()

    # ---- Subdomains sheet ----
    ws = wb.active
    ws.title = "Subdomains"
    ws.append(HEADERS)
    style_header(ws, 1, len(HEADERS))
    ws.row_dimensions[1].height = 28

    n = 0
    for root, (subs, meta) in all_data.items():
        for host, srcs in subs.items():
            ips, wsrc, info = meta.get(host, ("", "", {}))
            n += 1
            ws.append([
                n, root, host, ips, ", ".join(sorted(srcs)), len(srcs), wsrc,
                info.get("registrar", ""), info.get("org", ""), info.get("country", ""),
                info.get("created", ""), info.get("expires", ""), info.get("updated", ""),
                info.get("ns", ""), info.get("emails", ""), info.get("status", ""),
            ])
    last = ws.max_row
    for r in range(2, last + 1):
        fill = PatternFill("solid", fgColor=BAND) if r % 2 == 0 else None
        for c in range(1, len(HEADERS) + 1):
            cell = ws.cell(row=r, column=c)
            cell.font = Font(name=FONT, size=10)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="center",
                                       horizontal="center" if c in (1, 6, 10, 11, 12, 13) else "left",
                                       wrap_text=c in (4, 5, 14, 15, 16))
            if fill:
                cell.fill = fill
        # highlight hosts that resolve
        ws.cell(row=r, column=4).font = Font(
            name=FONT, size=10,
            color="1E7B34" if ws.cell(row=r, column=4).value else "999999")
    for i, w in enumerate(WIDTHS, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "D2"
    if last >= 2:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(HEADERS))}{last}"
    ws.sheet_view.zoomScale = 90

    # ---- Summary sheet (formulas reference the Subdomains sheet) ----
    sm = wb.create_sheet("Summary", 0)
    sm.sheet_view.showGridLines = False
    sm["A1"] = "Subdomain Enumeration Report"
    sm["A1"].font = Font(name=FONT, size=18, bold=True, color=NAVY)
    sm["A2"] = f"Generated: {datetime.now():%Y-%m-%d %H:%M}"
    sm["A2"].font = Font(name=FONT, size=10, italic=True, color="666666")

    sm.append([])
    sm.append(["Root Domain", "Total Subdomains", "Resolving (has IP)"])
    hdr = sm.max_row
    style_header(sm, hdr, 3, BLUE)
    first_dom = hdr + 1
    for root in all_data:
        r = sm.max_row + 1
        sm.cell(row=r, column=1, value=root)
        sm.cell(row=r, column=2, value=f"=COUNTIF(Subdomains!$B:$B,A{r})")
        sm.cell(row=r, column=3, value=f'=COUNTIFS(Subdomains!$B:$B,A{r},Subdomains!$D:$D,"?*")')
    last_dom = sm.max_row
    r = last_dom + 1
    sm.cell(row=r, column=1, value="TOTAL")
    sm.cell(row=r, column=2, value=f"=SUM(B{first_dom}:B{last_dom})")
    sm.cell(row=r, column=3, value=f"=SUM(C{first_dom}:C{last_dom})")
    for rr in range(first_dom, r + 1):
        for c in range(1, 4):
            cell = sm.cell(row=rr, column=c)
            cell.font = Font(name=FONT, size=11, bold=(rr == r))
            cell.border = BORDER
            cell.alignment = Alignment(horizontal="left" if c == 1 else "center")
            if rr == r:
                cell.fill = PatternFill("solid", fgColor=LIGHT)

    sm.cell(row=r + 2, column=1, value="Results per source")
    sm.cell(row=r + 2, column=1).font = Font(name=FONT, size=12, bold=True, color=NAVY)
    h2 = r + 3
    sm.cell(row=h2, column=1, value="Source")
    sm.cell(row=h2, column=2, value="Subdomains found")
    style_header(sm, h2, 2, BLUE)
    for i, t in enumerate(tool_names, 1):
        rr = h2 + i
        sm.cell(row=rr, column=1, value=t)
        sm.cell(row=rr, column=2, value=f'=COUNTIF(Subdomains!$E:$E,"*"&A{rr}&"*")')
        for c in (1, 2):
            cell = sm.cell(row=rr, column=c)
            cell.font = Font(name=FONT, size=11)
            cell.border = BORDER
            cell.alignment = Alignment(horizontal="left" if c == 1 else "center")
            if i % 2 == 0:
                cell.fill = PatternFill("solid", fgColor=BAND)
    sm.column_dimensions["A"].width = 30
    sm.column_dimensions["B"].width = 22
    sm.column_dimensions["C"].width = 22

    wb.save(path)
    log(f"\n[Excel] Saved -> {path}", "g")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def load_domains(args):
    doms = []
    if args.domain:
        doms.extend(args.domain)
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            doms.extend(line.strip() for line in f)
    clean, seen = [], set()
    for d in doms:
        d = re.sub(r"^https?://", "", d.strip().lower()).split("/")[0].lstrip("*.")
        if d and d not in seen and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d):
            seen.add(d)
            clean.append(d)
    return clean


def main():
    ap = argparse.ArgumentParser(description="Subdomain enumeration + WHOIS + Excel report")
    ap.add_argument("-d", "--domain", nargs="+", help="one or more domains")
    ap.add_argument("-l", "--list", help="file containing domains (one per line)")
    ap.add_argument("--chaos-key", help="Chaos (ProjectDiscovery) API key")
    ap.add_argument("--github-token", help="GitHub personal access token")
    ap.add_argument("-o", "--output", default="subdomains_report.xlsx", help="output xlsx path")
    ap.add_argument("-t", "--threads", type=int, default=10, help="threads for DNS/WHOIS")
    opts = ap.parse_args()

    domains = load_domains(opts)
    if not domains:
        ap.error("no valid domain given (use -d and/or -l)")

    log(f"{C['bold']}Loaded {len(domains)} domain(s){C['end']}", "g")
    all_data = {}
    for i, dom in enumerate(domains, 1):
        subs = enumerate_domain(dom, i, len(domains), opts)
        meta = run_whois(dom, list(subs), opts.threads) if subs else {}
        all_data[dom] = (subs, meta)

    build_excel(all_data, opts.output, [n for n, _ in SOURCES])
    log("Done.", "g")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted by user.", "r")
        sys.exit(1)
