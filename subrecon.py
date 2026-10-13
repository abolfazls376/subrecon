#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subrecon.py - Subdomain enumeration pipeline with WHOIS and a styled Excel report.

Steps (per domain):
  1. Subfinder      2. Assetfinder   3. Findomain
  4. Chaos (API)    5. crt.sh        6. GitHub Dorking (token)
  7. Ffuf (brute-force using a wordlist built from steps 1-6)
  then: merge + dedupe + sort -> DNS resolve + WHOIS -> httpx (http_live) -> custom wordlist -> Excel + JSON

Use ONLY on domains you own or are explicitly authorized to test.

Install:
  pip install requests python-whois openpyxl
  + tools in PATH: subfinder, assetfinder, findomain, ffuf, httpx (ProjectDiscovery), optionally chaos

Examples:
  python subrecon.py -d example.com --chaos-key KEY --github-token TOKEN
  python subrecon.py -l domains.txt --chaos-key KEY --github-token TOKEN -o report.xlsx
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date, timezone

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
# Ffuf (wordlist brute-force, step 7)
# ----------------------------------------------------------------------------
def words_from_subs(subs, root):
    """The label directly left of the root domain, for every known subdomain
    (same rule as build_wordlist: a.b.example.com -> 'b'). Used to build the
    wordlist that feeds ffuf."""
    suffix = "." + root
    words = set()
    for host in subs:
        if host.endswith(suffix):
            w = host[: -len(suffix)].split(".")[-1]
            if w:
                words.add(w)
    return sorted(words)


def check_ffuf_binary(path):
    exe = shutil.which(path)
    if not exe:
        log(f"   [!] '{path}' not found in PATH - Ffuf step skipped", "y")
        return None
    return exe


def run_ffuf(root, words, exe, threads, mc, timeout=1800):
    """
    Equivalent of:
      ffuf -u https://FUZZ.<root> -w wordlist.txt -t <threads> -mc <mc> -o out.json
    Returns the set of hosts ffuf matched (status code in `mc`).
    """
    wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    out_path = wl.name + ".out.json"
    try:
        wl.write("\n".join(words) + "\n")
        wl.close()
        cmd = [exe, "-u", f"https://FUZZ.{root}", "-w", wl.name,
               "-t", str(threads), "-mc", mc, "-o", out_path, "-of", "json", "-s"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            log(f"   [!] ffuf timed out after {timeout}s", "y")
            return set()
        except Exception as e:  # noqa
            log(f"   [!] ffuf failed: {e}", "r")
            return set()
        if not os.path.exists(out_path):
            err = (p.stderr or "").strip().splitlines()
            log(f"   [!] ffuf produced no output (exit {p.returncode}): "
                f"{err[-1] if err else 'unknown error'}", "y")
            return set()
        try:
            with open(out_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:  # noqa
            log(f"   [!] could not parse ffuf JSON output: {e}", "y")
            return set()
        raw = []
        for row in data.get("results", []):
            host = (row.get("host") or "").strip().lower()
            if not host:
                host = re.sub(r"^https?://", "", row.get("url", "")).split("/")[0].split(":")[0]
            if host:
                raw.append(host)
        return clean_hosts(raw, root)
    finally:
        for p_ in (wl.name, out_path):
            try:
                os.unlink(p_)
            except OSError:
                pass


def run_ffuf_step(domain, subs, d_idx, d_total, opts):
    """Step 7: brute-force with ffuf using a wordlist built from steps 1-6,
    then merge any new/matching hosts back into `subs`, tagged 'Ffuf'."""
    step(d_idx, d_total, 7, 7, "Ffuf (wordlist brute-force)", domain)
    if opts.no_ffuf:
        log("   [!] --no-ffuf set - skipped", "y")
        return subs
    exe = check_ffuf_binary(opts.ffuf_path)
    if not exe:
        return subs
    words = words_from_subs(subs, domain)
    if not words:
        log("   [!] no words available yet to build a wordlist - skipped", "y")
        return subs
    log(f"   [+] Wordlist built from current results: {len(words)} words", "c")
    t0 = time.time()
    found = run_ffuf(domain, words, exe, opts.ffuf_threads, opts.ffuf_mc, opts.ffuf_timeout)
    new = found - set(subs)
    for h in found:
        subs.setdefault(h, set()).add("Ffuf")
    subs = {h: subs[h] for h in sorted(subs)}
    log(f"   [+] Ffuf: {len(found)} hosts matched (mc={opts.ffuf_mc}), "
        f"{len(new)} new ({time.time() - t0:.1f}s)", "g")
    return subs


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
# HTTPX (live check)
# ----------------------------------------------------------------------------
HTTPX_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0"


def check_httpx_binary(path):
    """Return the executable path if it is ProjectDiscovery's httpx, else None."""
    exe = shutil.which(path)
    if not exe:
        log(f"   [!] '{path}' not found in PATH - HTTP check skipped", "y")
        return None
    try:
        p = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=30)
        txt = ((p.stdout or "") + (p.stderr or "")).lower()
    except Exception as e:  # noqa
        log(f"   [!] could not run httpx: {e}", "y")
        return None
    if "projectdiscovery" in txt or "current version" in txt:
        return exe
    log("   [!] The 'httpx' in PATH is not ProjectDiscovery's httpx (maybe the Python "
        "httpx CLI). Use --httpx-path /path/to/pd-httpx - HTTP check skipped", "y")
    return None


def run_httpx(root, hosts, exe, threads):
    """
    Equivalent of:
      cat subdomains.txt | httpx -silent -follow-host-redirects -title -status-code -cdn
         -tech-detect -H "user-agent:..." -H "referer:https://<root>" -threads N
    (+ -json for reliable parsing). Returns {host: info}.
    """
    results = {}
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(hosts) + "\n")
        tmp.close()
        cmd = [exe, "-l", tmp.name, "-silent", "-json", "-follow-host-redirects",
               "-title", "-status-code", "-cdn", "-tech-detect",
               "-H", f"user-agent:{HTTPX_UA}",
               "-H", f"referer:https://{root}",
               "-threads", str(threads)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True)
        t0 = time.time()
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                host = (row.get("input") or "").lower().strip()
                if not host:
                    host = re.sub(r"^https?://", "", row.get("url", "")).split("/")[0].split(":")[0].lower()
                if not host:
                    continue
                cdn = ""
                if row.get("cdn"):
                    cdn = row.get("cdn_name") or "yes"
                tech = row.get("tech") or row.get("technologies") or []
                info = {
                    "url": row.get("url", ""),
                    "status": row.get("status_code", row.get("status-code", "")),
                    "title": (row.get("title") or "").strip(),
                    "cdn": cdn,
                    "tech": ", ".join(tech) if isinstance(tech, list) else str(tech),
                }
                if host not in results or (not results[host]["status"] and info["status"]):
                    results[host] = info
                print(f"\r   live hosts found: {len(results)}/{len(hosts)} "
                      f"({time.time() - t0:.0f}s)", end="", flush=True)
            proc.wait()
        except KeyboardInterrupt:
            proc.kill()
            raise
        finally:
            if proc.poll() is None:
                proc.kill()
        print()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return results


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

HEADERS = ["#", "Root Domain", "Subdomain", "IP Address(es)", "http_live", "Status Code",
           "Title", "CDN", "Technologies", "HTTP URL", "Sources", "Source Count",
           "WHOIS Source", "Registrar", "Organization", "Country", "Created",
           "Expires", "Updated", "Name Servers", "Emails", "Status"]
WIDTHS = [6, 22, 40, 24, 12, 13, 34, 16, 36, 42, 30, 13, 22, 28, 28, 10, 13, 13, 13, 40, 32, 36]
COL = {h: i + 1 for i, h in enumerate(HEADERS)}
CENTER = {"#", "http_live", "Status Code", "Source Count", "Country", "Created", "Expires", "Updated"}
WRAP = {"IP Address(es)", "Title", "Technologies", "Sources", "Name Servers", "Emails", "Status"}


def L(name):
    return get_column_letter(COL[name])


def style_header(ws, row, ncols, fill=NAVY):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = Font(name=FONT, bold=True, color="FFFFFF", size=11)
        cell.fill = PatternFill("solid", fgColor=fill)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER


def status_color(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "000000"
    if code < 300:
        return "1E7B34"
    if code < 400:
        return "2F5597"
    if code < 500:
        return "C55A11"
    return "C00000"


def build_wordlist(all_data):
    """
    Python equivalent of:
      cat subs.txt | rev | cut -d . -f 3 | rev | sort -u
    i.e. the label directly to the left of the root domain
    (a.b.example.com -> b, x.example.com -> x). Returns sorted
    [(word, usage_count, root_domains)].
    """
    words = {}
    for root, (subs, _meta, _http) in all_data.items():
        suffix = "." + root
        for host in subs:
            if not host.endswith(suffix):
                continue
            word = host[:-len(suffix)].split(".")[-1]
            if not word:
                continue
            e = words.setdefault(word, {"count": 0, "roots": set()})
            e["count"] += 1
            e["roots"].add(root)
    return [(w, words[w]["count"], ", ".join(sorted(words[w]["roots"]))) for w in sorted(words)]


def build_excel(all_data, path, tool_names):
    wb = Workbook()

    # ---- Subdomains sheet ----
    ws = wb.active
    ws.title = "Subdomains"
    ws.append(HEADERS)
    style_header(ws, 1, len(HEADERS))
    ws.row_dimensions[1].height = 28

    n = 0
    for root, (subs, meta, http) in all_data.items():
        for host, srcs in subs.items():
            ips, wsrc, info = meta.get(host, ("", "", {}))
            if http is None:                      # httpx not run
                live, h = "N/A", {}
            else:
                h = http.get(host)
                live = h is not None
                h = h or {}
            n += 1
            ws.append([
                n, root, host, ips, live, h.get("status", ""), h.get("title", ""),
                h.get("cdn", ""), h.get("tech", ""), h.get("url", ""),
                ", ".join(sorted(srcs)), len(srcs), wsrc,
                info.get("registrar", ""), info.get("org", ""), info.get("country", ""),
                info.get("created", ""), info.get("expires", ""), info.get("updated", ""),
                info.get("ns", ""), info.get("emails", ""), info.get("status", ""),
            ])
    last = ws.max_row
    green = PatternFill("solid", fgColor="C6EFCE")
    red = PatternFill("solid", fgColor="FFC7CE")
    for r in range(2, last + 1):
        band = PatternFill("solid", fgColor=BAND) if r % 2 == 0 else None
        for c, name in enumerate(HEADERS, 1):
            cell = ws.cell(row=r, column=c)
            cell.font = Font(name=FONT, size=10)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="center",
                                       horizontal="center" if name in CENTER else "left",
                                       wrap_text=name in WRAP)
            if band:
                cell.fill = band
        ip = ws.cell(row=r, column=COL["IP Address(es)"])
        ip.font = Font(name=FONT, size=10, color="1E7B34" if ip.value else "999999")
        live = ws.cell(row=r, column=COL["http_live"])
        if live.value is True:
            live.fill, live.font = green, Font(name=FONT, size=10, bold=True, color="006100")
        elif live.value is False:
            live.fill, live.font = red, Font(name=FONT, size=10, bold=True, color="9C0006")
        sc = ws.cell(row=r, column=COL["Status Code"])
        if sc.value not in (None, ""):
            sc.font = Font(name=FONT, size=10, bold=True, color=status_color(sc.value))
    for i, w in enumerate(WIDTHS, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "D2"
    if last >= 2:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(HEADERS))}{last}"
    ws.sheet_view.zoomScale = 90

    # ---- Wordlist sheet (custom wordlist built from all subdomains) ----
    wl = wb.create_sheet("Wordlist")
    wl_headers = ["#", "Word", "Used In (subdomains)", "Root Domains"]
    wl.append(wl_headers)
    style_header(wl, 1, len(wl_headers))
    wl.row_dimensions[1].height = 28
    for i, (word, cnt, roots) in enumerate(build_wordlist(all_data), 1):
        wl.append([i, word, cnt, roots])
    for r in range(2, wl.max_row + 1):
        for c in range(1, 5):
            cell = wl.cell(row=r, column=c)
            cell.font = Font(name=FONT, size=10)
            cell.border = BORDER
            cell.alignment = Alignment(vertical="center",
                                       horizontal="center" if c in (1, 3) else "left")
            if r % 2 == 0:
                cell.fill = PatternFill("solid", fgColor=BAND)
    for col, w in zip("ABCD", (7, 34, 22, 45)):
        wl.column_dimensions[col].width = w
    wl.freeze_panes = "A2"
    if wl.max_row >= 2:
        wl.auto_filter.ref = f"A1:D{wl.max_row}"

    # ---- Summary sheet (formulas reference the Subdomains sheet) ----
    sm = wb.create_sheet("Summary", 0)
    sm.sheet_view.showGridLines = False
    sm["A1"] = "Subdomain Enumeration Report"
    sm["A1"].font = Font(name=FONT, size=18, bold=True, color=NAVY)
    sm["A2"] = f"Generated: {datetime.now():%Y-%m-%d %H:%M}"
    sm["A2"].font = Font(name=FONT, size=10, italic=True, color="666666")

    root_c, ip_c, live_c, src_c = L("Root Domain"), L("IP Address(es)"), L("http_live"), L("Sources")
    sm.append([])
    sm.append(["Root Domain", "Total Subdomains", "Resolving (has IP)", "http_live = TRUE"])
    hdr = sm.max_row
    style_header(sm, hdr, 4, BLUE)
    first_dom = hdr + 1
    for root in all_data:
        r = sm.max_row + 1
        sm.cell(row=r, column=1, value=root)
        sm.cell(row=r, column=2, value=f"=COUNTIF(Subdomains!${root_c}:${root_c},A{r})")
        sm.cell(row=r, column=3,
                value=f'=COUNTIFS(Subdomains!${root_c}:${root_c},A{r},Subdomains!${ip_c}:${ip_c},"?*")')
        sm.cell(row=r, column=4,
                value=f"=COUNTIFS(Subdomains!${root_c}:${root_c},A{r},Subdomains!${live_c}:${live_c},TRUE)")
    last_dom = sm.max_row
    r = last_dom + 1
    sm.cell(row=r, column=1, value="TOTAL")
    for c, col in ((2, "B"), (3, "C"), (4, "D")):
        sm.cell(row=r, column=c, value=f"=SUM({col}{first_dom}:{col}{last_dom})")
    for rr in range(first_dom, r + 1):
        for c in range(1, 5):
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
        sm.cell(row=rr, column=2,
                value=f'=COUNTIF(Subdomains!${src_c}:${src_c},"*"&A{rr}&"*")')
        for c in (1, 2):
            cell = sm.cell(row=rr, column=c)
            cell.font = Font(name=FONT, size=11)
            cell.border = BORDER
            cell.alignment = Alignment(horizontal="left" if c == 1 else "center")
            if i % 2 == 0:
                cell.fill = PatternFill("solid", fgColor=BAND)
    sm.column_dimensions["A"].width = 30
    for col in "BCD":
        sm.column_dimensions[col].width = 22

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


# ----------------------------------------------------------------------------
# JSON export
# ----------------------------------------------------------------------------
def _none(v):
    return None if v in ("", None) else v


def _split(v):
    return [x.strip() for x in v.split(",") if x.strip()] if v else []


def build_json(all_data, path, tool_names):
    """Write a clean, sorted, machine-readable report (schema_version 1.0)."""
    per_source = {t: 0 for t in tool_names}
    domains_out = []
    tot_subs = tot_res = 0
    tot_live = 0
    http_ran = False

    for root in sorted(all_data):
        subs, meta, http = all_data[root]
        items, res, live = [], 0, 0
        for host in sorted(subs):
            srcs = sorted(subs[host])
            for t in srcs:
                if t in per_source:
                    per_source[t] += 1
            ips, wsrc, info = meta.get(host, ("", "", {}))
            ip_list = _split(ips)
            res += bool(ip_list)

            h = {}
            is_live = None
            if http is not None:
                http_ran = True
                h = http.get(host) or {}
                is_live = host in http
                live += is_live
            code = h.get("status", "")
            try:
                code = int(code)
            except (TypeError, ValueError):
                code = None

            items.append({
                "subdomain": host,
                "ips": ip_list,
                "resolves": bool(ip_list),
                "http_live": is_live,
                "status_code": code,
                "title": _none(h.get("title")),
                "cdn": _none(h.get("cdn")),
                "technologies": _split(h.get("tech")),
                "http_url": _none(h.get("url")),
                "sources": srcs,
                "source_count": len(srcs),
                "whois": {
                    "source": _none(wsrc),
                    "registrar": _none(info.get("registrar")),
                    "organization": _none(info.get("org")),
                    "country": _none(info.get("country")),
                    "created": _none(info.get("created")),
                    "expires": _none(info.get("expires")),
                    "updated": _none(info.get("updated")),
                    "name_servers": _split(info.get("ns")),
                    "emails": _split(info.get("emails")),
                    "status": _split(info.get("status")),
                },
            })
        tot_subs += len(items)
        tot_res += res
        tot_live += live
        domains_out.append({
            "domain": root,
            "stats": {"total_subdomains": len(items), "resolving": res,
                      "http_live": live if http is not None else None},
            "subdomains": items,
        })

    report = {
        "schema_version": "1.0",
        "tool": "subrecon",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "total_domains": len(domains_out),
            "total_subdomains": tot_subs,
            "resolving": tot_res,
            "http_live": tot_live if http_ran else None,
            "per_source": per_source,
        },
        "domains": domains_out,
        "wordlist": [{"word": w, "count": c, "root_domains": _split(r)}
                     for w, c, r in build_wordlist(all_data)],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    log(f"[JSON] Saved -> {path}", "g")


def main():
    ap = argparse.ArgumentParser(description="Subdomain enumeration + WHOIS + httpx + Excel report")
    ap.add_argument("-d", "--domain", nargs="+", help="one or more domains")
    ap.add_argument("-l", "--list", help="file containing domains (one per line)")
    ap.add_argument("--chaos-key", help="Chaos (ProjectDiscovery) API key")
    ap.add_argument("--github-token", help="GitHub personal access token")
    ap.add_argument("-o", "--output", default="subdomains_report.xlsx", help="output xlsx path")
    ap.add_argument("-t", "--threads", type=int, default=10, help="threads for DNS/WHOIS")
    ap.add_argument("--httpx-threads", type=int, default=1, help="httpx -threads value (default 1)")
    ap.add_argument("--httpx-path", default="httpx", help="path/name of ProjectDiscovery httpx")
    ap.add_argument("--no-httpx", action="store_true", help="skip the httpx live check")
    ap.add_argument("--ffuf-path", default="ffuf", help="path/name of the ffuf binary")
    ap.add_argument("--ffuf-threads", type=int, default=50, help="ffuf -t value (default 50)")
    ap.add_argument("--ffuf-mc", default="200,403", help="ffuf -mc value (default 200,403)")
    ap.add_argument("--ffuf-timeout", type=int, default=1800, help="ffuf timeout in seconds (default 1800)")
    ap.add_argument("--no-ffuf", action="store_true", help="skip the ffuf brute-force step")
    opts = ap.parse_args()

    domains = load_domains(opts)
    if not domains:
        ap.error("no valid domain given (use -d and/or -l)")

    httpx_exe = None
    if not opts.no_httpx:
        httpx_exe = check_httpx_binary(opts.httpx_path)

    tool_names = [n for n, _ in SOURCES] + ["Ffuf"]
    log(f"{C['bold']}Loaded {len(domains)} domain(s){C['end']}", "g")
    all_data = {}
    for i, dom in enumerate(domains, 1):
        subs = enumerate_domain(dom, i, len(domains), opts)
        subs = run_ffuf_step(dom, subs, i, len(domains), opts)
        meta = run_whois(dom, list(subs), opts.threads) if subs else {}

        http = None
        if httpx_exe and subs:
            log(f"\n[HTTPX] Probing {len(subs)} hosts of {dom} "
                f"(threads={opts.httpx_threads}) ...", "m")
            http = run_httpx(dom, list(subs), httpx_exe, opts.httpx_threads)
            log(f"   [+] Live: {len(http)} | Down: {len(subs) - len(http)}", "g")
        all_data[dom] = (subs, meta, http)

    build_excel(all_data, opts.output, tool_names)

    words = build_wordlist(all_data)
    wl_path = os.path.splitext(opts.output)[0] + "_wordlist.txt"
    with open(wl_path, "w", encoding="utf-8") as f:
        f.write("\n".join(w for w, _, _ in words) + ("\n" if words else ""))
    log(f"[Wordlist] {len(words)} unique words -> sheet 'Wordlist' and {wl_path}", "g")
    build_json(all_data, os.path.splitext(opts.output)[0] + ".json", tool_names)
    log("Done.", "g")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted by user.", "r")
        sys.exit(1)
