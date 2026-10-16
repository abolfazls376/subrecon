# subrecon

A Python pipeline for subdomain enumeration. It runs several sources one by one, merges and de-duplicates the results, collects DNS and WHOIS data, and writes a styled Excel report.

> **Legal notice:** use this tool only on domains you own or have explicit written permission to test (for example, in-scope bug bounty programs). The author takes no responsibility for misuse.

## Features

- Runs 6 sources in order and shows live progress: Subfinder, Assetfinder, Findomain, Chaos (API key), crt.sh, GitHub Dorking (token)
- Step 7: brute-forces with `ffuf`, using a wordlist built on the fly from the labels already found in steps 1-6 (no external wordlist file needed), and merges any matches back in, tagged `Ffuf`
- Step 8 (Check CDN): resolves every current host with `dnsx`, then uses `mapcidr -filter-ip` against a CDN ranges file you provide to drop IPs that belong to a CDN, saving a resolved-IPs file and a non-CDN-IPs file
- Step 9 (Virtual Host Discovery): builds 3 wordlists (single words, `word.domain`, and every full subdomain found) plus a merged, deduplicated one - all saved to disk - then ffuf-fuzzes the `Host` header against the root domain's own URL and saves whichever entries returned a matching status code
- Before WHOIS: saves two plain-text dnsx exports - `dnsx -silent` (which subdomains resolve) and `dnsx -silent -resp-only` (the IPs they resolve to)
- WHOIS runs one host at a time (no threads), with a configurable delay between lookups, to avoid whois servers resetting the connection under load
- All per-domain artifacts (ffuf's vhost wordlists, Check CDN's IP files, the dnsx exports) are saved in a folder named after that domain, created next to the Excel output
- At the end of the run, prints a checklist with a green check (or a yellow x and a reason) for every stage, showing what actually ran for this invocation
- Accepts a single domain, several domains, or a list file
- Normalizes, de-duplicates and sorts all results, and records which sources (including Ffuf) found each host
- Probes every host with ProjectDiscovery `httpx` (after ffuf) and adds an `http_live` column (TRUE/FALSE) plus status code, title, CDN and technologies
- Resolves IP addresses and collects WHOIS fields (registrar, org, country, created, expires, updated, name servers, emails, status)
- Builds a custom wordlist from all found subdomains (the label next to the root domain, same as `rev | cut -d . -f 3 | rev | sort -u`), saved in a `Wordlist` sheet and in `<output>_wordlist.txt` — this is the same wordlist ffuf uses internally
- Exports a sorted, typed JSON report (`<output>.json`) ready to feed into another system
- Exports a styled `.xlsx` with a `Summary` sheet and a `Subdomains` sheet (filters, frozen panes, banded rows)

## How it works

```
input domains
   |
   v
[1] Subfinder -> [2] Assetfinder -> [3] Findomain -> [4] Chaos -> [5] crt.sh -> [6] GitHub Dorking
   |
   v
merge + clean + dedupe + sort
   |
   v
[7] Ffuf brute-force (wordlist built from the results above)
   |
   v
merge + dedupe + sort
   |
   v
[8] Check CDN: dnsx resolve -> mapcidr filter -> resolved_ips.txt / non_cdn_ips.txt
   |
   v
[9] Virtual Host Discovery: 3 wordlists + merge -> ffuf Host-header fuzzing -> vhost_discovered.txt
   |
   v
dnsx -silent (resolving subdomains) + dnsx -silent -resp-only (resolved IPs) -> 2 text files
   |
   v
WHOIS, one host at a time, with a delay between lookups
   |
   v
httpx live check (http_live)
   |
   v
Excel + JSON report
```

Each domain gets its own folder, named after it, created next to the Excel file:

```
report.xlsx
report.json
report_wordlist.txt
example.com/
  vhost_1_words.txt
  vhost_2_word_domain.txt
  vhost_3_all_subs.txt
  vhost_4_merged.txt
  vhost_discovered.txt
  resolved_ips.txt
  non_cdn_ips.txt
  dns_resolved_subdomains.txt
  dns_resolved_ips.txt
another-domain.com/
  ...
```

Step 7 reuses the labels already discovered (e.g. if `x.stage.example.com` was found, `stage` becomes a word) to probe `https://<word>.<domain>` directly with ffuf, so it can surface hosts like `stage.example.com` that no other source returned on its own.

Step 8 is independent of the Excel/JSON report: it runs
```
cat subdomains.txt | dnsx -silent -resp-only > resolved.txt
cat resolved.txt     | mapcidr -filter-ip <your cdn-ranges file> > non_cdn.txt
```
against the full current list of hosts for each domain, and writes two plain text files once, after every domain has been processed: `<output>_resolved_ips.txt` (every IP dnsx returned) and `<output>_non_cdn_ips.txt` (the same list with CDN IPs removed). Both files are deduplicated and sorted as real IP addresses.

## Requirements

- Python 3.9+
- External tools in your `PATH`: `subfinder`, `assetfinder`, `findomain`, `ffuf`, `dnsx`, `mapcidr`, `httpx` (ProjectDiscovery) (optional: `chaos`). `dnsx` is used both by Check CDN and by the pre-WHOIS export.
- Python packages: see `requirements.txt`

A missing tool is skipped with a warning; the other steps still run.

## Installation

```bash
git clone https://github.com/<your-username>/subrecon.git
cd subrecon

sudo apt install python3-full python3-venv -y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install the external tools (examples):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
export PATH=$PATH:~/go/bin
# findomain: download a binary from https://github.com/Findomain/Findomain/releases
```

## API keys and tokens

| Service | Where to get it |
|---|---|
| GitHub token | GitHub -> Settings -> Developer settings -> Personal access tokens -> Tokens (classic). No scopes are needed for code search. |
| Chaos API key | https://cloud.projectdiscovery.io -> profile menu -> API Key |

Keep them out of the code and out of Git. Use environment variables:

```bash
export GH_TOKEN="ghp_xxx"
export CHAOS_KEY="xxx"
```

## Usage

```bash
# single domain
python subrecon.py -d example.com --chaos-key "$CHAOS_KEY" --github-token "$GH_TOKEN"

# list of domains (one per line)
python subrecon.py -l domains.txt --chaos-key "$CHAOS_KEY" --github-token "$GH_TOKEN" -o report.xlsx -t 20
```

| Option | Description |
|---|---|
| `-d, --domain` | One or more domains |
| `-l, --list` | File with one domain per line |
| `--chaos-key` | Chaos API key |
| `--github-token` | GitHub personal access token |
| `-o, --output` | Output file (default `subdomains_report.xlsx`) |
| `--whois-delay` | Seconds to sleep between WHOIS lookups - sequential, one host at a time (default 15) |
| `--no-dns-check` | Skip the pre-WHOIS `dnsx -silent` / `dnsx -silent -resp-only` exports |
| `--httpx-threads` | httpx `-threads` value (default 1) |
| `--httpx-path` | Path to ProjectDiscovery httpx if the name `httpx` is taken by another tool |
| `--no-httpx` | Skip the live check (`http_live` becomes `N/A`) |
| `--ffuf-threads` | ffuf `-t` value (default 50) |
| `--ffuf-mc` | ffuf `-mc` value, matched status codes (default `200,403`) |
| `--ffuf-path` | Path to the ffuf binary |
| `--ffuf-timeout` | ffuf timeout in seconds (default 1800) |
| `--no-ffuf` | Skip the brute-force step |
| `--cdn-ranges` | Path to a plain IPv4 CDN ranges file (one CIDR/IP per line) - required to run the Check CDN step |
| `--dnsx-path` | Path to dnsx |
| `--mapcidr-path` | Path to mapcidr |
| `--dnsx-timeout` | dnsx timeout in seconds (default 600) |
| `--mapcidr-timeout` | mapcidr timeout in seconds (default 300) |
| `--no-cdn-check` | Skip the Check CDN step |
| `--vhost-threads` | ffuf `-t` value for vhost fuzzing (default 50) |
| `--vhost-mc` | ffuf `-mc` value for vhost fuzzing (default `200,403,301`) |
| `--vhost-timeout` | vhost ffuf timeout in seconds (default 1800) |
| `--no-vhost` | Skip the Virtual Host Discovery step |

## Output

`Wordlist` sheet: unique words, how many subdomains use each, and the root domains they come from.
`Summary` sheet: totals per domain, resolving hosts, and results per source (formulas, now including `Ffuf`).
`Subdomains` sheet: root domain, subdomain, IPs, sources, source count, WHOIS source and WHOIS fields.
`<output>_resolved_ips.txt`: every IP dnsx resolved, across all input domains.
`<output>_non_cdn_ips.txt`: the same IPs with anything in `--cdn-ranges` filtered out - this is your "real", non-CDN attack surface.

Everything below is written inside `<domain>/`, a folder created next to the Excel file and named after the domain it belongs to:
- `vhost_1_words.txt` - single words (e.g. `admin`, `dev`)
- `vhost_2_word_domain.txt` - those words with the domain appended (e.g. `admin.example.com`)
- `vhost_3_all_subs.txt` - every full subdomain found for that domain
- `vhost_4_merged.txt` - all three merged and deduplicated (this is the file ffuf actually fuzzes with)
- `vhost_discovered.txt` - entries from the merged wordlist whose `Host` header got a response matching `--vhost-mc`
- `resolved_ips.txt` / `non_cdn_ips.txt` - Check CDN's dnsx + mapcidr output for that domain
- `dns_resolved_subdomains.txt` / `dns_resolved_ips.txt` - the pre-WHOIS `dnsx -silent` / `dnsx -silent -resp-only` exports for that domain

The Excel report, the JSON report and the combined wordlist (`<output>_wordlist.txt`) stay at the top level next to `--output`, since they summarize *all* input domains together - only the single-domain, per-domain raw artifacts above move into the domain's own folder.

At the very end, a checklist is printed showing which stages actually ran for this invocation (green check) versus which were skipped and why (yellow x with a short reason - missing binary, missing credential, or an explicit `--no-*` flag):

```
==================================================
  Summary of tasks
==================================================
  [✓] Subfinder
  [✓] Assetfinder
  [✗] Findomain (binary not found in PATH)
  [✗] Chaos (no --chaos-key provided)
  [✓] crt.sh
  [✓] GitHub Dorking
  [✓] Ffuf (brute-force, step 7)
  [✓] Check CDN (dnsx + mapcidr)
  [✓] Virtual Host Discovery
  [✓] DNS Export (dnsx -silent)
  [✓] WHOIS
  [✓] httpx (live check)
  [✓] Excel Report
  [✓] JSON Report
```

This reflects whether each stage was *enabled and available* for the run (binary present, credential provided, flag not disabled) - not whether it found any results for a particular domain.

## Notes and limitations

- `http_live` is TRUE when httpx got any HTTP response (any status code), FALSE otherwise, and `N/A` if httpx was skipped. The referer header is set to `https://<root domain>` for each run.
- The Python `httpx` package also installs a command called `httpx`. If both exist, use `--httpx-path` to point to the ProjectDiscovery binary.

- WHOIS is mostly meaningful for registered domains. For a subdomain the tool tries a direct lookup first and falls back to the root domain; the `WHOIS Source` column shows which was used.
- GitHub code search is rate limited (about 30 requests/minute), so that step is slow by design.
- Chaos results depend on the target being in the Chaos dataset.
- The ffuf wordlist comes only from labels already found in steps 1-6, so it can't invent brand-new words — its value is testing those words directly against the root domain (e.g. turning a deep `x.stage.example.com` into a direct hit on `stage.example.com`). If the first six steps return nothing, step 7 is skipped.
- `-mc 200,403` means only those status codes count as a match; adjust `--ffuf-mc` (e.g. add `301,302`) if you want more.
- Check CDN needs `--cdn-ranges` pointed at your own plain IPv4 CDN ranges file; without it (or without `dnsx`/`mapcidr` in `PATH`) the step is skipped with a warning and the rest of the pipeline still runs.
- WHOIS is sequential by design now (`--whois-delay`, default 15s): with many subdomains this is the slowest part of a run on purpose, to avoid rate-limit resets from whois servers. Lower `--whois-delay` at your own risk for small target lists; there is no way to skip WHOIS entirely.
- The two pre-WHOIS dnsx exports use the full current subdomain list (post ffuf/CDN merge) and are independent of the Check CDN step's own `dnsx -silent -resp-only` call - they're written even if `--no-cdn-check` is set, and skipped only with `--no-dns-check` or if `dnsx` is missing.
- Step 8 does not change the Excel `IP Address(es)` column (that one is a plain Python DNS lookup per host, used for WHOIS/httpx bookkeeping) - it is a separate, authoritative IP list meant for things like port scanning a real, non-CDN attack surface.
- Step 9 fuzzes the `Host` header against a *fixed* URL (`https://<domain>`), so it is looking for other sites/vhosts answering on the same IP/endpoint - it does not touch DNS or the Excel/JSON report. Only entries whose response status is in `--vhost-mc` end up in the discovered file; everything else from the merged wordlist is tried but not kept.

## License

MIT (add a `LICENSE` file).

## JSON output

Written next to the Excel file (`report.xlsx` -> `report.json`). Structure (`schema_version` 1.0):

```json
{
  "schema_version": "1.0",
  "tool": "subrecon",
  "generated_at": "2026-10-13T10:00:00+00:00",
  "summary": {"total_domains": 1, "total_subdomains": 2, "resolving": 1, "http_live": 1,
              "per_source": {"Subfinder": 1, "crt.sh": 2}},
  "domains": [
    {
      "domain": "example.com",
      "stats": {"total_subdomains": 2, "resolving": 1, "http_live": 1},
      "subdomains": [
        {
          "subdomain": "a.example.com", "ips": ["1.1.1.1"], "resolves": true,
          "http_live": true, "status_code": 200, "title": "Home", "cdn": "cloudflare",
          "technologies": ["Nginx"], "http_url": "https://a.example.com",
          "sources": ["crt.sh"], "source_count": 1,
          "whois": {"source": "root domain", "registrar": "...", "organization": null,
                    "country": null, "created": "2000-01-01", "expires": null, "updated": null,
                    "name_servers": [], "emails": [], "status": []}
        }
      ]
    }
  ],
  "wordlist": [{"word": "a", "count": 1, "root_domains": ["example.com"]}]
}
```

Domains and subdomains are sorted alphabetically. Missing values are `null`, lists are real arrays, `http_live` is `true`/`false` (or `null` if httpx was not run).
