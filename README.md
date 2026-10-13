# subrecon

A Python pipeline for subdomain enumeration. It runs several sources one by one, merges and de-duplicates the results, collects DNS and WHOIS data, and writes a styled Excel report.

> **Legal notice:** use this tool only on domains you own or have explicit written permission to test (for example, in-scope bug bounty programs). The author takes no responsibility for misuse.

## Features

- Runs 6 sources in order and shows live progress: Subfinder, Assetfinder, Findomain, Chaos (API key), crt.sh, GitHub Dorking (token)
- Step 7: brute-forces with `ffuf`, using a wordlist built on the fly from the labels already found in steps 1-6 (no external wordlist file needed), and merges any matches back in, tagged `Ffuf`
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
DNS resolve + WHOIS (multi-threaded)
   |
   v
httpx live check (http_live)
   |
   v
Excel + JSON report
```

Step 7 reuses the labels already discovered (e.g. if `x.stage.example.com` was found, `stage` becomes a word) to probe `https://<word>.<domain>` directly with ffuf, so it can surface hosts like `stage.example.com` that no other source returned on its own.

## Requirements

- Python 3.9+
- External tools in your `PATH`: `subfinder`, `assetfinder`, `findomain`, `ffuf`, `httpx` (ProjectDiscovery) (optional: `chaos`)
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
| `-t, --threads` | Threads for DNS/WHOIS (default 10) |
| `--httpx-threads` | httpx `-threads` value (default 1) |
| `--httpx-path` | Path to ProjectDiscovery httpx if the name `httpx` is taken by another tool |
| `--no-httpx` | Skip the live check (`http_live` becomes `N/A`) |
| `--ffuf-threads` | ffuf `-t` value (default 50) |
| `--ffuf-mc` | ffuf `-mc` value, matched status codes (default `200,403`) |
| `--ffuf-path` | Path to the ffuf binary |
| `--ffuf-timeout` | ffuf timeout in seconds (default 1800) |
| `--no-ffuf` | Skip the brute-force step |

## Output

`Wordlist` sheet: unique words, how many subdomains use each, and the root domains they come from.
`Summary` sheet: totals per domain, resolving hosts, and results per source (formulas).
`Subdomains` sheet: root domain, subdomain, IPs, sources, source count, WHOIS source and WHOIS fields.

## Notes and limitations

- `http_live` is TRUE when httpx got any HTTP response (any status code), FALSE otherwise, and `N/A` if httpx was skipped. The referer header is set to `https://<root domain>` for each run.
- The Python `httpx` package also installs a command called `httpx`. If both exist, use `--httpx-path` to point to the ProjectDiscovery binary.

- WHOIS is mostly meaningful for registered domains. For a subdomain the tool tries a direct lookup first and falls back to the root domain; the `WHOIS Source` column shows which was used.
- GitHub code search is rate limited (about 30 requests/minute), so that step is slow by design.
- Chaos results depend on the target being in the Chaos dataset.
- The ffuf wordlist comes only from labels already found in steps 1-6, so it can't invent brand-new words — its value is testing those words directly against the root domain (e.g. turning a deep `x.stage.example.com` into a direct hit on `stage.example.com`). If the first six steps return nothing, step 7 is skipped.
- `-mc 200,403` means only those status codes count as a match; adjust `--ffuf-mc` (e.g. add `301,302`) if you want more.

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
