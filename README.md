# subrecon

A Python pipeline for subdomain enumeration. It runs several sources one by one, merges and de-duplicates the results, collects DNS and WHOIS data, and writes a styled Excel report.

> **Legal notice:** use this tool only on domains you own or have explicit written permission to test (for example, in-scope bug bounty programs). The author takes no responsibility for misuse.

## Features

- Runs 6 sources in order and shows live progress: Subfinder, Assetfinder, Findomain, Chaos (API key), crt.sh, GitHub Dorking (token)
- Accepts a single domain, several domains, or a list file
- Normalizes, de-duplicates and sorts all results, and records which sources found each host
- Probes every host with ProjectDiscovery `httpx` (last step) and adds an `http_live` column (TRUE/FALSE) plus status code, title, CDN and technologies
- Resolves IP addresses and collects WHOIS fields (registrar, org, country, created, expires, updated, name servers, emails, status)
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
DNS resolve + WHOIS (multi-threaded)
   |
   v
httpx live check (http_live)
   |
   v
Excel report
```

## Requirements

- Python 3.9+
- External tools in your `PATH`: `subfinder`, `assetfinder`, `findomain`, `httpx` (ProjectDiscovery) (optional: `chaos`)
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

## Output

`Summary` sheet: totals per domain, resolving hosts, and results per source (formulas).
`Subdomains` sheet: root domain, subdomain, IPs, sources, source count, WHOIS source and WHOIS fields.

## Notes and limitations

- `http_live` is TRUE when httpx got any HTTP response (any status code), FALSE otherwise, and `N/A` if httpx was skipped. The referer header is set to `https://<root domain>` for each run.
- The Python `httpx` package also installs a command called `httpx`. If both exist, use `--httpx-path` to point to the ProjectDiscovery binary.

- WHOIS is mostly meaningful for registered domains. For a subdomain the tool tries a direct lookup first and falls back to the root domain; the `WHOIS Source` column shows which was used.
- GitHub code search is rate limited (about 30 requests/minute), so that step is slow by design.
- Chaos results depend on the target being in the Chaos dataset.

## License

MIT (add a `LICENSE` file).
