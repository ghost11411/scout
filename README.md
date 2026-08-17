# Automated Bug Bounty Tool

![Made in India](https://img.shields.io/badge/Made%20in-India-orange?style=for-the-badge\&logo=india\&logoColor=white)
![Made in Bash](https://img.shields.io/badge/Made%20in-Bash-blue?style=for-the-badge\&logo=gnu-bash\&logoColor=white)

## Subdomains Gathering Using Tools

This project chains many free sources to discover as many subdomains as possible.

**Passive** — subfinder, assetfinder, findomain, subdog, xsubfind3r, cero, sublist3r,
subdominator, amass, bbot, gau (Wayback/Common Crawl), crt.sh, Cert Spotter, RapidDNS,
HackerTarget, subdomain.center and urlscan.io.

**Passive, with a free API token** — chaos (`PDCP_API_KEY`) and github-subdomains
(`GITHUB_TOKEN`). Both are skipped silently when the token is not set.

**Active** — `dnsx` DNS brute force against a wordlist, plus `alterx` permutations of
everything found, resolved with `dnsx`. Skip either with `SCOUT_BRUTE=0` /
`SCOUT_PERMUTE=0`.

DNS resolution uses `dnsx` throughout — a single `go install`, no compile step and no
external resolver binary to build.

---

## The recon pipeline

Scout chains the stages every modern bug-bounty methodology uses, each feeding the next.
Wildcard targets (`-wc`/`-wf`) get the full pipeline; plain domains (`-dm`/`-df`) are
resolved and probed but never subdomain-enumerated.

The flow follows Jason Haddix's *Bug Hunter's Methodology* (breadth-first asset discovery
→ probing → analysis → targeted scanning) plus ProjectDiscovery's `httpx`/`nuclei` chain.
Wildcard targets (`-wc`/`-wf`) get the full pipeline; plain domains (`-dm`/`-df`) are
resolved and probed but never subdomain-enumerated.

| # | Stage | Tools | Output | Default |
|---|-------|-------|--------|---------|
| 0 | Seed / ASN expansion *(review-only)* | `asnmap`, `amass intel` | `scope_expansion/` | **off — `SCOUT_ASN=1`** |
| 1 | Subdomain enumeration | ~20 passive + active sources | `subdomains/combined_subdomains.txt` | on (wildcards) |
| 2 | DNS resolution | `dnsx` | `final_subdomains.out` | on |
| 3 | **Live HTTP probing** | `httpx` (status/title/tech/server/CDN) | `http/live_hosts.txt`, `http/httpx.txt` | on — `SCOUT_HTTP=0` |
| 4 | URL collection | `gau`, `waybackurls` | `urls/all_urls.out` | on (wildcards) — `SCOUT_URLS=0` |
| 5 | **URL analysis** | `gf` patterns, `unfurl` | `urls/gf/<class>.txt`, `urls/param_keys.txt` | on — `SCOUT_ANALYZE=0` |
| 6 | JS collection | `gau`, `waybackurls`, `katana`, `hakrawler` | `js/all_js_files.out` | on (wildcards) — `SCOUT_JS=0` |
| 7 | **JS analysis** | `jsluice` (endpoints + secrets) | `js/js_endpoints.txt`, `js/js_secrets.jsonl` | on — `SCOUT_JS_ANALYZE=0` |
| 8 | **Vulnerability scan** | `nuclei` (incl. subdomain takeover) | `nuclei/nuclei.jsonl` | **off — `SCOUT_NUCLEI=1`** |
| 9 | **Content discovery** | `ffuf` + raft wordlists | `content/` | **off — `SCOUT_FFUF=1`** |
| 10 | **Port scan** | `naabu` (+ optional `nmap`) | `ports/<host>_ports` | **off — `SCOUT_PORTSCAN=1`** |
| 11 | **Screenshots** | `gowitness` (+ Chromium) | `screenshots/` | **off — `SCOUT_SCREENSHOTS=1`** |
| — | Run summary | *(aggregation)* | `SUMMARY.md` | always |

Stage 3 turns "this name resolves" into "a web service actually answers here", and its
`live_hosts.txt` is what the scanning stages target. Every run ends with a `SUMMARY.md`
rollup of counts and file pointers.

```bash
scout -wc "*.example.com"                                   # full passive recon + summary
SCOUT_NUCLEI=1 SCOUT_FFUF=1 scout -wc "*.example.com"       # add active scanning
SCOUT_SCREENSHOTS=1 SCOUT_ASN=1 scout -wc "*.example.com"   # visual triage + scope leads
```

## Staying in scope & not causing harm

Scout is built to keep a run inside a program's rules of engagement:

- **Passive by default, active by choice.** Stages that send real traffic (`nuclei`, `ffuf`,
  `naabu`) are **off** unless you set their env var. Nothing intrusive runs implicitly.
- **Safe mode** (`SCOUT_SAFE=1`, the default) rate-limits the active tools and **excludes
  `nuclei`'s destructive template classes** (`dos`, `fuzzing`, `intrusive`) so a scan
  finds issues without knocking a site over. `SCOUT_SAFE=0` removes those guards.
- **Out-of-scope exclusions.** `-xc host1,host2` / `-xf file` drop a host *and everything
  under it* from every probing and scanning stage — this is how you honour
  "`*.example.com` in scope **except** `support.example.com`".
- **Identifying User-Agent.** `SCOUT_UA` is sent by every target-touching tool; set it to
  include your researcher handle where a program asks for attribution.
- **Scope expansion is review-only.** ASN/related-domain leads (`SCOUT_ASN=1`) are written
  to `scope_expansion/` and **never auto-scanned** — you confirm they're in scope first.

Useful knobs: `SCOUT_HTTPX_RATELIMIT`, `SCOUT_NUCLEI_SEVERITY`, `SCOUT_NUCLEI_RATELIMIT`,
`SCOUT_FFUF_RATE`, `SCOUT_FFUF_HOST_LIMIT`, `SCOUT_JS_ANALYZE_LIMIT`, `NAABU_TOP_PORTS`.

---

## Install `curl` (so you can use the one-liner installer)

Run this to install `curl` on Debian/Ubuntu systems. The command is in a fenced code block so GitHub will show a copy button.

```bash
sudo apt update && sudo apt install curl -y
```

---

## Install (Recommended For Fresh Install)

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash
```

---

## Install Updates (Recommended For Updating)

Use this to only pull the latest changes without removing local files.

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash -s -- --update
```

---

## Install Forced (If Nothing Else Works)

```bash
curl -sL https://raw.githubusercontent.com/ghost11411/scout/main/configure | bash -s -- --force
```

---

> **Warning:** This project is heavily under development. Use the `--force` option with care as it will remove the install directory before re-cloning.
