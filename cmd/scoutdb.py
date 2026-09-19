#!/usr/bin/env python3
"""Scout result database: schema, ingest, first-seen diffing, backfill, stats.

Every write to the database happens here. This is python rather than the
sqlite3 CLI driven from bash for three reasons that all bite in practice:

  * Parameterised SQL. The URL corpus contains quotes, backticks, newlines and
    the occasional NUL. Building SQL by string interpolation in bash over
    urls/all_urls.out is a quoting bug waiting to happen.
  * One transaction for 200k rows instead of 200k sqlite3 forks.
  * jq is optional everywhere else in this project, with a degraded fallback.
    That is fine for a report and not fine for a data store; the python
    sqlite3 and json modules are stdlib and cannot go missing.

FIRST-SEEN SEMANTICS: an asset is "new" when it has never been recorded for
that target in ANY prior run. Not "absent from the previous run" -- a flaky
source that drops a host and recovers it would re-alert every time under that
rule (assetfinder went 63 -> 13 -> 13 across three real runs).

THE GATE: a stage that self-skips because its tool is missing leaves an empty
or absent file that is indistinguishable from "ran and found nothing".
.telemetry/tools.tsv is the only positive record of what actually executed, so
ingestion of each kind is gated on it. A kind that did not demonstrably run is
NOT ingested and NOT diffed -- it is reported as "not run", never as 0.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import time

SCHEMA_VERSION = 1
INGEST_VERSION = 1

# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS target (
  id            INTEGER PRIMARY KEY,
  root          TEXT    NOT NULL UNIQUE,
  is_unscoped   INTEGER NOT NULL DEFAULT 0,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS run (
  id                   INTEGER PRIMARY KEY,
  run_uid              TEXT    NOT NULL UNIQUE,
  dir                  TEXT    NOT NULL,
  started_at           INTEGER NOT NULL,
  ended_at             INTEGER,
  total_seconds        INTEGER,
  status               TEXT    NOT NULL,
  started_at_estimated INTEGER NOT NULL DEFAULT 0,
  scout_version        TEXT,
  safe_mode            INTEGER,
  user_agent           TEXT,
  argv                 TEXT,
  toggles              TEXT,
  host                 TEXT,
  ingested_at          INTEGER NOT NULL,
  ingest_version       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS run_started ON run(started_at);

CREATE TABLE IF NOT EXISTS run_target (
  run_id    INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES target(id),
  PRIMARY KEY (run_id, target_id)
);

CREATE TABLE IF NOT EXISTS run_stage (
  run_id   INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  stage    TEXT    NOT NULL,
  status   TEXT    NOT NULL,
  evidence TEXT,
  tools    TEXT,
  seconds  INTEGER,
  PRIMARY KEY (run_id, stage)
);

CREATE TABLE IF NOT EXISTS asset (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES target(id),
  kind          TEXT    NOT NULL,
  value         TEXT    NOT NULL,
  raw           TEXT,
  first_run_id  INTEGER NOT NULL REFERENCES run(id),
  first_seen_at INTEGER NOT NULL,
  last_run_id   INTEGER NOT NULL REFERENCES run(id),
  last_seen_at  INTEGER NOT NULL,
  times_seen    INTEGER NOT NULL DEFAULT 1,
  UNIQUE (target_id, kind, value)
);
CREATE INDEX IF NOT EXISTS asset_new  ON asset(first_run_id, kind);
CREATE INDEX IF NOT EXISTS asset_kind ON asset(target_id, kind, last_seen_at);

CREATE TABLE IF NOT EXISTS run_asset (
  run_id   INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
  PRIMARY KEY (run_id, asset_id)
);
CREATE INDEX IF NOT EXISTS run_asset_rev ON run_asset(asset_id);

CREATE TABLE IF NOT EXISTS asset_tag (
  asset_id INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
  run_id   INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  tag      TEXT    NOT NULL,
  PRIMARY KEY (asset_id, run_id, tag)
);
CREATE INDEX IF NOT EXISTS asset_tag_tag ON asset_tag(tag);

CREATE TABLE IF NOT EXISTS http_meta (
  asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
  run_id      INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  status_code INTEGER,
  title       TEXT,
  server      TEXT,
  tech        TEXT,
  PRIMARY KEY (asset_id, run_id)
);

CREATE TABLE IF NOT EXISTS finding_detail (
  asset_id    INTEGER PRIMARY KEY REFERENCES asset(id) ON DELETE CASCADE,
  source      TEXT,
  template_id TEXT,
  name        TEXT,
  severity    TEXT,
  host        TEXT,
  matched_at  TEXT,
  raw_json    TEXT
);
CREATE INDEX IF NOT EXISTS finding_sev ON finding_detail(severity);
"""

# --------------------------------------------------------------------------
# Stage map: which telemetry tool rows prove a kind's producing stage ran.
#
# Matching is a case-insensitive substring test against the `tool` column of
# .telemetry/tools.tsv, because REC_TOOL records names like "httpx (probe)".
# --------------------------------------------------------------------------
STAGES = {
    "subdomain": dict(
        phase="Subdomain Enumeration", toggle=None,
        tools=["subfinder", "assetfinder", "findomain", "subdog", "xsubfind3r",
               "cero", "crt", "sublist3r", "subdominator", "amass", "bbot",
               "github-subdomains", "chaos", "gau", "rapiddns", "certspotter",
               "hackertarget", "subdomaincenter", "urlscan", "dnsx_brute"]),
    "resolved": dict(phase="DNS Resolution", toggle=None, tools=["dnsx"]),
    "live_host": dict(phase="HTTP Probing", toggle="SCOUT_HTTP", tools=["httpx"]),
    "url": dict(phase="URL Discovery", toggle="SCOUT_URLS",
                tools=["gau", "waybackurls", "katana", "hakrawler"]),
    "url_shape": dict(phase="URL Discovery", toggle="SCOUT_URLS",
                      tools=["gau", "waybackurls", "katana", "hakrawler"]),
    "param": dict(phase="URL Analysis", toggle="SCOUT_ANALYZE",
                  tools=["gf", "unfurl"]),
    "js_file": dict(phase="JavaScript Discovery", toggle="SCOUT_JS",
                    tools=["gau", "waybackurls", "katana", "hakrawler"]),
    "js_endpoint": dict(phase="JavaScript Analysis", toggle="SCOUT_JS_ANALYZE",
                        tools=["jsluice"]),
    "js_secret": dict(phase="JavaScript Analysis", toggle="SCOUT_JS_ANALYZE",
                      tools=["jsluice"]),
    "finding": dict(phase="Vulnerability Scanning", toggle="SCOUT_NUCLEI",
                    tools=["nuclei"]),
    "takeover": dict(phase="Subdomain Takeover", toggle="SCOUT_TAKEOVER",
                     tools=["subzy", "nuclei"]),
    "port": dict(phase="Port & Service Scan", toggle="SCOUT_PORTSCAN",
                 tools=["naabu", "masscan"]),
}

# Kind -> the file(s) it is ingested from, relative to the run dir.
SOURCES = {
    "subdomain":   ["subdomains/combined_subdomains.txt", "final_subdomains.out"],
    "resolved":    ["resolved/dnsx_resolved.out"],
    "live_host":   ["http/live_hosts.txt"],
    "url":         ["urls/all_urls.out"],
    "js_file":     ["js/all_js_files.out"],
    "js_endpoint": ["js/js_endpoints.txt"],
    "param":       ["urls/param_keys.txt"],
}

CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(s):
    """Strip NUL and C0 controls. One junk byte in an archived URL would
    otherwise abort the entire transaction."""
    return CONTROL_RE.sub("", s).strip()


def read_lines(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "rb") as fh:
        for raw in fh:
            v = clean(raw.decode("utf-8", errors="replace"))
            if v:
                out.append(v)
    return out


def host_of_url(u):
    """Host of a URL. Mirrors EXCLUDE_URLS in cmd/lib: strip scheme, then
    everything from the first /:?# onwards."""
    h = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)
    h = re.split(r"[/:?#]", h, maxsplit=1)[0]
    return h.lower()


def canon_url(u):
    """Canonical URL for identity: lowercase scheme+host, drop the default
    port and any fragment, keep path+query verbatim, strip a trailing slash
    only on a bare root."""
    u = u.split("#", 1)[0]
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]+)(.*)$", u)
    if not m:
        return u
    scheme, netloc, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
    for scheme_default in (("http", ":80"), ("https", ":443")):
        if scheme == scheme_default[0] and netloc.endswith(scheme_default[1]):
            netloc = netloc[: -len(scheme_default[1])]
    if rest in ("", "/"):
        rest = ""
    return "%s://%s%s" % (scheme, netloc, rest)


def url_shape(u):
    """URL with every query VALUE replaced by '*'.

    Parameter-value churn (?id=1 vs ?id=2) is the single biggest source of
    fake "new URLs" -- without this, a diff reports thousands of new URLs per
    run that are the same endpoints. Diffing on shape surfaces genuinely new
    endpoints instead."""
    base, sep, query = canon_url(u).partition("?")
    if not sep or not query:
        return base
    parts = []
    for kv in query.split("&"):
        k, eq, _v = kv.partition("=")
        parts.append(k + "=*" if eq else k)
    return base + "?" + "&".join(parts)


# --------------------------------------------------------------------------
# Connection helpers
# --------------------------------------------------------------------------
def connect_rw(path):
    first = not os.path.exists(path)
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(path, timeout=20.0, isolation_level=None)
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA foreign_keys=ON")
    if first:
        con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    con.execute(
        "INSERT INTO schema_meta(key,value) VALUES('version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),))
    return con


def connect_ro(path):
    if not os.path.exists(path):
        die("no database at %s (run a scan, or: scout db backfill --all)" % path)
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=20.0)
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA query_only=1")
    con.row_factory = sqlite3.Row
    return con


def die(msg, code=1):
    sys.stderr.write("scoutdb: %s\n" % msg)
    sys.exit(code)


# --------------------------------------------------------------------------
# Run manifest + telemetry
# --------------------------------------------------------------------------
def load_manifest(run_dir):
    p = os.path.join(run_dir, ".scout_run.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", errors="replace") as fh:
            return json.load(fh)
    except Exception as e:
        sys.stderr.write("scoutdb: unreadable manifest %s: %s\n" % (p, e))
        return None


def synth_manifest(run_dir):
    """Manifest for a run that predates the sentinel (backfill). started_at is
    a genuine guess, flagged as such rather than presented as fact."""
    base = os.path.basename(run_dir.rstrip("/"))
    started, estimated = None, 1
    m = re.match(r"^output_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})$", base)
    if m:
        try:
            started = int(time.mktime(tuple(
                [int(x) for x in m.groups()] + [0, 0, -1])))
        except Exception:
            started = None
    if started is None:
        oldest = None
        for root, _dirs, files in os.walk(run_dir):
            for f in files:
                try:
                    st = os.stat(os.path.join(root, f)).st_mtime
                except OSError:
                    continue
                oldest = st if oldest is None else min(oldest, st)
        started = int(oldest if oldest else time.time())
    uid = hashlib.sha256(
        ("%s|%d" % (os.path.realpath(run_dir), started)).encode()).hexdigest()[:32]
    return {"schema": 1, "run_uid": uid, "status": "legacy",
            "started_at": started, "ended_at": None, "total_seconds": None,
            "argv": [], "toggles": {}, "safe": None, "ua": None, "host": None,
            "_estimated": estimated}


def load_telemetry(run_dir):
    tools, phases = [], {}
    p = os.path.join(run_dir, ".telemetry", "tools.tsv")
    if os.path.isfile(p):
        for line in read_lines(p):
            f = line.split("\t")
            if len(f) >= 5:
                tools.append(dict(phase=f[0], tool=f[1],
                                  secs=int(f[2] or 0), count=int(f[3] or 0),
                                  cmd=f[4]))
    p = os.path.join(run_dir, ".telemetry", "phases.tsv")
    if os.path.isfile(p):
        for line in read_lines(p):
            f = line.split("\t")
            if len(f) >= 2:
                phases[f[0]] = int(f[1] or 0)
    return tools, phases


def stage_status(kind, tools, phases, toggles):
    """ran | skipped_toggle | skipped_tool | unknown -- in priority order.

    A tool row is POSITIVE PROOF the binary executed, whatever its output
    count. That is the only trustworthy signal; file size is not."""
    spec = STAGES.get(kind)
    if not spec:
        return "unknown", "", [], 0
    matched = [t for t in tools
               if any(n.lower() in t["tool"].lower() for n in spec["tools"])
               and (not spec["phase"] or t["phase"] == spec["phase"])]
    if matched:
        ev = "telemetry: " + ", ".join(
            sorted(set("%s x%d" % (t["tool"], 1) for t in matched))[:6])
        return ("ran", ev, [dict(tool=t["tool"], secs=t["secs"], count=t["count"])
                            for t in matched],
                sum(t["secs"] for t in matched))
    tg = spec.get("toggle")
    if tg and str(toggles.get(tg, "")) == "0":
        return "skipped_toggle", "%s=0" % tg, [], 0
    if spec["phase"] and spec["phase"] in phases:
        return ("skipped_tool",
                "phase '%s' ran but no tool recorded" % spec["phase"], [], 0)
    return "unknown", "no telemetry for phase '%s'" % (spec["phase"] or "?"), [], 0


# --------------------------------------------------------------------------
# Targets and attribution
# --------------------------------------------------------------------------
def load_roots(run_dir):
    for name in ("scope_roots.txt", "wildcards_base.txt", "domains_all.txt"):
        p = os.path.join(run_dir, name)
        if os.path.isfile(p):
            roots = read_lines(p)
            if roots:
                if name == "scope_roots.txt":
                    return roots
                extra = read_lines(os.path.join(run_dir, "domains_all.txt"))
                return sorted(set(roots) | set(extra))
    return []


def attribute(value, kind, roots_set):
    """Root this value belongs to, or '' for the unscoped catch-all.

    Walks ancestors one label at a time, so the FIRST match is the longest
    match -- correct when both foo.com and sub.foo.com are roots. Same walk as
    EXCLUDE_HOSTS (cmd/lib) and the coverage tripwire in scout."""
    h = value
    if kind in ("url", "url_shape", "live_host", "js_file", "js_endpoint"):
        h = host_of_url(value)
    h = h.lower()
    if h in roots_set:
        return h
    s = h
    while "." in s:
        s = s.split(".", 1)[1]
        if s in roots_set:
            return s
    return ""


class Ingester(object):
    def __init__(self, con, run_id, run_started, roots_set, target_ids):
        self.con, self.run_id = con, run_id
        self.started = run_started
        self.roots_set, self.target_ids = roots_set, target_ids
        self.moved_first_seen = 0

    def target_id(self, root):
        if root in self.target_ids:
            return self.target_ids[root]
        cur = self.con.execute(
            "INSERT INTO target(root,is_unscoped,first_seen_at,last_seen_at) "
            "VALUES(?,?,?,?) ON CONFLICT(root) DO UPDATE SET "
            "last_seen_at=MAX(target.last_seen_at,excluded.last_seen_at) "
            "RETURNING id", (root, 1 if root == "" else 0,
                             self.started, self.started))
        tid = cur.fetchone()[0]
        self.target_ids[root] = tid
        return tid

    def add(self, kind, value, raw=None, tags=(), detail=None):
        value = clean(value)
        if not value:
            return None
        root = attribute(value, kind, self.roots_set)
        tid = self.target_id(root)
        cur = self.con.execute(
            "INSERT INTO asset(target_id,kind,value,raw,first_run_id,"
            "first_seen_at,last_run_id,last_seen_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(target_id,kind,value) DO UPDATE SET "
            "  first_run_id  = CASE WHEN excluded.first_seen_at < asset.first_seen_at "
            "                       THEN excluded.first_run_id ELSE asset.first_run_id END,"
            "  first_seen_at = MIN(asset.first_seen_at, excluded.first_seen_at),"
            "  last_run_id   = CASE WHEN excluded.last_seen_at > asset.last_seen_at "
            "                       THEN excluded.last_run_id ELSE asset.last_run_id END,"
            "  last_seen_at  = MAX(asset.last_seen_at, excluded.last_seen_at),"
            "  times_seen    = asset.times_seen + 1 "
            "RETURNING id, first_run_id",
            (tid, kind, value, raw, self.run_id, self.started,
             self.run_id, self.started))
        aid, first_run = cur.fetchone()
        self.con.execute(
            "INSERT OR IGNORE INTO run_asset(run_id,asset_id) VALUES(?,?)",
            (self.run_id, aid))
        for t in tags:
            self.con.execute(
                "INSERT OR IGNORE INTO asset_tag(asset_id,run_id,tag) "
                "VALUES(?,?,?)", (aid, self.run_id, t))
        if detail:
            self.con.execute(
                "INSERT INTO finding_detail(asset_id,source,template_id,name,"
                "severity,host,matched_at,raw_json) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(asset_id) DO UPDATE SET "
                "source=excluded.source, template_id=excluded.template_id, "
                "name=excluded.name, severity=excluded.severity, "
                "host=excluded.host, matched_at=excluded.matched_at, "
                "raw_json=excluded.raw_json",
                (aid, detail.get("source"), detail.get("template_id"),
                 detail.get("name"), detail.get("severity"), detail.get("host"),
                 detail.get("matched_at"), detail.get("raw_json")))
        return aid


# --------------------------------------------------------------------------
# Per-kind ingestion
# --------------------------------------------------------------------------
def ingest_simple(ing, run_dir, kind):
    n = 0
    seen = set()
    for rel in SOURCES.get(kind, []):
        for v in read_lines(os.path.join(run_dir, rel)):
            key = canon_url(v) if kind in ("url", "js_file", "js_endpoint",
                                           "live_host") else v.lower()
            if key in seen:
                continue
            seen.add(key)
            if ing.add(kind, key, raw=v):
                n += 1
    return n


def ingest_url_shapes(ing, run_dir):
    n, seen = 0, set()
    for v in read_lines(os.path.join(run_dir, "urls/all_urls.out")):
        s = url_shape(v)
        if s in seen:
            continue
        seen.add(s)
        if ing.add("url_shape", s, raw=v):
            n += 1
    return n


def ingest_gf_tags(ing, run_dir):
    """gf buckets tag existing URL assets. An ABSENT bucket file means zero
    hits (cmd/analyze_urls rm -f's empty ones), not that the stage skipped."""
    d = os.path.join(run_dir, "urls", "gf")
    if not os.path.isdir(d):
        return 0
    n = 0
    for f in sorted(os.listdir(d)):
        if not f.endswith(".txt"):
            continue
        cat = f[:-4]
        for v in read_lines(os.path.join(d, f)):
            if ing.add("url", canon_url(v), raw=v, tags=("gf:" + cat,)):
                n += 1
    return n


def ingest_findings(ing, run_dir):
    """nuclei-family JSONL from three files, plus the text-based vuln outputs."""
    n = 0
    for rel, source in (("nuclei/nuclei.jsonl", "nuclei"),
                        ("vulns/owasp_nuclei.jsonl", "owasp_nuclei"),
                        ("takeover/nuclei_takeover.jsonl", "nuclei_takeover")):
        p = os.path.join(run_dir, rel)
        if not os.path.isfile(p):
            continue
        for line in read_lines(p):
            try:
                o = json.loads(line)
            except Exception:
                continue
            info = o.get("info") or {}
            tid = o.get("template-id") or o.get("templateID") or ""
            name = info.get("name") or tid or "unknown"
            sev = (info.get("severity") or "unknown").lower()
            host = o.get("host") or ""
            matched = o.get("matched-at") or o.get("matched") or host
            if not host and matched:
                host = host_of_url(matched)
            kind = "takeover" if source == "nuclei_takeover" else "finding"
            val = "%s|%s|%s" % (tid or name, sev, matched or host)
            if ing.add(kind, val, raw=matched or host,
                       tags=("sev:" + sev, "src:" + source),
                       detail=dict(source=source, template_id=tid, name=name,
                                   severity=sev, host=host, matched_at=matched,
                                   raw_json=line[:4000])):
                n += 1
    # Signature-confirmed URL findings. These are confirmations, not candidates.
    for rel, source, sev in (("vulns/lfi.txt", "lfi", "high"),
                             ("vulns/sqli.txt", "sqli", "critical"),
                             ("vulns/open_redirect.txt", "open_redirect", "medium")):
        for v in read_lines(os.path.join(run_dir, rel)):
            if ing.add("finding", "%s|%s|%s" % (source, sev, canon_url(v)),
                       raw=v, tags=("sev:" + sev, "src:" + source),
                       detail=dict(source=source, template_id=source,
                                   name=source.upper() + " (signature match)",
                                   severity=sev, host=host_of_url(v),
                                   matched_at=v, raw_json=None)):
                n += 1
    # dalfox plain-text output is unstructured; keep the line verbatim.
    for v in read_lines(os.path.join(run_dir, "vulns/xss.txt")):
        if ing.add("finding", "xss|high|" + v[:400], raw=v,
                   tags=("sev:high", "src:dalfox"),
                   detail=dict(source="dalfox", template_id="dalfox",
                               name="XSS (dalfox)", severity="high",
                               host="", matched_at=v[:400], raw_json=None)):
            n += 1
    return n


SUBZY_VULN_RE = re.compile(r"\[\s*VULNERABLE\s*\]", re.I)


def ingest_takeovers(ing, run_dir):
    """subzy findings.

    Prefer subzy.json, which is structured. It holds `null` when there is
    nothing to report, so fall back to parsing stdout only when it carries no
    usable list.

    The stdout fallback requires a BRACKETED [ VULNERABLE ] token, not the
    substring "vulnerable". subzy's own banner prints

        [ No ] Save only vulnerable subdomains
        [ Yes ] Show only potentially vulnerable subdomains (--hide_fails)

    and a substring test turns those two configuration lines into two
    "takeover findings" on every single run -- which is what the first
    end-to-end run of this feature did, against a domain that does not exist.
    """
    n = 0
    jp = os.path.join(run_dir, "takeover/subzy.json")
    if os.path.isfile(jp):
        try:
            with open(jp, "r", errors="replace") as fh:
                doc = json.load(fh)
        except Exception:
            doc = None
        if isinstance(doc, list):
            for o in doc:
                if not isinstance(o, dict):
                    continue
                sub = o.get("subdomain") or o.get("url") or o.get("host") or ""
                svc = o.get("service") or o.get("engine") or "unknown"
                if not sub:
                    continue
                if ing.add("takeover", "subzy|%s|%s" % (svc, sub), raw=sub,
                           tags=("sev:high", "src:subzy"),
                           detail=dict(source="subzy", template_id="subzy",
                                       name="Possible subdomain takeover (%s)" % svc,
                                       severity="high", host=host_of_url(sub),
                                       matched_at=sub,
                                       raw_json=json.dumps(o)[:4000])):
                    n += 1
            return n

    for v in read_lines(os.path.join(run_dir, "takeover/takeovers.txt")):
        if not SUBZY_VULN_RE.search(v):
            continue
        if ing.add("takeover", "subzy|" + v[:400], raw=v,
                   tags=("sev:high", "src:subzy"),
                   detail=dict(source="subzy", template_id="subzy",
                               name="Possible subdomain takeover",
                               severity="high", host="", matched_at=v[:400],
                               raw_json=None)):
            n += 1
    return n


def ingest_http_meta(ing, run_dir):
    """httpx bracketed columns: URL [200] [Title] [server] [tech,tech].
    Fields are OMITTED when empty, so position is not reliable -- classify
    each bracket by shape instead."""
    p = os.path.join(run_dir, "http/httpx.txt")
    if not os.path.isfile(p):
        return 0
    n = 0
    for line in read_lines(p):
        parts = re.findall(r"\[([^\]]*)\]", line)
        url = line.split(" ", 1)[0]
        if not url.startswith("http"):
            continue
        code, title, server, tech = None, None, None, None
        for f in parts:
            f = f.strip()
            if not f:
                continue
            if code is None and re.fullmatch(r"\d{3}", f):
                code = int(f)
            elif "," in f and tech is None:
                tech = f
            elif title is None:
                title = f
            elif server is None:
                server = f
            elif tech is None:
                tech = f
        aid = ing.add("live_host", canon_url(url), raw=url)
        if aid:
            ing.con.execute(
                "INSERT INTO http_meta(asset_id,run_id,status_code,title,server,tech)"
                " VALUES(?,?,?,?,?,?) ON CONFLICT(asset_id,run_id) DO UPDATE SET"
                " status_code=excluded.status_code, title=excluded.title,"
                " server=excluded.server, tech=excluded.tech",
                (aid, ing.run_id, code, title, server, tech))
            n += 1
    return n


def ingest_ports(ing, run_dir, port_map):
    """SAFE_NAME is not reversible, so cmd/persist hands us a FORWARD
    safe->host map built from final_subdomains.out. Never parse a hostname
    back out of a filename."""
    d = os.path.join(run_dir, "ports")
    if not os.path.isdir(d):
        return 0
    n = 0
    for f in sorted(os.listdir(d)):
        if not f.endswith("_ports"):
            continue
        host = port_map.get(f[:-len("_ports")])
        if not host:
            continue
        for v in read_lines(os.path.join(d, f)):
            if v.isdigit() and ing.add("port", "%s:%s" % (host, v), raw=v):
                n += 1
    return n


def ingest_js_secrets(ing, run_dir):
    n = 0
    for line in read_lines(os.path.join(run_dir, "js/js_secrets.jsonl")):
        try:
            o = json.loads(line)
        except Exception:
            continue
        kind_ = o.get("kind") or o.get("type") or "secret"
        ctx = o.get("filename") or o.get("url") or ""
        data = o.get("data")
        val = "%s|%s" % (kind_, json.dumps(data, sort_keys=True)[:300]
                         if data is not None else line[:300])
        if ing.add("js_secret", val, raw=ctx, tags=("secret:" + str(kind_),)):
            n += 1
    return n


# --------------------------------------------------------------------------
# ingest command
# --------------------------------------------------------------------------
DIFF_FILES = {
    "subdomain": "new_subdomains.txt", "resolved": "new_resolved.txt",
    "live_host": "new_live_hosts.txt", "url": "new_urls.txt",
    "url_shape": "new_url_shapes.txt", "js_file": "new_js_files.txt",
    "js_endpoint": "new_js_endpoints.txt", "js_secret": "new_js_secrets.txt",
    "param": "new_params.txt", "port": "new_ports.txt",
    "takeover": "new_takeovers.txt",
}


def cmd_ingest(args):
    run_dir = os.path.realpath(args.run_dir)
    if not os.path.isdir(run_dir):
        die("no such run directory: %s" % run_dir)

    man = load_manifest(run_dir)
    if man is None:
        if not args.legacy:
            die("no .scout_run.json in %s (use --legacy to synthesize one)" % run_dir)
        man = synth_manifest(run_dir)
    status = man.get("status", "unknown")
    if status != "complete" and not args.allow_partial and status != "legacy":
        die("run status is '%s', refusing to ingest (use --allow-partial)" % status)

    tools, phases = load_telemetry(run_dir)
    toggles = man.get("toggles") or {}
    roots = load_roots(run_dir)
    roots_set = set(r.lower() for r in roots)
    started = int(man.get("started_at") or time.time())

    con = connect_rw(args.db)
    port_map = {}
    if args.port_map and os.path.isfile(args.port_map):
        for line in read_lines(args.port_map):
            f = line.split("\t")
            if len(f) == 2:
                port_map[f[0]] = f[1]

    try:
        con.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as e:
        die("database busy: %s" % e)

    try:
        cur = con.execute(
            "INSERT INTO run(run_uid,dir,started_at,ended_at,total_seconds,status,"
            "started_at_estimated,scout_version,safe_mode,user_agent,argv,toggles,"
            "host,ingested_at,ingest_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_uid) DO UPDATE SET dir=excluded.dir,"
            " status=excluded.status, ended_at=excluded.ended_at,"
            " total_seconds=excluded.total_seconds,"
            " ingested_at=excluded.ingested_at RETURNING id",
            (man.get("run_uid") or hashlib.sha256(run_dir.encode()).hexdigest()[:32],
             run_dir, started, man.get("ended_at"), man.get("total_seconds"),
             status, int(man.get("_estimated", 0)), man.get("scout_version"),
             man.get("safe"), man.get("ua"), json.dumps(man.get("argv") or []),
             json.dumps(toggles), man.get("host"), int(time.time()),
             INGEST_VERSION))
        run_id = cur.fetchone()[0]

        target_ids = {}
        ing = Ingester(con, run_id, started, roots_set, target_ids)
        for r in roots:
            con.execute("INSERT OR IGNORE INTO run_target(run_id,target_id) "
                        "VALUES(?,?)", (run_id, ing.target_id(r.lower())))

        counts, statuses = {}, {}
        for kind in ("subdomain", "resolved", "live_host", "url", "url_shape",
                     "param", "js_file", "js_endpoint", "js_secret",
                     "finding", "takeover", "port"):
            st, ev, tl, secs = stage_status(kind, tools, phases, toggles)
            statuses[kind] = (st, ev)
            con.execute(
                "INSERT INTO run_stage(run_id,stage,status,evidence,tools,seconds)"
                " VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,stage) DO UPDATE SET"
                " status=excluded.status, evidence=excluded.evidence,"
                " tools=excluded.tools, seconds=excluded.seconds",
                (run_id, kind, st, ev, json.dumps(tl), secs))
            if st != "ran":
                counts[kind] = None          # not run: never render as 0
                continue
            if kind in ("url", "url_shape") and os.environ.get("SCOUT_DB_URLS") == "0":
                counts[kind] = None
                statuses[kind] = ("skipped_toggle", "SCOUT_DB_URLS=0")
                continue
            if kind == "url_shape":
                counts[kind] = ingest_url_shapes(ing, run_dir)
            elif kind == "finding":
                counts[kind] = ingest_findings(ing, run_dir)
            elif kind == "takeover":
                counts[kind] = ingest_takeovers(ing, run_dir)
            elif kind == "port":
                counts[kind] = ingest_ports(ing, run_dir, port_map)
            elif kind == "js_secret":
                counts[kind] = ingest_js_secrets(ing, run_dir)
            else:
                counts[kind] = ingest_simple(ing, run_dir, kind)
            if kind == "url":
                ingest_gf_tags(ing, run_dir)
            if kind == "live_host":
                ingest_http_meta(ing, run_dir)
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise

    if args.diff_out:
        write_diff(con, run_id, run_dir, args.diff_out, counts, statuses)
    print("ingested run %s (%s) from %s" % (run_id, status, run_dir))
    return 0


def write_diff(con, run_id, run_dir, out_dir, counts, statuses):
    """Snapshot of the first-seen query into the run dir, so cmd/report can
    show deltas without ever touching the database."""
    os.makedirs(out_dir, exist_ok=True)
    prior = {}
    for row in con.execute(
            "SELECT t.root, COUNT(DISTINCT rt.run_id)-1 FROM run_target rt "
            "JOIN target t ON t.id=rt.target_id WHERE rt.target_id IN "
            "(SELECT target_id FROM run_target WHERE run_id=?) GROUP BY t.root",
            (run_id,)):
        prior[row[0]] = max(0, row[1])
    prior_runs = max(prior.values()) if prior else 0

    summary, notrun = [], []
    for kind in ("subdomain", "resolved", "live_host", "url", "url_shape",
                 "param", "js_file", "js_endpoint", "js_secret",
                 "finding", "takeover", "port"):
        st, ev = statuses.get(kind, ("unknown", ""))
        total = counts.get(kind)
        if total is None:
            summary.append((kind, st, "-", "-", prior_runs))
            notrun.append("%s\t%s\t%s" % (kind, st, ev))
            continue
        rows = [r[0] for r in con.execute(
            "SELECT value FROM asset WHERE first_run_id=? AND kind=? "
            "ORDER BY value", (run_id, kind))]
        fname = DIFF_FILES.get(kind)
        if fname:
            with open(os.path.join(out_dir, fname), "w") as fh:
                for v in rows:
                    fh.write(v + "\n")
        if kind == "finding":
            with open(os.path.join(out_dir, "new_findings.tsv"), "w") as fh:
                for r in con.execute(
                        "SELECT fd.severity, fd.name, fd.matched_at FROM asset a "
                        "JOIN finding_detail fd ON fd.asset_id=a.id "
                        "WHERE a.first_run_id=? AND a.kind='finding'", (run_id,)):
                    fh.write("\t".join(str(x or "") for x in r) + "\n")
        summary.append((kind, st, total, len(rows), prior_runs))

    with open(os.path.join(out_dir, "summary.tsv"), "w") as fh:
        for k, st, total, new, pr in summary:
            fh.write("%s\t%s\t%s\t%s\t%s\n" % (k, st, total, new, pr))
    with open(os.path.join(out_dir, "not_run.txt"), "w") as fh:
        for l in notrun:
            fh.write(l + "\n")


# --------------------------------------------------------------------------
# backfill / stats / new / verify / prune
# --------------------------------------------------------------------------
def looks_like_run(d):
    return any(os.path.exists(os.path.join(d, n)) for n in
               ("scope_roots.txt", "final_subdomains.out", ".telemetry"))


def cmd_backfill(args):
    dirs = list(args.dir or [])
    if args.all:
        ws = args.workspace or os.path.dirname(os.path.abspath(args.db))
        for name in sorted(os.listdir(ws)) if os.path.isdir(ws) else []:
            p = os.path.join(ws, name)
            if os.path.isdir(p) and looks_like_run(p):
                dirs.append(p)
    if not dirs:
        print("no run directories found to backfill")
        return 0

    # Ascending start time: first_run_id then lands correctly even before the
    # MIN() clause has to rescue it.
    def started_of(d):
        m = load_manifest(d) or synth_manifest(d)
        return int(m.get("started_at") or 0)
    dirs = sorted(set(os.path.realpath(d) for d in dirs), key=started_of)

    con = connect_ro(args.db) if os.path.exists(args.db) else None
    before = {}
    if con:
        for r in con.execute("SELECT id, first_run_id FROM asset"):
            before[r[0]] = r[1]
        con.close()

    for d in dirs:
        if args.dry_run:
            print("would ingest %s" % d)
            continue
        ns = argparse.Namespace(db=args.db, run_dir=d, port_map=None,
                                diff_out=None, allow_partial=True, legacy=True)
        try:
            cmd_ingest(ns)
        except Exception as e:
            sys.stderr.write("scoutdb: failed on %s: %s\n" % (d, e))

    if before and not args.dry_run:
        con = connect_ro(args.db)
        moved = sum(1 for r in con.execute("SELECT id, first_run_id FROM asset")
                    if r[0] in before and before[r[0]] != r[1])
        con.close()
        if moved:
            print("NOTE: %d first-seen dates moved to earlier runs. Any "
                  "diff/new_*.txt snapshot written before now may be stale; "
                  "the database itself is correct." % moved)
    return 0


def cmd_stats(args):
    con = connect_ro(args.db)
    print("database: %s" % args.db)
    for label, q in (
            ("targets", "SELECT COUNT(*) FROM target WHERE is_unscoped=0"),
            ("runs", "SELECT COUNT(*) FROM run"),
            ("assets", "SELECT COUNT(*) FROM asset")):
        print("  %-9s %s" % (label, con.execute(q).fetchone()[0]))
    print("  by kind:")
    for r in con.execute("SELECT kind, COUNT(*) c FROM asset GROUP BY kind "
                         "ORDER BY c DESC"):
        print("    %-14s %d" % (r[0], r[1]))
    print("  recent runs:")
    for r in con.execute(
            "SELECT run_uid, datetime(started_at,'unixepoch'), status, dir "
            "FROM run ORDER BY started_at DESC LIMIT 10"):
        print("    %s  %s  %-11s %s" % (r[0][:12], r[1], r[2], r[3]))
    con.close()
    return 0


def cmd_new(args):
    con = connect_ro(args.db)
    row = con.execute("SELECT id FROM run WHERE run_uid LIKE ?",
                      (args.run + "%",)).fetchone()
    if not row:
        die("no run matching '%s'" % args.run)
    for r in con.execute(
            "SELECT kind, COUNT(*) FROM asset WHERE first_run_id=? "
            "GROUP BY kind ORDER BY kind", (row[0],)):
        print("%-14s %d" % (r[0], r[1]))
    con.close()
    return 0


def cmd_verify(args):
    con = connect_ro(args.db)
    print("schema version: %s" % (con.execute(
        "SELECT value FROM schema_meta WHERE key='version'").fetchone() or ["?"])[0])
    print("integrity: %s" % con.execute("PRAGMA integrity_check").fetchone()[0])
    con.close()
    return 0


def cmd_prune(args):
    """Drop per-run membership for old runs while preserving every asset and
    its first-seen date -- history stays queryable, volume does not grow."""
    con = connect_rw(args.db)
    keep = max(1, args.keep)
    old = [r[0] for r in con.execute(
        "SELECT id FROM run ORDER BY started_at DESC LIMIT -1 OFFSET ?", (keep,))]
    if not old:
        print("nothing to prune (keeping %d runs)" % keep)
        return 0
    con.execute("BEGIN IMMEDIATE")
    for rid in old:
        con.execute("DELETE FROM run_asset WHERE run_id=?", (rid,))
        con.execute("DELETE FROM http_meta WHERE run_id=?", (rid,))
        con.execute("DELETE FROM asset_tag WHERE run_id=?", (rid,))
    con.execute("COMMIT")
    print("pruned per-run rows for %d run(s); assets and first-seen dates kept"
          % len(old))
    return 0


def main():
    ap = argparse.ArgumentParser(prog="scoutdb")
    ap.add_argument("--db", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--port-map")
    p.add_argument("--diff-out")
    p.add_argument("--allow-partial", action="store_true")
    p.add_argument("--legacy", action="store_true")
    p.set_defaults(fn=cmd_ingest)

    p = sub.add_parser("backfill")
    p.add_argument("--all", action="store_true")
    p.add_argument("--dir", action="append")
    p.add_argument("--workspace")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_backfill)

    for name, fn in (("stats", cmd_stats), ("verify", cmd_verify)):
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)

    p = sub.add_parser("new")
    p.add_argument("--run", required=True)
    p.set_defaults(fn=cmd_new)

    p = sub.add_parser("prune")
    p.add_argument("--keep", type=int, default=10)
    p.set_defaults(fn=cmd_prune)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
