#!/usr/bin/env python3
"""Read-only web UI over the Scout result database.

python3 stdlib only -- no pip, no venv. The installer is apt/go/pipx and a
dashboard is not worth adding a dependency channel for.

SECURITY NOTES, all of which matter because this process runs as root on the
operator's own machine and renders attacker-controlled strings:

  * Binds 127.0.0.1 only. There is no authentication, so exposing this exposes
    every host, URL and finding you have ever collected. Any other bind address
    requires SCOUT_SERVE_UNSAFE=1 and is refused otherwise.
  * EVERY value rendered into HTML goes through E(). httpx page titles, archived
    URLs and nuclei matched-at values are attacker-controlled -- a stored XSS
    into your own recon dashboard is a realistic outcome, not a theoretical one.
    A fixture in the test suite carries <script>alert(1)</script> as a title.
  * EVERY filter is a bound parameter, and sort columns come from a hardcoded
    whitelist -- never from the query string.
  * The database is opened read-only (mode=ro + PRAGMA query_only). No route
    issues DML.
  * No static files are served from the run directories. That would be a
    path-traversal surface for a root-owned server.
"""

import argparse
import html
import json
import os
import sqlite3
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KINDS = ["subdomain", "resolved", "live_host", "url", "url_shape", "param",
         "js_file", "js_endpoint", "js_secret", "finding", "takeover", "port"]
PER_CHOICES = (50, 100, 250, 500)
SORTS = {                       # whitelist: label -> SQL fragment
    "value": "a.value ASC",
    "newest": "a.first_seen_at DESC, a.value ASC",
    "oldest": "a.first_seen_at ASC, a.value ASC",
    "seen": "a.times_seen DESC, a.value ASC",
}
COUNT_CAP = 100000              # don't stall a page counting a huge URL corpus

DB_PATH = None


def E(v):
    """The only way a value reaches the page."""
    return html.escape("" if v is None else str(v), quote=True)


def db():
    con = sqlite3.connect("file:%s?mode=ro" % DB_PATH, uri=True, timeout=20.0)
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA query_only=1")
    con.row_factory = sqlite3.Row
    return con


CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--fg:#1c2024;--muted:#6b7480;--line:#e3e6ea;
--accent:#1f6feb;--new:#1a7f37;--crit:#b3261e;--high:#d9480f;--med:#b8860b;--low:#57606a}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--fg:#e6edf3;
--muted:#8b949e;--line:#30363d;--accent:#58a6ff;--new:#3fb950;--crit:#f85149;
--high:#ff8700;--med:#d29922;--low:#8b949e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1500px;margin:0 auto;padding:16px}
nav{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px;
position:sticky;top:0;z-index:5;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
nav .brand{font-weight:700;letter-spacing:.3px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:14px 16px;margin:0 0 16px}
h1{font-size:19px;margin:0 0 12px}h2{font-size:15px;margin:0 0 10px}
h3{font-size:13px;margin:14px 0 6px;color:var(--muted);text-transform:uppercase;
letter-spacing:.5px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.4px}
tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
word-break:break-all}
.muted{color:var(--muted)}
.tablewrap{overflow-x:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:10px 14px;min-width:120px}
.card .n{font-size:20px;font-weight:700}.card .l{color:var(--muted);font-size:12px}
.new{color:var(--new);font-weight:700}
.pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11.5px;
border:1px solid var(--line)}
.sev-critical{color:var(--crit);font-weight:700}.sev-high{color:var(--high);font-weight:700}
.sev-medium{color:var(--med)}.sev-low,.sev-info,.sev-unknown{color:var(--low)}
form.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
input,select,button{background:var(--bg);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:5px 8px;font:inherit;font-size:13px}
button{cursor:pointer}
.pager{display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap}
.notrun{color:var(--muted);font-style:italic}
"""


def page(title, body, active=""):
    nav = ['<nav><span class="brand">scout</span>']
    for href, label in (("/", "overview"), ("/targets", "targets"),
                        ("/runs", "runs"), ("/assets", "assets"),
                        ("/findings", "findings"), ("/new", "new")):
        mark = ' style="font-weight:700"' if active == label else ""
        nav.append('<a href="%s"%s>%s</a>' % (href, mark, label))
    nav.append('<span class="muted" style="margin-left:auto">%s</span></nav>'
               % E(DB_PATH))
    return ("<!doctype html><html><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s · scout</title><style>%s</style></head><body>%s"
            "<div class='wrap'>%s</div></body></html>"
            % (E(title), CSS, "".join(nav), body))


def qint(q, key, default, lo=None, hi=None):
    try:
        v = int(q.get(key, [default])[0])
    except (ValueError, TypeError):
        return default
    if lo is not None and v < lo:
        return lo
    if hi is not None and v > hi:
        return hi
    return v


def qstr(q, key, default=""):
    return (q.get(key, [default])[0] or "").strip()


# --------------------------------------------------------------------------
# Query building -- every filter bound, sort whitelisted
# --------------------------------------------------------------------------
def asset_query(q, extra_join="", extra_where=None):
    where, params = ["1=1"], []
    kind = qstr(q, "kind")
    if kind in KINDS:
        where.append("a.kind = ?")
        params.append(kind)
    tgt = qstr(q, "target")
    if tgt.isdigit():
        where.append("a.target_id = ?")
        params.append(int(tgt))
    elif qstr(q, "scoped", "1") == "1":
        where.append("t.is_unscoped = 0")
    term = qstr(q, "q")
    if term:
        where.append("a.value LIKE ? ESCAPE '\\'")
        params.append("%" + term.replace("\\", "\\\\").replace("%", "\\%")
                      .replace("_", "\\_") + "%")
    run = qstr(q, "run")
    if run:
        where.append("a.first_run_id IN (SELECT id FROM run WHERE run_uid LIKE ?)")
        params.append(run + "%")
    if qstr(q, "new") == "1" and not run:
        where.append("a.first_run_id = (SELECT id FROM run ORDER BY started_at "
                     "DESC LIMIT 1)")
    tag = qstr(q, "tag")
    if tag:
        where.append("EXISTS (SELECT 1 FROM asset_tag g WHERE g.asset_id=a.id "
                     "AND g.tag = ?)")
        params.append(tag)
    if extra_where:
        where.append(extra_where)
    sql_from = ("FROM asset a JOIN target t ON t.id = a.target_id %s WHERE %s"
                % (extra_join, " AND ".join(where)))
    return sql_from, params


def render_rows(rows):
    out = []
    for r in rows:
        first = "yes" if r["is_new"] else ""
        out.append(
            "<tr><td class='mono'>%s</td><td>%s</td><td class='mono'>%s</td>"
            "<td class='mono'>%s</td><td>%s</td><td class='%s'>%s</td></tr>"
            % (E(r["value"]), E(r["kind"]), E(r["root"] or "(unscoped)"),
               E(r["times_seen"]),
               E(r["first_seen"]), "new" if first else "muted",
               "NEW" if first else ""))
    return "".join(out)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
def route_index(q):
    con = db()
    tg = con.execute("SELECT COUNT(*) FROM target WHERE is_unscoped=0").fetchone()[0]
    rn = con.execute("SELECT COUNT(*) FROM run").fetchone()[0]
    ast = con.execute("SELECT COUNT(*) FROM asset").fetchone()[0]
    cards = ['<div class="cards">',
             '<div class="card"><div class="n">%d</div><div class="l">targets</div></div>' % tg,
             '<div class="card"><div class="n">%d</div><div class="l">runs</div></div>' % rn,
             '<div class="card"><div class="n">%d</div><div class="l">assets</div></div>' % ast]
    last = con.execute("SELECT id, run_uid, started_at FROM run ORDER BY "
                       "started_at DESC LIMIT 1").fetchone()
    if last:
        n = con.execute("SELECT COUNT(*) FROM asset WHERE first_run_id=?",
                        (last["id"],)).fetchone()[0]
        cards.append('<div class="card"><div class="n new">%d</div>'
                     '<div class="l">new in last run</div></div>' % n)
    cards.append("</div>")

    body = ["<h1>Overview</h1>", "".join(cards)]
    body.append('<section class="panel"><h2>Assets by kind</h2><div class="tablewrap"><table>'
                '<tr><th>Kind</th><th>Total</th><th>New in last run</th></tr>')
    for r in con.execute("SELECT kind, COUNT(*) c FROM asset GROUP BY kind "
                         "ORDER BY c DESC"):
        nn = 0
        if last:
            nn = con.execute("SELECT COUNT(*) FROM asset WHERE kind=? AND "
                             "first_run_id=?", (r["kind"], last["id"])).fetchone()[0]
        body.append("<tr><td><a href='/assets?kind=%s'>%s</a></td><td class='mono'>%d</td>"
                    "<td class='mono %s'>%s</td></tr>"
                    % (E(r["kind"]), E(r["kind"]), r["c"],
                       "new" if nn else "muted", ("+%d" % nn) if nn else "0"))
    body.append("</table></div></section>")

    body.append('<section class="panel"><h2>Recent runs</h2><div class="tablewrap"><table>'
                '<tr><th>Run</th><th>Started</th><th>Status</th><th>New</th><th>Directory</th></tr>')
    for r in con.execute(
            "SELECT id,run_uid,datetime(started_at,'unixepoch') s,status,dir,"
            "started_at_estimated e FROM run ORDER BY started_at DESC LIMIT 15"):
        nn = con.execute("SELECT COUNT(*) FROM asset WHERE first_run_id=?",
                         (r["id"],)).fetchone()[0]
        body.append("<tr><td class='mono'><a href='/run/%s'>%s</a></td><td>%s%s</td>"
                    "<td>%s</td><td class='mono %s'>%s</td><td class='mono muted'>%s</td></tr>"
                    % (E(r["run_uid"]), E(r["run_uid"][:12]), E(r["s"]),
                       " <span class='muted'>(est)</span>" if r["e"] else "",
                       E(r["status"]), "new" if nn else "muted",
                       ("+%d" % nn) if nn else "0", E(r["dir"])))
    body.append("</table></div></section>")
    con.close()
    return page("Overview", "".join(body), "overview")


def route_targets(q):
    con = db()
    body = ["<h1>Targets</h1>", '<section class="panel"><div class="tablewrap"><table>'
            "<tr><th>Root</th><th>Runs</th><th>Assets</th><th>First seen</th>"
            "<th>Last seen</th></tr>"]
    for r in con.execute(
            "SELECT t.id,t.root,t.is_unscoped,"
            " datetime(t.first_seen_at,'unixepoch') f,"
            " datetime(t.last_seen_at,'unixepoch') l,"
            " (SELECT COUNT(*) FROM run_target rt WHERE rt.target_id=t.id) runs,"
            " (SELECT COUNT(*) FROM asset a WHERE a.target_id=t.id) assets"
            " FROM target t ORDER BY t.is_unscoped, t.root"):
        name = r["root"] or "(unscoped / third-party)"
        body.append("<tr><td><a href='/assets?target=%d'>%s</a>%s</td>"
                    "<td class='mono'>%d</td><td class='mono'>%d</td>"
                    "<td class='muted'>%s</td><td class='muted'>%s</td></tr>"
                    % (r["id"], E(name),
                       " <span class='pill'>unscoped</span>" if r["is_unscoped"] else "",
                       r["runs"], r["assets"], E(r["f"]), E(r["l"])))
    body.append("</table></div></section>")
    con.close()
    return page("Targets", "".join(body), "targets")


def route_runs(q):
    con = db()
    body = ["<h1>Runs</h1>", '<section class="panel"><div class="tablewrap"><table>'
            "<tr><th>Run</th><th>Started</th><th>Status</th><th>Duration</th>"
            "<th>New</th><th>Directory</th></tr>"]
    for r in con.execute(
            "SELECT id,run_uid,datetime(started_at,'unixepoch') s,status,dir,"
            "total_seconds,started_at_estimated e FROM run ORDER BY started_at DESC"):
        nn = con.execute("SELECT COUNT(*) FROM asset WHERE first_run_id=?",
                         (r["id"],)).fetchone()[0]
        body.append("<tr><td class='mono'><a href='/run/%s'>%s</a></td><td>%s%s</td>"
                    "<td>%s</td><td class='mono'>%s</td><td class='mono %s'>%s</td>"
                    "<td class='mono muted'>%s</td></tr>"
                    % (E(r["run_uid"]), E(r["run_uid"][:12]), E(r["s"]),
                       " <span class='muted'>(est)</span>" if r["e"] else "",
                       E(r["status"]),
                       E("%ss" % r["total_seconds"] if r["total_seconds"] else "—"),
                       "new" if nn else "muted", ("+%d" % nn) if nn else "0",
                       E(r["dir"])))
    body.append("</table></div></section>")
    con.close()
    return page("Runs", "".join(body), "runs")


def route_run(q, uid):
    con = db()
    r = con.execute("SELECT * FROM run WHERE run_uid = ?", (uid,)).fetchone()
    if not r:
        con.close()
        return None
    body = ["<h1>Run %s</h1>" % E(r["run_uid"][:12])]
    body.append('<section class="panel"><div class="tablewrap"><table>')
    for label, val in (("run uid", r["run_uid"]), ("directory", r["dir"]),
                       ("status", r["status"]),
                       ("started", "%s%s" % (
                           con.execute("SELECT datetime(?,'unixepoch')",
                                       (r["started_at"],)).fetchone()[0],
                           " (estimated)" if r["started_at_estimated"] else "")),
                       ("duration", "%ss" % r["total_seconds"]
                        if r["total_seconds"] else "—"),
                       ("safe mode", r["safe_mode"]),
                       ("user agent", r["user_agent"]),
                       ("argv", " ".join(json.loads(r["argv"] or "[]")))):
        body.append("<tr><th style='width:140px'>%s</th><td class='mono'>%s</td></tr>"
                    % (E(label), E(val)))
    body.append("</table></div></section>")

    # The stage table is the honest part: it distinguishes "found nothing" from
    # "never ran", which a bare count cannot.
    body.append('<section class="panel"><h2>Stages</h2>'
                '<p class="muted">A stage that did not run is never reported as zero.</p>'
                '<div class="tablewrap"><table>'
                "<tr><th>Asset type</th><th>Status</th><th>Recorded</th>"
                "<th>New</th><th>Evidence</th></tr>")
    for st in con.execute("SELECT * FROM run_stage WHERE run_id=? ORDER BY stage",
                          (r["id"],)):
        ran = st["status"] == "ran"
        total = con.execute("SELECT COUNT(*) FROM run_asset ra JOIN asset a ON "
                            "a.id=ra.asset_id WHERE ra.run_id=? AND a.kind=?",
                            (r["id"], st["stage"])).fetchone()[0] if ran else None
        new = con.execute("SELECT COUNT(*) FROM asset WHERE first_run_id=? AND "
                          "kind=?", (r["id"], st["stage"])).fetchone()[0] if ran else None
        body.append("<tr><td>%s</td><td>%s</td><td class='mono'>%s</td>"
                    "<td class='mono %s'>%s</td><td class='muted'>%s</td></tr>"
                    % (E(st["stage"]),
                       ("ran" if ran else
                        "<span class='notrun'>%s</span>" % E(st["status"])),
                       E(total if ran else "—"),
                       "new" if (new or 0) else "muted",
                       E(("+%d" % new) if ran and new else ("0" if ran else "—")),
                       E(st["evidence"])))
    body.append("</table></div></section>")
    body.append("<p><a href='/assets?run=%s'>All assets first seen in this run</a></p>"
                % E(r["run_uid"]))
    con.close()
    return page("Run %s" % r["run_uid"][:12], "".join(body), "runs")


def filters_form(q, con, show_kind=True):
    out = ["<form class='filters' method='get'>"]
    if show_kind:
        out.append("<select name='kind'><option value=''>all kinds</option>")
        for k in KINDS:
            sel = " selected" if qstr(q, "kind") == k else ""
            out.append("<option%s>%s</option>" % (sel, E(k)))
        out.append("</select>")
    out.append("<select name='target'><option value=''>all targets</option>")
    for t in con.execute("SELECT id, root, is_unscoped FROM target ORDER BY "
                         "is_unscoped, root"):
        sel = " selected" if qstr(q, "target") == str(t["id"]) else ""
        out.append("<option value='%d'%s>%s</option>"
                   % (t["id"], sel, E(t["root"] or "(unscoped)")))
    out.append("</select>")
    out.append("<input name='q' placeholder='contains…' value='%s'>" % E(qstr(q, "q")))
    out.append("<select name='sort'>")
    for s in SORTS:
        sel = " selected" if qstr(q, "sort", "value") == s else ""
        out.append("<option%s>%s</option>" % (sel, E(s)))
    out.append("</select>")
    out.append("<select name='per'>")
    for p in PER_CHOICES:
        sel = " selected" if qint(q, "per", 100) == p else ""
        out.append("<option%s>%d</option>" % (sel, p))
    out.append("</select>")
    nk = " checked" if qstr(q, "new") == "1" else ""
    out.append("<label><input type='checkbox' name='new' value='1'%s> new only</label>" % nk)
    sc = " checked" if qstr(q, "scoped", "1") == "1" else ""
    out.append("<label><input type='checkbox' name='scoped' value='1'%s> in-scope only</label>" % sc)
    out.append("<button>filter</button></form>")
    return "".join(out)


def route_assets(q):
    con = db()
    per = qint(q, "per", 100)
    per = per if per in PER_CHOICES else 100
    page_n = qint(q, "page", 1, lo=1)
    order = SORTS.get(qstr(q, "sort", "value"), SORTS["value"])
    sql_from, params = asset_query(q)

    total = con.execute("SELECT COUNT(*) FROM (SELECT a.id %s LIMIT %d)"
                        % (sql_from, COUNT_CAP), params).fetchone()[0]
    rows = con.execute(
        "SELECT a.value, a.kind, a.times_seen, t.root, a.first_run_id,"
        " datetime(a.first_seen_at,'unixepoch') first_seen,"
        " (a.first_run_id = (SELECT id FROM run ORDER BY started_at DESC LIMIT 1))"
        " AS is_new %s ORDER BY %s LIMIT ? OFFSET ?"
        % (sql_from, order), params + [per, (page_n - 1) * per]).fetchall()

    body = ["<h1>Assets</h1>", filters_form(q, con)]
    body.append('<section class="panel"><div class="tablewrap"><table>'
                "<tr><th>Value</th><th>Kind</th><th>Target</th><th>Seen</th>"
                "<th>First seen</th><th></th></tr>")
    body.append(render_rows(rows) or
                "<tr><td colspan=6 class='muted'>nothing matches</td></tr>")
    body.append("</table></div>")

    qq = {k: v[0] for k, v in q.items() if k != "page"}
    def link(n, label):
        qq2 = dict(qq, page=str(n))
        return "<a href='/assets?%s'>%s</a>" % (urllib.parse.urlencode(qq2), label)
    body.append("<div class='pager'>")
    if page_n > 1:
        body.append(link(page_n - 1, "← prev"))
    body.append("<span class='muted'>page %d · %s%d matching</span>"
                % (page_n, "≥" if total >= COUNT_CAP else "", total))
    if page_n * per < total:
        body.append(link(page_n + 1, "next →"))
    body.append(" · <a href='/export.csv?%s'>export CSV</a>"
                % urllib.parse.urlencode(qq))
    body.append("</div></section>")
    con.close()
    return page("Assets", "".join(body), "assets")


def route_findings(q):
    con = db()
    per = qint(q, "per", 100)
    per = per if per in PER_CHOICES else 100
    page_n = qint(q, "page", 1, lo=1)
    where, params = ["a.kind IN ('finding','takeover')"], []
    sev = qstr(q, "severity")
    if sev:
        where.append("fd.severity = ?")
        params.append(sev)
    src = qstr(q, "source")
    if src:
        where.append("fd.source = ?")
        params.append(src)
    if qstr(q, "new") == "1":
        where.append("a.first_run_id = (SELECT id FROM run ORDER BY started_at "
                     "DESC LIMIT 1)")
    term = qstr(q, "q")
    if term:
        where.append("(fd.name LIKE ? OR fd.matched_at LIKE ?)")
        params += ["%" + term + "%"] * 2
    sql_from = ("FROM asset a JOIN finding_detail fd ON fd.asset_id=a.id "
                "JOIN target t ON t.id=a.target_id WHERE " + " AND ".join(where))
    total = con.execute("SELECT COUNT(*) " + sql_from, params).fetchone()[0]
    rows = con.execute(
        "SELECT fd.severity,fd.name,fd.source,fd.matched_at,t.root,"
        " datetime(a.first_seen_at,'unixepoch') fs,"
        " (a.first_run_id=(SELECT id FROM run ORDER BY started_at DESC LIMIT 1)) is_new "
        + sql_from +
        " ORDER BY CASE fd.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, fd.name"
        " LIMIT ? OFFSET ?", params + [per, (page_n - 1) * per]).fetchall()

    body = ["<h1>Findings</h1>", "<form class='filters' method='get'>",
            "<select name='severity'><option value=''>all severities</option>"]
    for s in ("critical", "high", "medium", "low", "info", "unknown"):
        sel = " selected" if sev == s else ""
        body.append("<option%s>%s</option>" % (sel, s))
    body.append("</select><input name='q' placeholder='name or location…' value='%s'>"
                % E(term))
    nk = " checked" if qstr(q, "new") == "1" else ""
    body.append("<label><input type='checkbox' name='new' value='1'%s> new only</label>" % nk)
    body.append("<button>filter</button></form>")
    body.append('<section class="panel"><div class="tablewrap"><table>'
                "<tr><th>Severity</th><th>Name</th><th>Source</th><th>Location</th>"
                "<th>Target</th><th>First seen</th><th></th></tr>")
    for r in rows:
        body.append("<tr><td class='sev-%s'>%s</td><td>%s</td><td class='muted'>%s</td>"
                    "<td class='mono'>%s</td><td class='mono'>%s</td>"
                    "<td class='muted'>%s</td><td class='%s'>%s</td></tr>"
                    % (E(r["severity"] or "unknown"), E(r["severity"] or "unknown"),
                       E(r["name"]), E(r["source"]), E(r["matched_at"]),
                       E(r["root"] or "(unscoped)"), E(r["fs"]),
                       "new" if r["is_new"] else "", "NEW" if r["is_new"] else ""))
    if not rows:
        body.append("<tr><td colspan=7 class='muted'>no findings recorded</td></tr>")
    body.append("</table></div><div class='pager'><span class='muted'>%d total</span>"
                "</div></section>" % total)
    con.close()
    return page("Findings", "".join(body), "findings")


def route_new(q):
    con = db()
    last = con.execute("SELECT id, run_uid, datetime(started_at,'unixepoch') s "
                       "FROM run ORDER BY started_at DESC LIMIT 1").fetchone()
    body = ["<h1>New since first seen</h1>"]
    if not last:
        body.append("<p class='muted'>No runs recorded yet.</p>")
    else:
        body.append("<p class='muted'>Latest run <span class='mono'>%s</span> "
                    "(%s). An asset counts as new only if it has never been "
                    "recorded for its target in any earlier run.</p>"
                    % (E(last["run_uid"][:12]), E(last["s"])))
        body.append('<section class="panel"><div class="tablewrap"><table>'
                    "<tr><th>Kind</th><th>New</th><th></th></tr>")
        for r in con.execute("SELECT kind, COUNT(*) c FROM asset WHERE "
                             "first_run_id=? GROUP BY kind ORDER BY c DESC",
                             (last["id"],)):
            body.append("<tr><td>%s</td><td class='mono new'>+%d</td>"
                        "<td><a href='/assets?kind=%s&run=%s'>view</a></td></tr>"
                        % (E(r["kind"]), r["c"], E(r["kind"]), E(last["run_uid"])))
        body.append("</table></div></section>")
    con.close()
    return page("New", "".join(body), "new")


def route_api_assets(q):
    con = db()
    per = qint(q, "per", 100, hi=1000)
    page_n = qint(q, "page", 1, lo=1)
    order = SORTS.get(qstr(q, "sort", "value"), SORTS["value"])
    sql_from, params = asset_query(q)
    total = con.execute("SELECT COUNT(*) FROM (SELECT a.id %s LIMIT %d)"
                        % (sql_from, COUNT_CAP), params).fetchone()[0]
    rows = con.execute("SELECT a.value,a.kind,a.times_seen,t.root,"
                       " a.first_seen_at,a.last_seen_at %s ORDER BY %s "
                       "LIMIT ? OFFSET ?" % (sql_from, order),
                       params + [per, (page_n - 1) * per]).fetchall()
    con.close()
    return json.dumps({"total": total, "page": page_n, "per": per,
                       "items": [dict(r) for r in rows]}, indent=1)


def route_export_csv(q):
    con = db()
    sql_from, params = asset_query(q)
    rows = con.execute("SELECT a.value,a.kind,t.root,a.times_seen,"
                       " datetime(a.first_seen_at,'unixepoch') first_seen %s "
                       "ORDER BY a.value LIMIT 50000" % sql_from, params)
    out = ["value,kind,target,times_seen,first_seen"]
    for r in rows:
        out.append(",".join('"%s"' % str(x or "").replace('"', '""') for x in r))
    con.close()
    return "\n".join(out) + "\n"


def route_healthz(q):
    try:
        con = db()
        v = con.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()
        n = con.execute("SELECT COUNT(*) FROM run").fetchone()[0]
        con.close()
        return json.dumps({"ok": True, "db": DB_PATH,
                           "schema": (v[0] if v else None), "runs": n})
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})


class Handler(BaseHTTPRequestHandler):
    server_version = "scout"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # No external anything: this page must not be able to phone out.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        p = u.path.rstrip("/") or "/"
        try:
            if p == "/":
                return self._send(route_index(q))
            if p == "/targets":
                return self._send(route_targets(q))
            if p == "/runs":
                return self._send(route_runs(q))
            if p.startswith("/run/"):
                r = route_run(q, urllib.parse.unquote(p[len("/run/"):]))
                if r is None:
                    return self._send(page("Not found", "<h1>No such run</h1>"), code=404)
                return self._send(r)
            if p == "/assets":
                return self._send(route_assets(q))
            if p == "/findings":
                return self._send(route_findings(q))
            if p == "/new":
                return self._send(route_new(q))
            if p == "/api/assets.json":
                return self._send(route_api_assets(q), "application/json")
            if p == "/export.csv":
                return self._send(route_export_csv(q), "text/csv; charset=utf-8")
            if p == "/healthz":
                return self._send(route_healthz(q), "application/json")
            return self._send(page("Not found", "<h1>404</h1>"), code=404)
        except Exception as e:
            sys.stderr.write("error on %s: %s\n" % (self.path, e))
            return self._send(page("Error", "<h1>Error</h1><p class='mono'>%s</p>"
                                   % E(e)), code=500)


def main():
    global DB_PATH
    ap = argparse.ArgumentParser(prog="scout serve")
    ap.add_argument("--db", required=True)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()

    if a.host not in ("127.0.0.1", "localhost", "::1") \
            and os.environ.get("SCOUT_SERVE_UNSAFE") != "1":
        sys.stderr.write(
            "refusing to bind %s: this interface has no authentication and would\n"
            "expose every host, URL and finding in the database. Set\n"
            "SCOUT_SERVE_UNSAFE=1 if you genuinely intend that.\n" % a.host)
        return 2
    if not os.path.exists(a.db):
        sys.stderr.write("no database at %s — run a scan, or: scout db backfill --all\n"
                         % a.db)
        return 1
    DB_PATH = os.path.abspath(a.db)
    try:
        db().close()
    except Exception as e:
        sys.stderr.write("cannot open database read-only: %s\n" % e)
        return 1

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    sys.stderr.write("scout serve: http://%s:%d  (db: %s)\n"
                     % (a.host, a.port, DB_PATH))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nstopped\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
