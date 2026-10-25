"""SQLite-хранилище сканов, дифф между сканами и граф связей."""
import json
import os
import sqlite3
from dataclasses import asdict

from .models import SEVERITY_ORDER, SEVERITY_WEIGHT

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, started REAL NOT NULL,
    finished REAL NOT NULL, probed INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    scan_id INTEGER NOT NULL REFERENCES scans(id), name TEXT NOT NULL, status TEXT, ips TEXT, cnames TEXT,
    issuers TEXT, first_seen TEXT, not_after TEXT, wildcard INTEGER, http_status INTEGER, title TEXT,
    tech TEXT, tls_days INTEGER, score INTEGER, PRIMARY KEY (scan_id, name)
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id), host TEXT, severity TEXT NOT NULL, code TEXT NOT NULL, message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


class Store:
    def __init__(self, path):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def save(self, result) -> int:
        cur = self.db.execute("INSERT INTO scans (domain, started, finished, probed) VALUES (?,?,?,?)",
                              (result.domain, result.started, result.finished, int(result.probed)))
        sid = cur.lastrowid
        for h in result.hosts:
            p = h.probe
            self.db.execute(
                "INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, h.name, h.dns.status, json.dumps(h.dns.ips), json.dumps(h.dns.cnames), json.dumps(h.issuers),
                 h.first_seen, h.last_not_after, int(h.wildcard), p.status if p else None, p.title if p else None,
                 json.dumps(h.tech), p.tls_days_left if p else None, h.score))
            for f in h.findings:
                self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?)", (sid, h.name, f.severity, f.code, f.message))
        for f in result.domain_findings:
            self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?)", (sid, f.host, f.severity, f.code, f.message))
        self.db.commit()
        return sid

    def domains(self):
        rows = self.db.execute("SELECT domain, MAX(id) AS last_scan, COUNT(*) AS scans FROM scans GROUP BY domain ORDER BY domain")
        return [dict(r) for r in rows]

    def scan_ids(self, domain):
        return [r[0] for r in self.db.execute("SELECT id FROM scans WHERE domain = ? ORDER BY id", (domain,))]

    def scan_row(self, scan_id):
        r = self.db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(r) if r else None

    def hosts(self, scan_id):
        out = []
        for r in self.db.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY score DESC, name", (scan_id,)):
            d = dict(r)
            for k in ("ips", "cnames", "issuers", "tech"):
                d[k] = json.loads(d[k] or "[]")
            out.append(d)
        return out

    def findings(self, scan_id, host=None):
        sql, args = "SELECT host, severity, code, message FROM findings WHERE scan_id = ?", [scan_id]
        if host is not None:
            sql, args = sql + " AND host = ?", args + [host]
        rows = [dict(r) for r in self.db.execute(sql, args)]
        rows.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
        return rows

    def summary(self, scan_id):
        hosts = self.hosts(scan_id)
        findings = self.findings(scan_id)
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f["severity"]] += 1
        resolved = sum(1 for h in hosts if h["status"] == "ok")
        tech = {}
        for h in hosts:
            for t in h["tech"]:
                tech[t["name"]] = tech.get(t["name"], 0) + 1
        penalty = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
        return {"hosts": len(hosts), "resolved": resolved, "findings": counts, "grade": grade(penalty, len(hosts)),
                "tech": sorted(tech.items(), key=lambda kv: -kv[1]), "scan": self.scan_row(scan_id)}

    def diff(self, domain):
        ids = self.scan_ids(domain)
        if len(ids) < 2:
            return None
        old, new = ids[-2], ids[-1]
        h_old = {h["name"]: h for h in self.hosts(old)}
        h_new = {h["name"]: h for h in self.hosts(new)}
        f_key = lambda f: (f["host"], f["code"], f["message"])
        f_old = {f_key(f) for f in self.findings(old)}
        changed = [{"host": n, "old": h_old[n]["ips"], "new": h_new[n]["ips"]}
                   for n in h_new if n in h_old and h_old[n]["ips"] != h_new[n]["ips"]]
        return {"old_scan": old, "new_scan": new,
                "new_hosts": sorted(set(h_new) - set(h_old)), "gone_hosts": sorted(set(h_old) - set(h_new)),
                "ip_changes": changed,
                "new_findings": [f for f in self.findings(new) if f_key(f) not in f_old],
                "fixed_findings": [f for f in self.findings(old) if f_key(f) not in {f_key(x) for x in self.findings(new)}]}

    def graph(self, scan_id, limit=40):
        hosts = self.hosts(scan_id)[:limit]
        nodes, edges = {}, []
        for h in hosts:
            nodes[h["name"]] = {"id": h["name"], "kind": "host", "score": h["score"]}
            prev = h["name"]
            for cname in h["cnames"]:
                nodes.setdefault(cname, {"id": cname, "kind": "cname"})
                edges.append([prev, cname])
                prev = cname
            for ip in h["ips"]:
                nodes.setdefault(ip, {"id": ip, "kind": "ip"})
                edges.append([prev, ip])
        return {"nodes": list(nodes.values()), "edges": edges, "truncated": len(self.hosts(scan_id)) > limit}

    def close(self):
        self.db.close()


def grade(penalty, host_count):
    """Оценка A–F: штраф на хост, чтобы большие домены не штрафовались просто за размер."""
    per = penalty / max(host_count, 1)
    for letter, limit in (("A", 1.0), ("B", 3.0), ("C", 6.0), ("D", 10.0)):
        if per <= limit:
            return letter
    return "F"
