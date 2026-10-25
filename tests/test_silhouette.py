import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from silhouette import checks, dashboard, demo, fingerprint, pipeline, sources
from silhouette.dnsclient import resolve_host
from silhouette.models import ProbeResult
from silhouette.probe import Prober, is_public
from silhouette.store import Store, grade

D = "corp.example"


def codes(findings):
    return {f.code for f in findings}


# ---- источники ----

def test_parse_crtsh_filters_and_merges():
    payload = [
        {"name_value": "www.corp.example\n*.corp.example\nevil.other.example\nadmin@corp.example", "issuer_name": "C=US, O=LE, CN=R3",
         "not_before": "2025-01-02T00:00:00", "not_after": "2025-04-02T00:00:00"},
        {"name_value": "WWW.corp.example", "issuer_name": "C=US, O=X, CN=Sectigo", "not_before": "2024-06-01T00:00:00",
         "not_after": "2026-01-01T00:00:00"},
        {"name_value": "bad name.corp.example"},
    ]
    out = sources.parse_crtsh(payload, D)
    assert set(out) == {"www.corp.example", "corp.example"}  # чужой домен, почта и пробелы отсеяны
    www = out["www.corp.example"]
    assert www["issuers"] == ["R3", "Sectigo"] and www["first_seen"] == "2024-06-01T00:00:00"
    assert www["not_after"] == "2026-01-01T00:00:00"
    assert out["corp.example"]["wildcard"] is True


def test_fetch_crtsh_retries_then_fails():
    calls = []

    def failing(req, timeout):
        calls.append(1)
        raise OSError("boom")

    with pytest.raises(RuntimeError, match="crt.sh недоступен"):
        sources.fetch_crtsh(D, urlopen=failing, retries=3, sleep=lambda s: None)
    assert len(calls) == 3


# ---- DNS и проверки ----

def test_resolve_chain_and_dangling():
    dns, _, _ = demo.build(1)
    ok = resolve_host(dns, "app.corp.example")
    assert ok.status == "ok" and ok.cnames == ["lb.corp.example"] and ok.ips
    dangling = resolve_host(dns, "docs.corp.example")
    assert dangling.status == "dangling" and dangling.cnames == ["corp.github.io"]
    assert resolve_host(dns, "nope.corp.example").status == "nxdomain"


def test_takeover_candidate_vs_plain_dangling():
    dns, _, _ = demo.build(1)
    f = checks.check_dns_host("docs.corp.example", resolve_host(dns, "docs.corp.example"))
    assert "takeover-candidate" in codes(f) and f[0].severity == "high"
    dns.zone["x.corp.example"] = {"a": None, "cname": "gone.unknown-vendor.example"}
    dns.zone["gone.unknown-vendor.example"] = "NX"
    f = checks.check_dns_host("x.corp.example", resolve_host(dns, "x.corp.example"))
    assert codes(f) == {"dangling-cname"}


def test_internal_ip_flags_rfc1918_but_not_documentation_ranges():
    from silhouette.models import DNSResult
    assert "internal-ip-in-dns" in codes(checks.check_dns_host("a.corp.example", DNSResult([], ["10.1.2.3"], "ok")))
    assert "internal-ip-in-dns" not in codes(checks.check_dns_host("a.corp.example", DNSResult([], ["203.0.113.9"], "ok")))


def test_service_name_token():
    from silhouette.models import DNSResult
    assert "service-name" in codes(checks.check_dns_host("jenkins.corp.example", DNSResult([], ["203.0.113.9"], "ok")))
    assert "service-name" not in codes(checks.check_dns_host("www.corp.example", DNSResult([], ["203.0.113.9"], "ok")))


@pytest.mark.parametrize("spf,dmarc,expected", [
    (["v=spf1 +all"], ["v=DMARC1; p=reject"], "spf-open"),
    (["v=spf1 include:x ?all"], ["v=DMARC1; p=reject"], "spf-neutral"),
    (["v=spf1 include:x ~all"], ["v=DMARC1; p=reject"], "spf-softfail"),
    (["v=spf1 include:x -all"], ["v=DMARC1; p=none"], "dmarc-monitor"),
    ([], [], "spf-missing"),
    (["v=spf1 -all"], [], "dmarc-missing"),
])
def test_email_checks(spf, dmarc, expected):
    dns = demo.FakeDNS({}, txt={D: spf, "_dmarc." + D: dmarc}, mx=["10 mail.corp.example"])
    assert expected in codes(checks.check_email(D, dns))


def test_email_clean_domain_reports_ok():
    dns = demo.FakeDNS({}, txt={D: ["v=spf1 include:x -all"], "_dmarc." + D: ["v=DMARC1; p=reject"]}, mx=["10 m"])
    assert codes(checks.check_email(D, dns)) == {"mail-ok"}


# ---- отпечатки ----

def test_detect_tech_with_versions():
    tech = fingerprint.detect_tech({"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.3"}, demo.WORDPRESS)
    names = {(t["name"], t["version"]) for t in tech}
    assert ("Apache", "2.4.49") in names and ("PHP", "7.4.3") in names and ("WordPress", "5.8.1") in names


def test_risky_versions():
    tech = fingerprint.detect_tech({"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.3"}, demo.WORDPRESS)
    f = fingerprint.analyze_tech_risks("blog.corp.example", tech)
    assert {x.severity for x in f} == {"high", "medium"}
    ok = fingerprint.detect_tech({"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.3.1"}, "")
    assert fingerprint.analyze_tech_risks("h", ok) == []


def test_header_analysis():
    bad = fingerprint.analyze_headers("h", "https", {"Server": "nginx/1.18.0", "Set-Cookie": "a=1"}, 200)
    assert {"no-hsts", "no-csp", "clickjacking", "version-disclosure", "cookie-no-secure", "cookie-no-httponly"} <= codes(bad)
    good = fingerprint.analyze_headers("h", "https", demo.GOOD, 200)
    assert codes(good) == set()


def test_takeover_body_signature():
    assert codes(fingerprint.check_takeover_body("h", demo.GITHUB_404)) == {"takeover-body"}
    assert fingerprint.check_takeover_body("h", "<html>ok</html>") == []


def test_is_public_skips_internal_and_documentation():
    assert not any(is_public(ip) for ip in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "203.0.113.5", "not-an-ip"))
    assert is_public("8.8.8.8")


def test_real_prober_refuses_internal_only_hosts():
    r = Prober().probe("intranet.corp.example", ["10.0.4.12"])
    assert r.status is None and "нет публичных IP" in r.error


# ---- конвейер ----

def test_passive_scan_never_probes():
    dns, _, source = demo.build(1)

    class Boom:
        def probe(self, *a):
            raise AssertionError("пассивный режим не должен зондировать")

    result = pipeline.run_scan(D, source, dns, prober=None)
    assert not result.probed and all(h.probe is None for h in result.hosts)
    assert "takeover-candidate" in codes([f for h in result.hosts for f in h.findings])


def test_probe_scan_adds_http_findings():
    dns, prober, source = demo.build(1)
    result = pipeline.run_scan(D, source, dns, prober)
    allf = [f for h in result.hosts for f in h.findings]
    assert {"risky-version", "tls-invalid", "tls-expiring", "service-exposed"} <= codes(allf)
    blog = next(h for h in result.hosts if h.name == "blog.corp.example")
    assert blog.score >= 28 and {t["name"] for t in blog.tech} >= {"WordPress", "Apache"}


# ---- хранилище, дифф, оценка ----

def test_store_diff_between_scans():
    store = Store(":memory:")
    demo.seed(store)
    d = store.diff(D)
    assert d["new_hosts"] == ["pay.corp.example", "test-api.corp.example"] and d["gone_hosts"] == ["old.corp.example"]
    assert any(c["host"] == "api.corp.example" for c in d["ip_changes"])
    assert any(f["host"] == "jenkins.corp.example" and f["code"] == "service-exposed" for f in d["new_findings"])
    assert any(f["host"] == "docs.corp.example" and f["code"] == "takeover-candidate" for f in d["fixed_findings"])


def test_diff_needs_two_scans():
    store = Store(":memory:")
    dns, prober, source = demo.build(1)
    store.save(pipeline.run_scan(D, source, dns, prober))
    assert store.diff(D) is None


def test_grade_scales_per_host():
    assert grade(0, 10) == "A" and grade(10, 10) == "A" and grade(20, 10) == "B" and grade(100, 10) == "D" and grade(400, 10) == "F"
    assert grade(100, 100) == "A"  # размер домена сам по себе не штрафуется


def test_graph_links_host_cname_ip():
    store = Store(":memory:")
    ids = demo.seed(store)
    g = store.graph(ids[-1])
    assert ["app.corp.example", "lb.corp.example"] in g["edges"]
    assert any(e[0] == "lb.corp.example" for e in g["edges"])
    kinds = {n["kind"] for n in g["nodes"]}
    assert kinds == {"host", "cname", "ip"}


# ---- дашборд ----

def test_dashboard_api(tmp_path):
    db = str(tmp_path / "d.db")
    store = Store(db)
    demo.seed(store)
    store.close()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(db))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    get = lambda p: urllib.request.urlopen(base + p).read()
    try:
        assert b"SILHOUETTE" in get("/")
        assert json.loads(get("/api/domains"))[0]["domain"] == D
        sm = json.loads(get(f"/api/summary/{D}"))
        assert sm["hosts"] == 29 and sm["findings"]["high"] >= 4
        assert json.loads(get(f"/api/host/{D}/docs.{D}"))["findings"]
        assert len(json.loads(get(f"/api/graph/{D}"))["nodes"]) > 10
        for bad in ("/api/host/corp.example/nope.corp.example", "/api/summary/unknown.example", "/api/summary/..%2Fetc",
                    "/api/bogus/corp.example"):
            with pytest.raises(urllib.error.HTTPError) as e:
                get(bad)
            assert e.value.code == 404
    finally:
        httpd.shutdown()


def test_attacker_controlled_strings_do_not_break_storage():
    store = Store(":memory:")
    dns, prober, source = demo.build(1)
    prober.pages["www.corp.example"] = ProbeResult(scheme="https", status=200, headers={"server": "<script>alert(1)</script>/1.0"},
                                                   body="<title><img src=x onerror=alert(1)></title>", title="<img src=x onerror=alert(1)>")
    sid = store.save(pipeline.run_scan(D, source, dns, prober))
    host = next(h for h in store.hosts(sid) if h["name"] == "www.corp.example")
    assert "<img" in host["title"]  # хранится как текст; экранирование на стороне страницы через textContent
