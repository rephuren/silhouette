import io
import json
import urllib.error

import pytest

from silhouette import pipeline, shodan
from silhouette.models import DNSResult, HostRecord
from silhouette.shodan import Shodan, ShodanError


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(table, calls=None):
    def opener(req, timeout=None):
        if calls is not None:
            calls.append(req.full_url)
        ip = req.full_url.split("/host/")[1].split("?")[0]
        entry = table.get(ip)
        if isinstance(entry, int):
            raise urllib.error.HTTPError(req.full_url, entry, "x", {}, None)
        if entry is None:
            raise urllib.error.HTTPError(req.full_url, 404, "x", {}, None)
        return FakeResp(json.dumps(entry).encode())
    return opener


def client(table, calls=None):
    return Shodan("KEY123", interval=0, opener=opener_for(table, calls), sleep=lambda s: None)


def rec(*ips):
    return HostRecord(name="vpn.corp.test", dns=DNSResult([], list(ips), "ok"))


def test_risky_ports_and_cves_become_findings():
    r = rec("8.8.4.4")
    shodan.enrich(r, client({"8.8.4.4": {"ports": [22, 3389, 443], "vulns": ["CVE-2021-44228", "CVE-2019-0708"]}}))
    codes = {f.code for f in r.findings}
    assert codes == {"shodan-port", "shodan-cve"}
    assert any("3389" in f.message and f.severity == "high" for f in r.findings)
    assert any("CVE-2019-0708" in f.message for f in r.findings)


def test_only_harmless_ports_give_one_info_finding():
    r = rec("8.8.4.4")
    shodan.enrich(r, client({"8.8.4.4": {"ports": [443, 80]}}))
    assert [f.code for f in r.findings] == ["shodan-ports"] and r.findings[0].severity == "info"


def test_unknown_ip_private_ip_and_ipv6_are_skipped():
    calls = []
    r = rec("8.8.4.4", "10.0.0.5", "2001:db8::1")
    shodan.enrich(r, client({"8.8.4.4": None}, calls))
    assert r.findings == [] and len(calls) == 1


def test_key_is_never_in_findings_or_errors():
    for status in (401, 500):
        r = rec("8.8.4.4")
        shodan.enrich(r, client({"8.8.4.4": status}))
        assert r.findings and all("KEY123" not in f.message for f in r.findings) and r.findings[0].code == "shodan-error"


def test_missing_key_is_an_error():
    with pytest.raises(ShodanError):
        Shodan("")


def test_lookup_is_cached_per_ip():
    calls = []
    c = client({"8.8.4.4": {"ports": [3389]}}, calls)
    c.lookup("8.8.4.4")
    c.lookup("8.8.4.4")
    assert len(calls) == 1


def test_run_scan_passes_intel_to_hosts():
    class FakeDNS:
        def lookup(self, name, rtype):
            return ("ok", ["8.8.4.4"]) if rtype == "A" else ("noanswer", [])

    result = pipeline.run_scan("corp.test", lambda d: {"vpn.corp.test": {}}, FakeDNS(), intel=client({"8.8.4.4": {"ports": [5900]}}))
    assert any(f.code == "shodan-port" for h in result.hosts for f in h.findings)
