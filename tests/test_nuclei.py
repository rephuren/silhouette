import json

import pytest

from silhouette import nuclei
from silhouette.__main__ import main
from silhouette.models import DNSResult, HostRecord, ProbeResult
from silhouette.nuclei import Nuclei, NucleiError


def line(tid, name, sev):
    return json.dumps({"template-id": tid, "info": {"name": name, "severity": sev}, "matched-at": "https://x"})


def rec(status=200):
    return HostRecord(name="app.corp.test", dns=DNSResult([], ["8.8.4.4"], "ok"), probe=ProbeResult(status=status))


def test_parse_maps_severity_and_skips_garbage():
    out = "\n".join([line("CVE-2023-1", "Exposed panel", "high"), "not json", "[1,2]", json.dumps({"x": 1}), line("tech-detect", "Tech", "info")])
    found = nuclei.parse("app.corp.test", out)
    assert [(f.severity, f.code) for f in found] == [("high", "nuclei"), ("info", "nuclei")]
    assert "CVE-2023-1" in found[0].message


def test_parse_limits_findings_per_host():
    out = "\n".join(line(f"t{i}", "n", "low") for i in range(50))
    assert len(nuclei.parse("h", out)) == nuclei.MAX_FINDINGS_PER_HOST


def test_argv_has_no_shell_and_excludes_intrusive_tags():
    n = Nuclei(binary="/usr/bin/nuclei", rps=3, runner=lambda a, t: "")
    argv = n.argv("app.corp.test")
    assert argv[:3] == ["/usr/bin/nuclei", "-u", "https://app.corp.test"]
    assert argv[argv.index("-exclude-tags") + 1] == "dos,fuzz,bruteforce,intrusive" and argv[argv.index("-rate-limit") + 1] == "3"


def test_invalid_host_name_is_not_run():
    calls = []
    n = Nuclei(binary="nuclei", runner=lambda a, t: calls.append(a) or "")
    assert n.scan("evil.test; rm -rf /") == [] and calls == []


def test_enrich_only_for_hosts_that_answered_the_probe():
    r1, r2 = rec(200), rec(None)
    n = Nuclei(binary="nuclei", runner=lambda a, t: line("t", "N", "medium"))
    nuclei.enrich(r1, n)
    nuclei.enrich(r2, n)
    assert len(r1.findings) == 1 and r2.findings == []


def test_runner_error_becomes_single_info_finding():
    def boom(argv, timeout):
        raise NucleiError("nuclei не уложился во время")
    r = rec()
    nuclei.enrich(r, Nuclei(binary="nuclei", runner=boom))
    assert [f.code for f in r.findings] == ["nuclei-error"]


def test_missing_binary_is_reported(monkeypatch):
    monkeypatch.setattr(nuclei.shutil, "which", lambda name: None)
    with pytest.raises(NucleiError):
        Nuclei()


def test_cli_requires_authorization_and_probe(capsys):
    assert main(["scan", "corp.test", "--nuclei"]) == 2
    assert main(["scan", "corp.test", "--nuclei", "--probe"]) == 2
    assert "--i-am-authorized" in capsys.readouterr().err
