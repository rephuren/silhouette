from silhouette import checks
from silhouette.models import INFO, LOW


class DNS:
    """Подмена DNS-клиента: ответы по типу записи."""

    def __init__(self, dnskey=("noanswer", []), caa=("noanswer", [])):
        self.answers = {"DNSKEY": dnskey, "CAA": caa}

    def lookup(self, name, rtype):
        return self.answers.get(rtype, ("noanswer", []))


def codes(findings):
    return {f.code: f.severity for f in findings}


def test_missing_both_gives_two_low_findings():
    got = codes(checks.check_dns_hardening("example.org", DNS()))
    assert got == {"dnssec-missing": LOW, "caa-missing": LOW}


def test_everything_present_gives_single_info():
    dns = DNS(("ok", ["257 3 13 AAAA"]), ("ok", ['0 issue "letsencrypt.org"']))
    assert codes(checks.check_dns_hardening("example.org", dns)) == {"dns-hardening-ok": INFO}


def test_dnssec_only_or_caa_only():
    only_dnssec = codes(checks.check_dns_hardening("example.org", DNS(("ok", ["257 3 13 K"]))))
    assert only_dnssec == {"caa-missing": LOW}
    only_caa = codes(checks.check_dns_hardening("example.org", DNS(caa=("ok", ['0 issue "pki.goog"']))))
    assert only_caa == {"dnssec-missing": LOW}


def test_caa_without_issue_tag_is_not_a_restriction():
    dns = DNS(("ok", ["257 3 13 K"]), ("ok", ['0 iodef "mailto:sec@example.org"']))
    assert codes(checks.check_dns_hardening("example.org", dns)) == {"caa-no-issue": INFO}


def test_caa_issue_and_issuewild_recognized():
    for record in ['0 issue ";"', '0 issuewild "letsencrypt.org"', '128 issue "digicert.com"']:
        dns = DNS(("ok", ["257 3 13 K"]), ("ok", [record]))
        got = codes(checks.check_dns_hardening("example.org", dns))
        assert "caa-missing" not in got, record


def test_dns_errors_do_not_produce_false_alarms():
    got = codes(checks.check_dns_hardening("example.org", DNS(("error", []), ("error", []))))
    assert got == {"dnssec-unknown": INFO, "caa-unknown": INFO}
    assert not any(sev == LOW for sev in got.values())


def test_nonexistent_domain_is_skipped():
    assert checks.check_dns_hardening("nope.example", DNS(("nxdomain", []))) == []


def test_pipeline_includes_dns_hardening_for_demo_domain():
    from silhouette import demo
    from silhouette.pipeline import run_scan

    dns, prober, source = demo.build(1)
    result = run_scan(demo.DOMAIN, source, dns, prober, workers=1)
    assert any(f.code == "dns-hardening-ok" for f in result.domain_findings)
