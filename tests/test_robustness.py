import io
import json
import os
import urllib.error
from email.message import Message

import dns.exception
import dns.resolver
import pytest

from silhouette import sources
from silhouette.dnsclient import MAX_CHAIN, DNSClient, resolve_host
from silhouette.probe import Prober

D = "corp.example"
PAYLOAD = [{"name_value": "www.corp.example", "issuer_name": "C=US, CN=R3", "not_before": "2024-01-01T00:00:00", "not_after": "2025-01-01T00:00:00"}]


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://crt.sh", code, "err", headers, io.BytesIO(b""))


# ---- разбор ответов crt.sh ----

def test_parse_crtsh_rejects_non_list_payload():
    with pytest.raises(ValueError):
        sources.parse_crtsh({"error": "rate limited"}, D)


def test_parse_crtsh_skips_garbage_entries():
    out = sources.parse_crtsh(["str", 5, None, {"name_value": None}, {"name_value": "x" * 5000 + ".corp.example"}, PAYLOAD[0]], D)
    assert set(out) == {"www.corp.example"}


def test_fetch_html_error_page_is_a_failure_not_a_crash(tmp_path):
    def html(req, timeout):
        return FakeResp(b"<html>502 Bad Gateway</html>")

    with pytest.raises(RuntimeError, match="crt.sh недоступен"):
        sources.fetch_crtsh(D, urlopen=html, retries=2, sleep=lambda s: None, cache_dir=str(tmp_path))
    assert not os.path.exists(sources._cache_path(str(tmp_path), D))  # мусор в кэш не пишем


# ---- Retry-After ----

def test_retry_after_numeric_http_date_and_garbage():
    h = Message()
    h["Retry-After"] = "7"
    assert sources.retry_after_seconds(h) == 7
    h.replace_header("Retry-After", "9999")
    assert sources.retry_after_seconds(h) == sources.MAX_RETRY_WAIT
    h.replace_header("Retry-After", "Wed, 21 Oct 2015 07:28:10 GMT")
    assert sources.retry_after_seconds(h, now=lambda: 1445412490 - 10) == 10
    h.replace_header("Retry-After", "когда-нибудь")
    assert sources.retry_after_seconds(h) is None
    assert sources.retry_after_seconds(Message()) is None


def test_fetch_waits_for_retry_after_then_succeeds():
    calls, sleeps = [], []

    def flaky(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise http_error(429, "5")
        return FakeResp(json.dumps(PAYLOAD).encode())

    out = sources.fetch_crtsh(D, urlopen=flaky, retries=3, sleep=sleeps.append)
    assert "www.corp.example" in out
    assert 5 in sleeps  # ждали ровно столько, сколько попросил сервер


def test_fetch_backoff_without_retry_after_uses_jitter():
    sleeps = []

    def down(req, timeout):
        raise http_error(503)

    with pytest.raises(RuntimeError):
        sources.fetch_crtsh(D, urlopen=down, retries=3, sleep=sleeps.append, jitter=lambda: 0.5)
    assert 2.5 in sleeps and 4.5 in sleeps


# ---- кэш ----

def test_cache_hit_skips_network_and_expiry_refetches(tmp_path):
    calls = []

    def ok(req, timeout):
        calls.append(1)
        return FakeResp(json.dumps(PAYLOAD).encode())

    kw = dict(urlopen=ok, sleep=lambda s: None, cache_dir=str(tmp_path))
    first = sources.fetch_crtsh(D, **kw)
    again = sources.fetch_crtsh(D, **kw)
    assert first == again and len(calls) == 1
    path = sources._cache_path(str(tmp_path), D)
    old = os.path.getmtime(path) - 10 * 3600
    os.utime(path, (old, old))
    sources.fetch_crtsh(D, **kw)
    assert len(calls) == 2


def test_corrupt_cache_is_ignored(tmp_path):
    path = sources._cache_path(str(tmp_path), D)
    os.makedirs(os.path.dirname(path))
    with open(path, "w") as fh:
        fh.write("{оборвано")
    out = sources.fetch_crtsh(D, urlopen=lambda r, timeout: FakeResp(json.dumps(PAYLOAD).encode()), sleep=lambda s: None, cache_dir=str(tmp_path))
    assert "www.corp.example" in out


def test_cache_path_cannot_escape_cache_dir(tmp_path):
    path = sources._cache_path(str(tmp_path), "../../etc/passwd")
    assert os.path.commonpath([path, str(tmp_path)]) == str(tmp_path)
    assert ".." not in os.path.relpath(path, str(tmp_path)).split(os.sep)


# ---- DNS: ошибки, таймауты, циклы ----

@pytest.mark.parametrize("exc", [dns.exception.Timeout(), dns.resolver.NoNameservers(), dns.resolver.LifetimeTimeout(), OSError("net down")])
def test_dns_failures_become_error_status(exc):
    client = DNSClient()

    def boom(*a, **k):
        raise exc

    client.resolver.resolve = boom
    assert client.lookup("a.corp.example", "A") == ("error", [])
    assert resolve_host(client, "a.corp.example").status == "error"


def test_dns_nxdomain_and_noanswer_are_distinguished():
    client = DNSClient()
    client.resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NXDOMAIN())
    assert client.lookup("x.corp.example", "A")[0] == "nxdomain"
    client.resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NoAnswer())
    assert client.lookup("x.corp.example", "A")[0] == "noanswer"


class LoopDNS:
    """a -> b -> a: бесконечная цепочка CNAME."""

    def __init__(self):
        self.calls = 0

    def lookup(self, name, rtype):
        self.calls += 1
        if rtype == "CNAME":
            return "ok", ["b.corp.example" if name.startswith("a.") else "a.corp.example"]
        return "noanswer", []


def test_cname_loop_is_bounded():
    dns_client = LoopDNS()
    result = resolve_host(dns_client, "a.corp.example")
    assert len(result.cnames) == MAX_CHAIN
    assert result.status in ("nodata", "error")
    assert dns_client.calls < 4 * MAX_CHAIN


# ---- ограничение скорости проб ----

def test_prober_spaces_probes_by_rps():
    now = [100.0]
    waits = []

    def sleep(s):
        waits.append(round(s, 3))
        now[0] += s

    prober = Prober(rps=4, sleep=sleep, clock=lambda: now[0])
    for _ in range(5):
        prober._throttle()
    assert waits == [0.25] * 4  # без ожидания ушла только первая проба, остальные через 1/rps


def test_prober_without_public_ip_skips_before_throttle():
    prober = Prober(rps=1, sleep=lambda s: pytest.fail("не должно ждать"), clock=lambda: 0.0)
    assert "нет публичных IP" in prober.probe("x.corp.example", ["10.0.0.1"]).error


def test_dns_client_survives_missing_resolver_config(monkeypatch):
    real = dns.resolver.Resolver

    def fake(configure=True, *a, **k):
        if configure:
            raise dns.resolver.NoResolverConfiguration("no nameservers")
        return real(configure=False)

    monkeypatch.setattr(dns.resolver, "Resolver", fake)
    client = DNSClient()
    assert client.resolver.nameservers
