"""Сканирование домена: источники → DNS → проверки → (опционально) зондирование."""
import time
from concurrent.futures import ThreadPoolExecutor

from . import checks, fingerprint
from .dnsclient import resolve_host
from .models import HIGH, LOW, MEDIUM, Finding, HostRecord, ProbeResult, ScanResult


def _apply_probe(rec: HostRecord, probe: ProbeResult):
    rec.probe = probe
    if probe.error and probe.status is None:
        return
    rec.tech = fingerprint.detect_tech(probe.headers, probe.body)
    rec.findings += fingerprint.analyze_tech_risks(rec.name, rec.tech)
    rec.findings += fingerprint.analyze_headers(rec.name, probe.scheme, probe.headers, probe.status)
    rec.findings += fingerprint.check_takeover_body(rec.name, probe.body)
    if probe.tls_error:
        sev = HIGH if "expired" in probe.tls_error.lower() else MEDIUM
        rec.findings.append(Finding(sev, "tls-invalid", f"сертификат не проходит проверку: {probe.tls_error}", rec.name))
    elif probe.tls_days_left is not None and probe.tls_days_left < 14:
        rec.findings.append(Finding(MEDIUM, "tls-expiring", f"сертификат истекает через {probe.tls_days_left} дн.", rec.name))
    tokens = {t for t in checks.SERVICE_NAME_TOKENS if t in rec.name.split(".", 1)[0].replace("-", ".").split(".")}
    if tokens and probe.status and 200 <= probe.status < 400:
        rec.findings.append(Finding(MEDIUM, "service-exposed", f"служебный хост ({', '.join(sorted(tokens))}) отвечает из интернета (HTTP {probe.status})", rec.name))


def scan_host(name, meta, dns_client, prober):
    rec = HostRecord(name=name, issuers=list(meta.get("issuers", [])), first_seen=meta.get("first_seen"),
                     last_not_after=meta.get("not_after"), wildcard=bool(meta.get("wildcard")))
    rec.dns = resolve_host(dns_client, name)
    rec.findings += checks.check_dns_host(name, rec.dns)
    if prober is not None and rec.dns.status == "ok":
        _apply_probe(rec, prober.probe(name, rec.dns.ips))
    return rec


def run_scan(domain, source, dns_client, prober=None, workers=8, progress=None) -> ScanResult:
    """source(domain) -> {имя: meta}. prober=None означает чисто пассивный режим."""
    domain = domain.lower().strip(".")
    started = time.time()
    names = dict(source(domain))
    names.setdefault(domain, {})
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_host, n, m, dns_client, prober) for n, m in sorted(names.items())]
        hosts = []
        for i, f in enumerate(futures, 1):
            hosts.append(f.result())
            if progress:
                progress(i, len(futures))
    result = ScanResult(domain=domain, started=started, finished=time.time(), probed=prober is not None, hosts=hosts)
    result.domain_findings = checks.check_email(domain, dns_client)
    return result
