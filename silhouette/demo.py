"""Симулированная среда для демо и тестов: домен corp.example (.example зарезервирован, реальных адресов нет).
Подставные DNS и сайты прогоняются через настоящий конвейер, так что показаны реальные проверки."""
from .models import ProbeResult

DOMAIN = "corp.example"
NET = "203.0.113"

WORDPRESS = ('<html><head><title>Blog</title><meta name="generator" content="WordPress 5.8.1">'
             '<script src="/wp-content/themes/x/app.js"></script></head></html>')
NEXT = '<html><head><title>Corp Platform</title></head><body><script id="__NEXT_DATA__"></script></body></html>'
JENKINS = "<html><head><title>Dashboard [Jenkins]</title></head></html>"
GRAFANA = "<html><head><title>Grafana</title></head></html>"
PLAIN = "<html><head><title>{t}</title></head><body>hello</body></html>"
GITHUB_404 = "<html><body><p>There isn't a GitHub Pages site here.</p></body></html>"
JQUERY_OLD = '<html><head><title>Legacy portal</title><script src="/js/jquery-1.12.4.min.js"></script></head></html>'
GOOD = {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff"}


class FakeDNS:
    def __init__(self, zone, txt=None, mx=None):
        self.zone, self.txt, self.mx = zone, txt or {}, mx or []

    def lookup(self, name, rtype):
        if rtype == "TXT":
            return ("ok", self.txt[name]) if name in self.txt else ("noanswer", [])
        if rtype == "MX":
            return ("ok", self.mx) if name == DOMAIN and self.mx else ("noanswer", [])
        entry = self.zone.get(name)
        if entry is None or entry == "NX":
            return "nxdomain", []
        if rtype == "CNAME":
            return ("ok", [entry["cname"]]) if entry.get("cname") else ("noanswer", [])
        if rtype == "A":
            return ("ok", entry["a"]) if entry.get("a") else ("noanswer", [])
        return "noanswer", []


class FakeProber:
    def __init__(self, pages):
        self.pages = pages

    def probe(self, host, ips):
        return self.pages.get(host, ProbeResult(error="нет ответа"))


def page(title_or_body, headers=None, status=200, tls_days=200, tls_error=None, scheme="https"):
    body = title_or_body if "<" in title_or_body else PLAIN.format(t=title_or_body)
    from .fingerprint import extract_title
    return ProbeResult(scheme=scheme, status=status, headers={k.lower(): v for k, v in (headers or {}).items()},
                       body=body, title=extract_title(body), tls_days_left=None if tls_error else tls_days,
                       tls_error=tls_error, tls_issuer="R3")


def host(a, cname=None):
    return {"a": a if isinstance(a, list) else [a], "cname": cname}


def build(stage=1):
    z = {
        DOMAIN: host(f"{NET}.10"),
        "www.corp.example": host(f"{NET}.10"),
        "app.corp.example": host(f"{NET}.21", "lb.corp.example"),
        "lb.corp.example": host(f"{NET}.21"),
        "api.corp.example": host(f"{NET}.30" if stage == 1 else f"{NET}.31"),
        "auth.corp.example": host(f"{NET}.22"),
        "mail.corp.example": host("198.51.100.5"),
        "vpn.corp.example": host("198.51.100.9"),
        "blog.corp.example": host(f"{NET}.40"),
        "shop.corp.example": host("198.51.100.77", "shops.myshopify.example"),
        "shops.myshopify.example": host("198.51.100.77"),
        "cdn.corp.example": host("192.0.2.15", "d111.cloudfront.example"),
        "d111.cloudfront.example": host("192.0.2.15"),
        "static.corp.example": host("192.0.2.15", "d111.cloudfront.example"),
        "staging.corp.example": host(f"{NET}.51"),
        "dev.corp.example": host(f"{NET}.52"),
        "jenkins.corp.example": host(f"{NET}.60"),
        "grafana.corp.example": host(f"{NET}.61"),
        "git.corp.example": host(f"{NET}.62"),
        "intranet.corp.example": host("10.0.4.12"),
        "legacy.corp.example": host(f"{NET}.70"),
        "portal.corp.example": host(f"{NET}.71"),
        "support.corp.example": host("198.51.100.90", "corp.zendesk.com"),
        "corp.zendesk.com": host("198.51.100.90"),
        "status.corp.example": host("192.0.2.40", "corp-status.herokuapp.com"),
        "corp-status.herokuapp.com": "NX",
        "careers.corp.example": host("192.0.2.50"),
        "docs.corp.example": host("192.0.2.60", "corp.github.io") if stage == 1 else host("192.0.2.60"),
        "corp.github.io": "NX",
        "wiki.corp.example": host(f"{NET}.80"),
        "backup.corp.example": host(f"{NET}.81"),
        "metrics.corp.example": host(f"{NET}.82"),
    }
    if stage == 1:
        z["old.corp.example"] = host(f"{NET}.90")
    else:
        z["pay.corp.example"] = host(f"{NET}.100")
        z["test-api.corp.example"] = host(f"{NET}.101")
    txt = {DOMAIN: ["v=spf1 include:_spf.example ~all"], "_dmarc." + DOMAIN: ["v=DMARC1; p=none; rua=mailto:d@corp.example"]}
    dns = FakeDNS(z, txt=txt, mx=["10 mail.corp.example"])

    pages = {
        DOMAIN: page("Corp", {**GOOD, "server": "cloudflare", "cf-ray": "1"}),
        "www.corp.example": page("Corp", {**GOOD, "server": "cloudflare", "cf-ray": "1"}),
        "app.corp.example": page(NEXT, {**GOOD, "x-vercel-id": "fra1::x"}),
        "api.corp.example": page("API", {"server": "nginx/1.18.0", "strict-transport-security": "max-age=1"}),
        "auth.corp.example": page("Login", {**GOOD, "set-cookie": "sid=1; Secure; HttpOnly"}),
        "blog.corp.example": page(WORDPRESS, {"server": "Apache/2.4.49", "x-powered-by": "PHP/7.4.3",
                                              "set-cookie": "wordpress_test_cookie=1"}),
        "shop.corp.example": page("Shop", {**GOOD, "x-shopid": "1"}),
        "cdn.corp.example": page("CDN", {"x-amz-cf-id": "abc", "strict-transport-security": "max-age=1"}),
        "staging.corp.example": page("Staging", {"server": "nginx/1.24.0"}),
        "dev.corp.example": page("Dev", {"server": "nginx/1.24.0"}, tls_error="certificate has expired"),
        "jenkins.corp.example": page(JENKINS, {"x-jenkins": "2.401", "server": "Jetty"},
                                     status=403 if stage == 1 else 200),
        "grafana.corp.example": page(GRAFANA, {"set-cookie": "grafana_sess=1"}),
        "legacy.corp.example": page(JQUERY_OLD, {"server": "Microsoft-IIS/8.5", "x-powered-by": "ASP.NET",
                                                  "x-aspnet-version": "4.0.30319"}),
        "docs.corp.example": page(GITHUB_404, {"server": "GitHub.com", "x-github-request-id": "1"}, status=404),
        "support.corp.example": page("Support", GOOD, tls_days=9),
        "careers.corp.example": page("Careers", GOOD),
        "wiki.corp.example": page("Wiki", {"server": "nginx"}),
        "portal.corp.example": page("Portal", {**GOOD, "set-cookie": "PHPSESSID=1; HttpOnly"}),
    }
    return dns, FakeProber(pages), (lambda domain: {n: {"issuers": ["R3"], "first_seen": "2025-01-10"}
                                                    for n in z if n.endswith(DOMAIN) and z[n] != "NX"})


def seed(store):
    import time

    from .pipeline import run_scan
    ids = []
    for stage in (1, 2):
        dns, prober, source = build(stage)
        result = run_scan(DOMAIN, source, dns, prober)
        base = time.time() - (2 - stage) * 86400 * 7
        result.started, result.finished = base - 20, base
        ids.append(store.save(result))
    return ids
