"""Определение технологий и разбор заголовков по ответу сайта (в духе WhatWeb)."""
import re

from .models import HIGH, INFO, LOW, MEDIUM, Finding

# (название, где искать, регэксп). Версия берётся из группы "v", если она есть.
TECH_RULES = [
    ("nginx", "server", r"nginx(?:/(?P<v>[\d.]+))?"),
    ("Apache", "server", r"Apache(?:/(?P<v>[\d.]+))?"),
    ("Microsoft IIS", "server", r"Microsoft-IIS(?:/(?P<v>[\d.]+))?"),
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("PHP", "x-powered-by", r"PHP(?:/(?P<v>[\d.]+))?"),
    ("ASP.NET", "x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "x-aspnet-version", r"(?P<v>[\d.]+)"),
    ("Express", "x-powered-by", r"Express"),
    ("Vercel", "x-vercel-id", r".+"),
    ("GitHub Pages", "x-github-request-id", r".+"),
    ("Amazon CloudFront", "x-amz-cf-id", r".+"),
    ("Fastly", "x-served-by", r"cache-"),
    ("Varnish", "via", r"varnish"),
    ("Shopify", "x-shopid", r".+"),
    ("PHP (сессия)", "set-cookie", r"PHPSESSID"),
    ("Java (сессия)", "set-cookie", r"JSESSIONID"),
    ("Laravel", "set-cookie", r"laravel_session"),
    ("Django", "set-cookie", r"csrftoken"),
    ("WordPress", "body", r"/wp-(?:content|includes)/"),
    ("WordPress", "generator", r"WordPress(?:\s+(?P<v>[\d.]+))?"),
    ("Drupal", "generator", r"Drupal(?:\s+(?P<v>[\d.]+))?"),
    ("Joomla", "generator", r"Joomla"),
    ("Next.js", "body", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", "body", r"__NUXT__|/_nuxt/"),
    ("Angular", "body", r"ng-version=\"(?P<v>[\d.]+)\""),
    ("React", "body", r"data-reactroot|react-dom"),
    ("jQuery", "body", r"jquery[-.](?P<v>\d+\.\d+\.\d+)(?:\.min)?\.js"),
    ("Bootstrap", "body", r"bootstrap(?:[-.](?P<v>\d+\.\d+\.\d+))?(?:\.min)?\.(?:css|js)"),
    ("Grafana", "body", r"<title>Grafana"),
    ("Jenkins", "x-jenkins", r".+"),
    ("phpMyAdmin", "body", r"phpMyAdmin"),
]
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Версии с известными проблемами. Проверяйте актуальность перед выводами.
RISKY_VERSIONS = [
    ("Apache", lambda v: v in ("2.4.49", "2.4.50"), HIGH, "обход путей и RCE (CVE-2021-41773 / CVE-2021-42013)"),
    ("PHP", lambda v: _ver(v) < (8, 2), MEDIUM, "ветка PHP снята с поддержки или скоро будет снята"),
    ("nginx", lambda v: _ver(v) < (1, 20), LOW, "очень старая ветка nginx"),
    ("jQuery", lambda v: _ver(v) < (3, 5), MEDIUM, "jQuery до 3.5.0 уязвим к XSS (CVE-2020-11022 / CVE-2020-11023)"),
    ("Bootstrap", lambda v: _ver(v) < (4, 3), LOW, "старый Bootstrap с известными XSS"),
]

# Тела страниц «ничейных» ресурсов у сервисов (признак возможного захвата)
TAKEOVER_BODIES = [
    ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ("Heroku", "No such app"),
    ("AWS S3", "NoSuchBucket"),
    ("Azure", "404 Web Site not found"),
    ("Netlify", "Not Found - Request ID"),
    ("Surge", "project not found"),
    ("Ghost", "The thing you were looking for is no longer here"),
    ("Zendesk", "Help Center Closed"),
    ("Bitbucket", "Repository not found"),
]


def _ver(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in parts[:3]) + (0,) * (3 - len(parts[:3])) if parts else (9999, 0, 0)


def extract_title(body):
    m = TITLE_RE.search(body or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def detect_tech(headers, body):
    """headers: ключи в нижнем регистре. Возвращает [{name, version, evidence}] без дублей."""
    headers = {k.lower(): v for k, v in headers.items()}
    generator = ""
    m = GENERATOR_RE.search(body or "")
    if m:
        generator = m.group(1)
    found, seen = [], set()
    for name, where, pattern in TECH_RULES:
        if where == "body":
            hay = body or ""
        elif where == "generator":
            hay = generator
        else:
            hay = headers.get(where, "")
        if not hay:
            continue
        match = re.search(pattern, hay, re.I)
        if not match:
            continue
        version = (match.groupdict().get("v") or "") if match.groupdict() else ""
        key = (name, version)
        if key in seen or (name, "") in seen and not version:
            continue
        seen.add(key)
        found.append({"name": name, "version": version, "evidence": where})
    return found


def analyze_tech_risks(host, tech):
    out = []
    for t in tech:
        if not t["version"]:
            continue
        for name, bad, severity, why in RISKY_VERSIONS:
            if t["name"] == name and bad(t["version"]):
                out.append(Finding(severity, "risky-version", f"{name} {t['version']}: {why}", host))
    return out


def analyze_headers(host, scheme, headers, status):
    h = {k.lower(): v for k, v in headers.items()}
    out = []
    if scheme == "https" and "strict-transport-security" not in h:
        out.append(Finding(LOW, "no-hsts", "нет заголовка HSTS", host))
    if status and 200 <= status < 300:
        csp = h.get("content-security-policy", "")
        if not csp:
            out.append(Finding(LOW, "no-csp", "нет Content-Security-Policy", host))
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            out.append(Finding(LOW, "clickjacking", "страницу можно встроить во фрейм (нет X-Frame-Options / frame-ancestors)", host))
        if "x-content-type-options" not in h:
            out.append(Finding(INFO, "no-nosniff", "нет X-Content-Type-Options: nosniff", host))
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server) or re.search(r"\d+\.\d+", powered):
        out.append(Finding(LOW, "version-disclosure", f"заголовки раскрывают версии ПО ({(server + ' ' + powered).strip()})", host))
    cookie = h.get("set-cookie", "")
    if cookie:
        low = cookie.lower()
        if scheme == "https" and "secure" not in low:
            out.append(Finding(LOW, "cookie-no-secure", "Set-Cookie без флага Secure", host))
        if "httponly" not in low:
            out.append(Finding(LOW, "cookie-no-httponly", "Set-Cookie без флага HttpOnly", host))
    return out


def check_takeover_body(host, body):
    for service, marker in TAKEOVER_BODIES:
        if marker.lower() in (body or "").lower():
            return [Finding(HIGH, "takeover-body", f"страница похожа на «ничейный» ресурс {service} (\"{marker}\")", host)]
    return []
