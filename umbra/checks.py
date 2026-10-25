"""Проверки, которым нужен только DNS: захват поддоменов, почтовая защита домена, утечки имён и адресов."""
import ipaddress
import re

from .models import HIGH, INFO, LOW, MEDIUM, Finding

# Сервисы, на которые часто остаются «висячие» CNAME (ориентир: can-i-take-over-xyz)
TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.azure.com": "Azure", "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager", "blob.core.windows.net": "Azure Blob",
    "s3.amazonaws.com": "AWS S3", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "bitbucket.io": "Bitbucket", "surge.sh": "Surge", "netlify.app": "Netlify", "ghost.io": "Ghost",
    "pantheonsite.io": "Pantheon", "readme.io": "Readme", "zendesk.com": "Zendesk", "helpscoutdocs.com": "Help Scout",
    "fastly.net": "Fastly", "unbouncepages.com": "Unbounce", "cargocollective.com": "Cargo",
}
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10")]
SERVICE_NAME_TOKENS = {
    "dev", "test", "stage", "staging", "uat", "qa", "admin", "jenkins", "gitlab", "grafana", "kibana", "vpn",
    "internal", "backup", "old", "beta", "sandbox", "intranet", "phpmyadmin", "ftp", "git", "sentry", "demo",
}


def takeover_service(cname_target: str):
    t = cname_target.lower().rstrip(".")
    for suffix, name in TAKEOVER_SERVICES.items():
        if t == suffix or t.endswith("." + suffix):
            return name
    return None


def check_dns_host(name, dns_result):
    out = []
    if dns_result.status == "dangling":
        target = dns_result.cnames[-1]
        service = takeover_service(target)
        if service:
            out.append(Finding(HIGH, "takeover-candidate",
                               f"CNAME → {target} не существует ({service}): поддомен можно захватить, зарегистрировав ресурс", name))
        else:
            out.append(Finding(MEDIUM, "dangling-cname", f"CNAME → {target} указывает в никуда", name))
    for ip in dns_result.ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in net for net in INTERNAL_NETS if net.version == addr.version):
            out.append(Finding(LOW, "internal-ip-in-dns", f"публичный DNS отдаёт внутренний адрес {ip}: раскрывает схему сети", name))
            break
    tokens = set(re.split(r"[.\-_]", name.split(".", 1)[0]))
    hit = sorted(tokens & SERVICE_NAME_TOKENS)
    if hit and dns_result.status == "ok":
        out.append(Finding(LOW, "service-name", f"служебное имя в публичном DNS ({', '.join(hit)}): подсказка атакующему", name))
    return out


def check_email(domain, dns_client):
    """SPF и DMARC корня домена."""
    out = []
    _, txt = dns_client.lookup(domain, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    _, mx = dns_client.lookup(domain, "MX")
    sends_mail = bool(mx)
    if not spf:
        if sends_mail:
            out.append(Finding(MEDIUM, "spf-missing", "нет SPF-записи: письма от имени домена легко подделать", domain))
    else:
        qualifier = None
        for term in spf[0].lower().split():
            if term in ("all", "+all"):
                qualifier = "+"
            elif term in ("-all", "~all", "?all"):
                qualifier = term[0]
        if qualifier == "+":
            out.append(Finding(HIGH, "spf-open", "SPF разрешает отправку с любого адреса (+all)", domain))
        elif qualifier == "?":
            out.append(Finding(MEDIUM, "spf-neutral", "SPF с ?all не защищает от подделки", domain))
        elif qualifier == "~":
            out.append(Finding(LOW, "spf-softfail", "SPF с ~all: подделка помечается, но не отклоняется", domain))
    _, dmarc = dns_client.lookup("_dmarc." + domain, "TXT")
    dm = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if not dm:
        if sends_mail:
            out.append(Finding(MEDIUM, "dmarc-missing", "нет DMARC: нет политики для подделанных писем", domain))
    else:
        m = re.search(r"\bp=(\w+)", dm[0].lower())
        policy = m.group(1) if m else "none"
        if policy == "none":
            out.append(Finding(LOW, "dmarc-monitor", "DMARC в режиме p=none: только мониторинг, ничего не блокируется", domain))
    if not out and (spf or dm):
        out.append(Finding(INFO, "mail-ok", "SPF и DMARC настроены", domain))
    return out
