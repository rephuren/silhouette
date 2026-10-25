"""Пассивные источники поддоменов. Сейчас: логи Certificate Transparency через crt.sh.
Запрос уходит к crt.sh, а не к цели: целевые серверы на этом этапе не затрагиваются."""
import json
import re
import time
import urllib.parse
import urllib.request

CRT_URL = "https://crt.sh/?q={q}&output=json"
UA = "umbra/0.1 (passive CT lookup)"
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?$")


def valid_hostname(name: str) -> bool:
    if not name or len(name) > 253 or " " in name or "@" in name:
        return False
    return all(LABEL_RE.match(label) for label in name.split("."))


def parse_crtsh(payload, domain):
    """payload: список записей crt.sh. Возвращает {имя: {issuers, first_seen, not_after, wildcard}}."""
    domain = domain.lower().strip(".")
    out = {}
    for entry in payload:
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = raw.strip().lower()
            wildcard = name.startswith("*.")
            name = name[2:] if wildcard else name
            if not valid_hostname(name) or not (name == domain or name.endswith("." + domain)):
                continue
            rec = out.setdefault(name, {"issuers": set(), "first_seen": None, "not_after": None, "wildcard": False})
            if entry.get("issuer_name"):
                rec["issuers"].add(_issuer_cn(entry["issuer_name"]))
            nb, na = entry.get("not_before"), entry.get("not_after")
            if nb and (rec["first_seen"] is None or nb < rec["first_seen"]):
                rec["first_seen"] = nb
            if na and (rec["not_after"] is None or na > rec["not_after"]):
                rec["not_after"] = na
            rec["wildcard"] = rec["wildcard"] or wildcard
    for rec in out.values():
        rec["issuers"] = sorted(rec["issuers"])
    return out


def _issuer_cn(issuer_name: str) -> str:
    m = re.search(r"CN=([^,]+)", issuer_name)
    return (m.group(1) if m else issuer_name).strip()


def fetch_crtsh(domain, urlopen=urllib.request.urlopen, retries=3, timeout=40, sleep=time.sleep):
    url = CRT_URL.format(q=urllib.parse.quote("%." + domain))
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=timeout) as resp:
                return parse_crtsh(json.loads(resp.read().decode("utf-8", "replace")), domain)
        except Exception as e:  # сеть и разбор: повторяем, crt.sh часто отвечает ошибками под нагрузкой
            last = e
            sleep(2 * (attempt + 1))
    raise RuntimeError(f"crt.sh недоступен: {last.__class__.__name__}: {last}")
