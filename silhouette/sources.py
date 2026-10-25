"""Пассивные источники поддоменов. Сейчас: логи Certificate Transparency через crt.sh.
Запрос уходит к crt.sh, а не к цели: целевые серверы на этом этапе не затрагиваются."""
import email.utils
import json
import os
import random
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CRT_URL = "https://crt.sh/?q={q}&output=json"
UA = "silhouette/0.1 (passive CT lookup)"
MIN_INTERVAL = 1.5      # пауза между запросами к crt.sh: сервис общий и бесплатный
MAX_RETRY_WAIT = 60     # дольше Retry-After не ждём
CACHE_TTL = 6 * 3600
_throttle_lock = threading.Lock()
_last_request = 0.0
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?$")


def valid_hostname(name: str) -> bool:
    if not name or len(name) > 253 or " " in name or "@" in name:
        return False
    return all(LABEL_RE.match(label) for label in name.split("."))


def parse_crtsh(payload, domain):
    """payload: список записей crt.sh. Возвращает {имя: {issuers, first_seen, not_after, wildcard}}."""
    domain = domain.lower().strip(".")
    if not isinstance(payload, list):
        raise ValueError("crt.sh вернул не список записей")
    out: dict[str, dict] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            continue
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


def retry_after_seconds(headers, now=time.time):
    """Разбирает Retry-After: число секунд или HTTP-дата. None, если заголовка нет или он нечитаем."""
    value = headers.get("Retry-After") if headers is not None else None
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(int(value), MAX_RETRY_WAIT)
    try:
        when = email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None
    return max(0, min(int(when - now()), MAX_RETRY_WAIT))


def _throttle(sleep, clock):
    global _last_request
    with _throttle_lock:
        wait = _last_request + MIN_INTERVAL - clock()
        if wait > 0:
            sleep(wait)
        _last_request = clock()


def _cache_path(cache_dir, domain):
    return os.path.join(cache_dir, "crtsh", re.sub(r"[^a-z0-9.\-_]", "_", domain.lower()) + ".json")


def _cache_read(path, ttl, clock):
    try:
        if clock() - os.path.getmtime(path) > ttl:
            return None
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        return payload if isinstance(payload, list) else None
    except (OSError, ValueError):
        return None  # нет кэша, он устарел или повреждён: идём в сеть


def _cache_write(path, payload):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)  # атомарно: недописанный файл не попадёт в кэш
    except OSError:
        pass  # кэш необязателен


def fetch_crtsh(domain, urlopen=urllib.request.urlopen, retries=3, timeout=40, sleep=time.sleep,
                cache_dir=None, cache_ttl=CACHE_TTL, clock=time.time, jitter=random.random):
    cache = _cache_path(cache_dir, domain) if cache_dir else None
    if cache:
        cached = _cache_read(cache, cache_ttl, clock)
        if cached is not None:
            return parse_crtsh(cached, domain)
    url = CRT_URL.format(q=urllib.parse.quote("%." + domain))
    last: Exception | None = None
    for attempt in range(retries):
        _throttle(sleep, clock)
        wait = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            parsed = parse_crtsh(payload, domain)
            if cache:
                _cache_write(cache, payload)
            return parsed
        except urllib.error.HTTPError as e:  # 429/503 просят подождать: уважаем Retry-After
            last = e
            wait = retry_after_seconds(e.headers, clock)
        except Exception as e:  # сеть и разбор: повторяем, crt.sh часто отвечает ошибками под нагрузкой
            last = e
        if attempt < retries - 1:
            sleep(wait if wait is not None else 2 * (attempt + 1) + jitter())
    raise RuntimeError(f"crt.sh недоступен: {last.__class__.__name__}: {last}")
