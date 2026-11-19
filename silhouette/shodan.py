"""Пассивное обогащение через Shodan: какие порты и сервисы он уже видел на IP хоста и какие CVE к ним привязал.

Запросы уходят в Shodan, а не к цели: целевые серверы не затрагиваются. Ключ берётся из окружения, в вывод и в тексты
ошибок не попадает. Данные Shodan могут быть устаревшими, поэтому находки помечены как «по данным Shodan»."""
import json
import threading
import time
import urllib.error
import urllib.request

from .models import HIGH, INFO, MEDIUM, Finding
from .probe import is_public

API = "https://api.shodan.io/shodan/host/{ip}?key={key}&minify=false"
UA = "silhouette/0.2 (passive Shodan lookup)"
RISKY_PORTS = {
    23: (HIGH, "Telnet"), 445: (HIGH, "SMB"), 3389: (HIGH, "RDP"), 5900: (HIGH, "VNC"), 2375: (HIGH, "Docker API без TLS"),
    6379: (HIGH, "Redis"), 9200: (HIGH, "Elasticsearch"), 27017: (HIGH, "MongoDB"), 11211: (HIGH, "Memcached"), 5984: (HIGH, "CouchDB"),
    3306: (MEDIUM, "MySQL"), 5432: (MEDIUM, "PostgreSQL"), 1433: (MEDIUM, "MSSQL"), 21: (MEDIUM, "FTP"), 22: (INFO, "SSH"),
}
MAX_CVES = 8


class ShodanError(RuntimeError):
    pass


class Shodan:
    """lookup(ip) -> dict | None (None: Shodan об IP ничего не знает). Не больше одного запроса в `interval` секунд на весь скан."""

    def __init__(self, key, timeout=10.0, interval=1.1, opener=None, sleep=time.sleep, clock=time.monotonic):
        if not key:
            raise ShodanError("нет ключа Shodan: задайте переменную окружения SHODAN_API_KEY")
        self._key, self.timeout, self.interval = key, timeout, interval
        self._open = opener or urllib.request.urlopen
        self._sleep, self._clock = sleep, clock
        self._lock = threading.Lock()
        self._next = 0.0
        self._cache: dict = {}

    def _throttle(self):
        with self._lock:
            now = self._clock()
            wait = self._next - now
            self._next = max(now, self._next) + self.interval
        if wait > 0:
            self._sleep(wait)

    def lookup(self, ip):
        if ip in self._cache:
            return self._cache[ip]
        self._throttle()
        req = urllib.request.Request(API.format(ip=ip, key=self._key), headers={"User-Agent": UA})
        try:
            with self._open(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read(4_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._cache[ip] = None
                return None
            if e.code in (401, 403):
                raise ShodanError(f"Shodan отклонил ключ (HTTP {e.code})") from None
            raise ShodanError(f"Shodan ответил HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError):
            raise ShodanError("не удалось получить ответ Shodan") from None  # исключение может нести URL с ключом, поэтому без цепочки
        if not isinstance(data, dict):
            raise ShodanError("Shodan вернул неожиданный ответ")
        self._cache[ip] = data
        return data


def analyze(host, ip, data):
    """Находки по ответу Shodan для одного IP."""
    if not data:
        return []
    out = []
    ports = sorted({p for p in data.get("ports", []) if isinstance(p, int)})
    for port in ports:
        if port in RISKY_PORTS:
            sev, label = RISKY_PORTS[port]
            out.append(Finding(sev, "shodan-port", f"по данным Shodan, {ip}:{port} ({label}) открыт из интернета", host))
    cves = sorted({str(c) for c in (data.get("vulns") or []) if str(c).upper().startswith("CVE-")})
    if cves:
        shown = ", ".join(cves[:MAX_CVES]) + (f" и ещё {len(cves) - MAX_CVES}" if len(cves) > MAX_CVES else "")
        out.append(Finding(HIGH, "shodan-cve", f"по данным Shodan, {ip} связан с CVE: {shown} (Shodan может ошибаться: проверьте версию)", host))
    if ports and not out:
        out.append(Finding(INFO, "shodan-ports", f"по данным Shodan, на {ip} видны порты: {', '.join(map(str, ports[:12]))}", host))
    return out


def enrich(rec, client):
    """Добавляет находки Shodan к HostRecord. Ошибки сервиса не рушат скан: хост получает одну находку info."""
    seen = set()
    for ip in rec.dns.ips:
        if ip in seen or not is_public(ip) or ":" in ip:  # IPv6 пока не спрашиваем: Shodan лучше знает IPv4
            continue
        seen.add(ip)
        try:
            rec.findings += analyze(rec.name, ip, client.lookup(ip))
        except ShodanError as e:
            rec.findings.append(Finding(INFO, "shodan-error", str(e), rec.name))
            return
