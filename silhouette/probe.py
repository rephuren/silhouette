"""Активное зондирование: один GET / и чтение сертификата. Включается только явным флагом.
Берёт только публичные IP (внутренние адреса пропускаются), без редиректов и без перебора путей."""
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from .fingerprint import extract_title
from .models import ProbeResult

UA = "silhouette/0.1 (authorized security assessment)"
MAX_BODY = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _cert_info(host, timeout):
    """(ошибка_проверки | None, дней_до_истечения | None, издатель | None)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
        if not cert:
            return None, None, None
        info: Any = cert
        days = int((ssl.cert_time_to_seconds(info["notAfter"]) - time.time()) // 86400)
        issuer = dict(x[0] for x in info.get("issuer", ())).get("commonName")
        return None, days, issuer
    except ssl.SSLCertVerificationError as e:
        return (e.verify_message or str(e)), None, None
    except (OSError, ssl.SSLError):
        return None, None, None


class Prober:
    def __init__(self, timeout=6.0, rps=5.0, sleep=time.sleep, clock=time.monotonic):
        self.timeout = timeout
        self.interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._sleep, self._clock = sleep, clock
        self._lock = threading.Lock()
        self._next = 0.0

    def _throttle(self):
        """Не больше rps проб в секунду на весь скан, сколько бы ни было потоков."""
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            wait = self._next - now
            self._next = max(now, self._next) + self.interval
        if wait > 0:
            self._sleep(wait)

    def probe(self, host, ips) -> ProbeResult:
        if not any(is_public(ip) for ip in ips):
            return ProbeResult(error="нет публичных IP, пропущено")
        self._throttle()
        result = ProbeResult()
        opener_ctx = ssl.create_default_context()
        opener_ctx.check_hostname = False
        opener_ctx.verify_mode = ssl.CERT_NONE  # содержимое читаем даже при плохом сертификате, ошибку фиксируем отдельно
        for scheme in ("https", "http"):
            try:
                opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=opener_ctx))
                req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
                resp = opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                resp = e  # 3xx/4xx/5xx тоже ответ
            except (urllib.error.URLError, OSError, ssl.SSLError) as e:
                result.error = f"{scheme}: {getattr(e, 'reason', e)}"
                continue
            result.scheme, result.status = scheme, resp.status if hasattr(resp, "status") else resp.code
            result.headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(MAX_BODY)
            result.body = body.decode("utf-8", "replace")
            result.title = extract_title(result.body)
            result.error = None
            break
        if result.scheme == "https":
            result.tls_error, result.tls_days_left, result.tls_issuer = _cert_info(host, self.timeout)
        return result
