import argparse
import functools
import os
import sys

from . import dashboard, demo, pipeline
from .dnsclient import DNSClient
from .gate import decide
from .models import SEVERITY_ORDER
from .probe import Prober
from .sources import fetch_crtsh
from .store import Store

RED, DIM, BOLD, RESET = "\033[38;2;179;0;15m", "\033[2m", "\033[1m", "\033[0m"
SEV_MARK = {"critical": ("▓▓", RED + BOLD), "high": ("▓", RED), "medium": ("▒", ""), "low": ("░", DIM), "info": ("·", DIM)}
LEGAL = ("Активное зондирование отправляет HTTP/TLS-запросы на серверы цели. Используйте его только для доменов, "
         "которыми вы владеете или на проверку которых у вас есть письменное разрешение.")


def print_report(store, domain, color, min_severity="low"):
    ids = store.scan_ids(domain)
    if not ids:
        print(f"по {domain} сканов нет")
        return
    sid = ids[-1]
    sm = store.summary(sid)

    def c(code, s):
        return f"{code}{s}{RESET}" if color and code else s

    print(c(BOLD, f"{domain}") + f"  оценка {c(RED, sm['grade'])}  хостов {sm['hosts']} (отвечают {sm['resolved']})")
    print("  " + "  ".join(f"{k} {v}" for k, v in sm["findings"].items()))
    limit = SEVERITY_ORDER.index(min_severity)
    for f in store.findings(sid):
        if SEVERITY_ORDER.index(f["severity"]) > limit:
            continue
        mark, code = SEV_MARK[f["severity"]]
        print(f"  {c(code, mark):>3} {f['host'] or domain}: {f['message']}")
    if sm["tech"]:
        print(c(DIM, "  технологии: " + ", ".join(f"{n} ×{k}" for n, k in sm["tech"][:10])))


def gate(store, domain, fail_on, fail_on_new):
    code, reasons = decide(store, domain, fail_on, fail_on_new)
    for r in reasons:
        print(f"порог превышен: {r}", file=sys.stderr)
    return code


def main(argv=None):
    p = argparse.ArgumentParser(prog="silhouette", description="Монитор внешней поверхности атаки")
    sub = p.add_subparsers(dest="mode", required=True)
    sc = sub.add_parser("scan", help="просканировать домен")
    sc.add_argument("domain")
    sc.add_argument("--db", default="data/silhouette.db")
    sc.add_argument("--probe", action="store_true", help="активное зондирование: GET / и сертификат")
    sc.add_argument("--i-am-authorized", action="store_true", help="подтверждение права проверять этот домен (нужно для --probe)")
    sc.add_argument("--workers", type=int, default=8)
    sc.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], help="код возврата 3, если в скане есть находки не ниже порога")
    sc.add_argument("--fail-on-new", choices=[*SEVERITY_ORDER, "none"], help="код возврата 3, если появились новые находки не ниже порога (против прошлого скана)")
    sc.add_argument("--rps", type=float, default=5.0, help="предел активных проб в секунду (с --probe)")
    sc.add_argument("--no-cache", action="store_true", help="не использовать кэш ответов crt.sh")
    sc.add_argument("--cache-ttl", type=int, default=6 * 3600, help="срок жизни кэша crt.sh, секунды")
    rp = sub.add_parser("report", help="отчёт по последнему скану")
    rp.add_argument("domain")
    rp.add_argument("--db", default="data/silhouette.db")
    rp.add_argument("--min-severity", default="low", choices=SEVERITY_ORDER)
    rp.add_argument("--no-color", action="store_true")
    rp.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], help="код возврата 3, если в последнем скане есть находки не ниже порога")
    rp.add_argument("--fail-on-new", choices=[*SEVERITY_ORDER, "none"], help="код возврата 3, если в последнем скане появились новые находки не ниже порога")
    df = sub.add_parser("diff", help="что изменилось с прошлого скана")
    df.add_argument("domain")
    df.add_argument("--db", default="data/silhouette.db")
    ds = sub.add_parser("dashboard", help="локальный веб-дашборд")
    ds.add_argument("--db", default="data/silhouette.db")
    ds.add_argument("--host", default="127.0.0.1")
    ds.add_argument("--port", type=int, default=8090)
    sd = sub.add_parser("seed-demo", help="симулированный домен corp.example для демо")
    sd.add_argument("--db", default="data/demo.db")
    a = p.parse_args(argv)

    if a.mode == "seed-demo":
        store = Store(a.db)
        demo.seed(store)
        print(f"демо записано в {a.db} (домен {demo.DOMAIN}, 2 скана)")
        return 0
    if a.mode == "dashboard":
        dashboard.serve(a.host, a.port, a.db)
        return 0
    if a.mode == "report":
        store = Store(a.db)
        print_report(store, a.domain.lower(), sys.stdout.isatty() and not a.no_color, a.min_severity)
        return gate(store, a.domain.lower(), a.fail_on, a.fail_on_new)
    if a.mode == "diff":
        d = Store(a.db).diff(a.domain.lower())
        if not d:
            print("нужно минимум два скана")
            return 0
        for title, items in (("новые хосты", d["new_hosts"]), ("исчезли", d["gone_hosts"])):
            print(f"{title}: {', '.join(items) or '—'}")
        for ch in d["ip_changes"]:
            print(f"смена IP: {ch['host']}  {ch['old']} → {ch['new']}")
        for f in d["new_findings"]:
            print(f"+ [{f['severity']}] {f['host']}: {f['message']}")
        for f in d["fixed_findings"]:
            print(f"- [{f['severity']}] {f['host']}: {f['message']}")
        return 0

    # scan
    if a.probe and not a.i_am_authorized:
        print(LEGAL + "\nДобавьте --i-am-authorized, если это так.", file=sys.stderr)
        return 2
    print("режим: " + ("активный (--probe)" if a.probe else "пассивный: запросы только к crt.sh и DNS, цель не затрагивается"))
    store = Store(a.db)
    try:
        cache_dir = None if a.no_cache else os.path.join(os.path.dirname(a.db) or ".", "cache")
        source = functools.partial(fetch_crtsh, cache_dir=cache_dir, cache_ttl=a.cache_ttl)
        result = pipeline.run_scan(a.domain, source, DNSClient(), Prober(rps=a.rps) if a.probe else None, a.workers,
                                   progress=lambda i, n: print(f"\r  хостов обработано: {i}/{n}", end="", file=sys.stderr))
    except RuntimeError as e:
        print(f"\nошибка: {e}", file=sys.stderr)
        return 1
    print(file=sys.stderr)
    store.save(result)
    print_report(store, result.domain, sys.stdout.isatty())
    return gate(store, result.domain, a.fail_on, a.fail_on_new)


if __name__ == "__main__":
    sys.exit(main())
