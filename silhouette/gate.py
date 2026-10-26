"""Решение «падать ли в CI»: порог по серьёзности для всех находок последнего скана или только для новых."""
from .models import SEVERITY_ORDER

EXIT_OK, EXIT_FINDINGS = 0, 3


def at_least(findings, threshold):
    """Находки не ниже порога. Порог none отключает проверку."""
    if threshold in (None, "none"):
        return []
    if threshold not in SEVERITY_ORDER:
        raise ValueError(f"порог {threshold!r}: ожидается одно из {', '.join(SEVERITY_ORDER)} или none")
    limit = SEVERITY_ORDER.index(threshold)
    return [f for f in findings if SEVERITY_ORDER.index(f["severity"]) <= limit]


def decide(store, domain, fail_on=None, fail_on_new=None):
    """Возвращает (код, причины). Код 3 означает «порог превышен»; 0, если порогов нет или всё в норме."""
    ids = store.scan_ids(domain)
    if not ids:
        return EXIT_OK, []
    reasons = []
    hit = at_least(store.findings(ids[-1]), fail_on)
    if hit:
        reasons.append(f"находок не ниже {fail_on}: {len(hit)}")
    if fail_on_new not in (None, "none"):
        diff = store.diff(domain)
        new = at_least(diff["new_findings"], fail_on_new) if diff else []
        if new:
            reasons.append(f"новых находок не ниже {fail_on_new}: {len(new)}")
    return (EXIT_FINDINGS if reasons else EXIT_OK), reasons
