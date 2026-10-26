import pytest

from silhouette import demo
from silhouette.__main__ import main
from silhouette.gate import EXIT_FINDINGS, EXIT_OK, at_least, decide
from silhouette.store import Store


def f(sev):
    return {"severity": sev, "code": "x", "message": "m", "host": "h"}


def test_at_least_filters_by_threshold():
    items = [f("critical"), f("high"), f("medium"), f("low"), f("info")]
    assert len(at_least(items, "high")) == 2
    assert len(at_least(items, "info")) == 5
    assert at_least(items, "none") == [] and at_least(items, None) == []


def test_at_least_rejects_unknown_threshold():
    with pytest.raises(ValueError):
        at_least([f("high")], "huge")


@pytest.fixture()
def demo_db(tmp_path):
    path = str(tmp_path / "demo.db")
    store = Store(path)
    demo.seed(store)  # два скана corp.example: во втором есть новые и исправленные находки
    return path, store


def test_decide_no_scans_is_ok(tmp_path):
    assert decide(Store(str(tmp_path / "e.db")), "none.example", "low") == (EXIT_OK, [])


def test_fail_on_counts_all_findings_of_last_scan(demo_db):
    _, store = demo_db
    code, reasons = decide(store, demo.DOMAIN, fail_on="high")
    assert code == EXIT_FINDINGS and "high" in reasons[0]
    assert decide(store, demo.DOMAIN, fail_on="none") == (EXIT_OK, [])
    assert decide(store, demo.DOMAIN) == (EXIT_OK, [])


def test_fail_on_new_looks_only_at_findings_that_appeared(demo_db):
    _, store = demo_db
    diff = store.diff(demo.DOMAIN)
    new_sev = {x["severity"] for x in diff["new_findings"]}
    assert "high" in new_sev  # во втором демо-скане есть новая находка уровня high
    code, reasons = decide(store, demo.DOMAIN, fail_on_new="high")
    assert code == EXIT_FINDINGS and "новых" in reasons[0]
    assert decide(store, demo.DOMAIN, fail_on_new="critical") == (EXIT_OK, [])


def test_fail_on_new_with_single_scan_is_ok(tmp_path):
    store = Store(str(tmp_path / "one.db"))
    from silhouette.pipeline import run_scan

    dns, prober, source = demo.build(1)
    store.save(run_scan(demo.DOMAIN, source, dns, prober, workers=1))
    assert store.diff(demo.DOMAIN) is None
    assert decide(store, demo.DOMAIN, fail_on_new="low")[0] == EXIT_OK


def test_cli_report_exit_codes(demo_db, capsys):
    path, _ = demo_db
    assert main(["report", demo.DOMAIN, "--db", path, "--no-color"]) == 0
    assert main(["report", demo.DOMAIN, "--db", path, "--no-color", "--fail-on", "high"]) == EXIT_FINDINGS
    assert "порог превышен" in capsys.readouterr().err
    assert main(["report", demo.DOMAIN, "--db", path, "--no-color", "--fail-on", "none"]) == 0
    assert main(["report", demo.DOMAIN, "--db", path, "--no-color", "--fail-on-new", "critical"]) == 0


def test_cli_rejects_unknown_threshold(demo_db):
    path, _ = demo_db
    with pytest.raises(SystemExit) as e:
        main(["report", demo.DOMAIN, "--db", path, "--fail-on", "huge"])
    assert e.value.code == 2
