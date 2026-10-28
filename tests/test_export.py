import pytest

from silhouette import demo, export
from silhouette.__main__ import main
from silhouette.store import Store


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "d.db")
    demo.seed(Store(path))
    return path


def data_for(db, **kw):
    return export.collect(Store(db), demo.DOMAIN, **kw)


def fake(message, host="a.example"):
    return {
        "domain": "d.example",
        "summary": {"grade": "B", "hosts": 1, "resolved": 1, "findings": {"high": 1}, "tech": [("<b>nginx</b>", 2)]},
        "findings": [{"severity": "high", "host": host, "message": message, "code": "x"}],
    }


def test_collect_unknown_domain_is_none(db):
    assert export.collect(Store(db), "nope.example") is None


def test_markdown_has_summary_and_table(db):
    md = export.render_md(data_for(db))
    assert md.startswith(f"# {demo.DOMAIN}") and "| уровень | хост | сообщение |" in md and "Оценка **" in md


def test_markdown_cells_cannot_break_table_or_inject_html():
    md = export.render_md(fake("a | b\n<script>alert(1)</script>"))
    row = [ln for ln in md.splitlines() if ln.startswith("| high | a.example")][0]
    assert "\n" not in row and "a \\| b" in row and "<script>" not in md and "&lt;script&gt;" in md


def test_html_is_self_contained_and_escaped(db):
    page = export.render_html(fake('"><img src=x onerror=alert(1)>', host="<i>h</i>"))
    assert "<img src=x" not in page and "<i>h</i>" not in page and "&lt;img src=x" in page
    assert "<script" not in page.lower() and "<link" not in page.lower() and "http://" not in page and "https://" not in page
    assert "default-src 'none'" in page and "&lt;b&gt;nginx" in page


def test_html_for_demo_lists_all_findings(db):
    d = data_for(db)
    page = export.render_html(d)
    assert page.count('<td class="sev ') == len(d["findings"]) > 0


def test_min_severity_filters_findings(db):
    all_f = data_for(db, min_severity="info")["findings"]
    high = data_for(db, min_severity="high")["findings"]
    assert len(high) < len(all_f) and all(f["severity"] in ("critical", "high") for f in high)


def test_empty_findings_message():
    d = fake("x")
    d["findings"] = []
    assert "Находок выбранного уровня нет" in export.render_md(d) and "Находок выбранного уровня нет" in export.render_html(d)


def test_unknown_format_rejected(db):
    with pytest.raises(ValueError):
        export.render(data_for(db), "pdf")


def test_cli_writes_file_and_stdout(db, tmp_path, capsys):
    out = tmp_path / "r.html"
    assert main(["report", demo.DOMAIN, "--db", db, "--format", "html", "--output", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert main(["report", demo.DOMAIN, "--db", db, "--format", "md"]) == 0
    assert capsys.readouterr().out.startswith(f"# {demo.DOMAIN}")


def test_cli_missing_domain_and_gate_still_applies(db, capsys):
    assert main(["report", "none.example", "--db", db, "--format", "md"]) == 1
    assert main(["report", demo.DOMAIN, "--db", db, "--format", "md", "--fail-on", "info"]) == 3
