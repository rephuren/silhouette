"""Выгрузка отчёта по последнему скану в один файл: Markdown или самодостаточный HTML."""
import html
import re

from .models import SEVERITY_ORDER

FORMATS = ("text", "md", "html")

CSS = (
    ":root{--bg:#050505;--panel:#0a0a0a;--line:#1a1a1a;--text:#e8e8e8;--dim:#8a8a8a;--red:#b3000f}"
    "html{background:var(--bg)}body{margin:0 auto;max-width:900px;padding:24px 16px;color:var(--text);background:var(--bg);"
    'font:14px/1.5 "SF Mono",Menlo,Consolas,monospace}h1{font-size:22px;margin:0 0 4px}h1::before{content:"▓ ";color:var(--red)}'
    ".meta{color:var(--dim);margin:0 0 20px}table{width:100%;border-collapse:collapse}"
    "td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}"
    "th{color:var(--dim);font-weight:400}.sev{white-space:nowrap}.critical,.high{color:var(--red)}.low,.info{color:var(--dim)}"
)
CSP = "default-src 'none'; style-src 'unsafe-inline'"


def collect(store, domain, min_severity="low"):
    ids = store.scan_ids(domain)
    if not ids:
        return None
    sid = ids[-1]
    limit = SEVERITY_ORDER.index(min_severity)
    return {
        "domain": domain,
        "summary": store.summary(sid),
        "findings": [f for f in store.findings(sid) if SEVERITY_ORDER.index(f["severity"]) <= limit],
    }


def _md_cell(text):
    """Ячейка таблицы Markdown: без переводов строк, вертикальной черты и HTML-разметки."""
    text = re.sub(r"\s+", " ", str(text))
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_md(data):
    sm = data["summary"]
    lines = [
        f"# {_md_cell(data['domain'])}",
        "",
        f"Оценка **{sm['grade']}**, хостов {sm['hosts']} (отвечают {sm['resolved']}).",
        "",
        "| уровень | число |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in sm["findings"].items()),
        "",
        "## Находки",
        "",
    ]
    if data["findings"]:
        lines += ["| уровень | хост | сообщение |", "|---|---|---|"]
        lines += [f"| {f['severity']} | {_md_cell(f['host'] or data['domain'])} | {_md_cell(f['message'])} |" for f in data["findings"]]
    else:
        lines.append("Находок выбранного уровня нет.")
    if sm["tech"]:
        lines += ["", "## Технологии", "", ", ".join(f"{_md_cell(n)} ×{k}" for n, k in sm["tech"][:10])]
    return "\n".join(lines) + "\n"


def render_html(data):
    e = html.escape
    sm = data["summary"]
    rows = "".join(
        f'<tr><td class="sev {e(f["severity"])}">{e(f["severity"])}</td><td>{e(f["host"] or data["domain"])}</td><td>{e(f["message"])}</td></tr>'
        for f in data["findings"]
    ) or '<tr><td colspan="3">Находок выбранного уровня нет.</td></tr>'
    counts = " · ".join(f"{e(k)} {v}" for k, v in sm["findings"].items())
    tech = ", ".join(f"{e(n)} ×{k}" for n, k in sm["tech"][:10])
    return (
        f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>{e(data["domain"])}: отчёт</title>'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}"><style>{CSS}</style></head><body>'
        f"<h1>{e(data['domain'])}</h1>"
        f'<p class="meta">оценка {e(sm["grade"])} · хостов {sm["hosts"]} (отвечают {sm["resolved"]}) · {counts}</p>'
        f"<table><tr><th>уровень</th><th>хост</th><th>сообщение</th></tr>{rows}</table>"
        + (f'<p class="meta">технологии: {tech}</p>' if tech else "")
        + "</body></html>\n"
    )


def render(data, fmt):
    if fmt == "md":
        return render_md(data)
    if fmt == "html":
        return render_html(data)
    raise ValueError(f"неизвестный формат: {fmt}")
