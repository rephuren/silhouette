import json
import struct
import zipfile

from silhouette import meta
from silhouette.__main__ import main


def _ifd(entries, base, end="<"):
    """Собирает IFD: entries = [(тег, тип, количество, bytes значения)], данные длиннее 4 байт кладутся после таблицы."""
    n = len(entries)
    table = struct.pack(end + "H", n)
    data_off = base + 2 + n * 12 + 4
    blob = b""
    for tag, typ, count, val in entries:
        if len(val) <= 4:
            table += struct.pack(end + "HHI4s", tag, typ, count, val.ljust(4, b"\0"))
        else:
            table += struct.pack(end + "HHII", tag, typ, count, data_off + len(blob))
            blob += val
    return table + struct.pack(end + "I", 0) + blob


def make_jpeg(tmp_path, with_gps=True):
    ascii_ = lambda s: s.encode() + b"\0"  # noqa: E731
    rat = lambda *v: b"".join(struct.pack("<II", int(x * 100), 100) for x in v)  # noqa: E731
    gps_entries = [(1, 2, 2, b"N\0"), (2, 5, 3, rat(53, 54, 0)), (3, 2, 2, b"E\0"), (4, 5, 3, rat(27, 33, 0))]
    ifd0_entries = [(0x010F, 2, 6, ascii_("Canon")), (0x0131, 2, 14, ascii_("Photoshop 24.1")), (0x013B, 2, 14, ascii_("Ivan Petrov"))]
    if with_gps:
        ifd0_entries.append((0x8825, 4, 1, struct.pack("<I", 0)))
    # расчёт смещения GPS IFD: после IFD0 и его данных
    ifd0 = _ifd(ifd0_entries, 8)
    gps_off = 8 + len(ifd0)
    if with_gps:
        ifd0 = _ifd([(t, ty, c, struct.pack("<I", gps_off) if t == 0x8825 else v) for t, ty, c, v in ifd0_entries], 8)
        gps_off = 8 + len(ifd0)
    tiff = b"II*\0" + struct.pack("<I", 8) + ifd0 + (_ifd(gps_entries, gps_off) if with_gps else b"")
    seg = b"Exif\0\0" + tiff
    data = b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg + b"\xff\xd9"
    p = tmp_path / "photo.jpg"
    p.write_bytes(data)
    return p


def codes(findings):
    return {f["code"] for f in findings}


def test_jpeg_exif_person_software_and_gps(tmp_path):
    found = meta.inspect_file(make_jpeg(tmp_path))
    assert {"meta-person", "meta-software", "meta-gps"} <= codes(found)
    gps = next(f for f in found if f["code"] == "meta-gps")
    assert gps["severity"] == "high" and "53.9" in gps["message"] and "27.55" in gps["message"]


def test_jpeg_without_exif_or_gps(tmp_path):
    p = tmp_path / "plain.jpg"
    p.write_bytes(b"\xff\xd8\xff\xd9")
    assert meta.inspect_file(p) == []
    assert "meta-gps" not in codes(meta.inspect_file(make_jpeg(tmp_path, with_gps=False)))


def test_corrupt_exif_does_not_crash(tmp_path):
    good = make_jpeg(tmp_path).read_bytes()
    for cut in range(10, len(good), 7):
        (tmp_path / "x.jpg").write_bytes(good[:cut])
        meta.inspect_file(tmp_path / "x.jpg")


def make_docx(tmp_path, creator="Ivan Petrov", path_in_template=True):
    core = f'<cp:coreProperties xmlns:cp="a" xmlns:dc="b"><dc:creator>{creator}</dc:creator><cp:lastModifiedBy>ivan</cp:lastModifiedBy></cp:coreProperties>'
    tpl = "C:\\Users\\ivanp\\Templates\\Normal.dotm" if path_in_template else "Normal.dotm"
    app = f'<Properties xmlns="a"><Application>Microsoft Office Word</Application><Company>ACME LLC</Company><Template>{tpl}</Template></Properties>'
    p = tmp_path / "report.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
    return p


def test_docx_person_org_software_and_local_path(tmp_path):
    found = meta.inspect_file(make_docx(tmp_path))
    assert {"meta-person", "meta-org", "meta-software", "meta-local-path"} <= codes(found)
    assert any("ivanp" in f["message"] for f in found if f["code"] == "meta-local-path")


def test_docx_clean_template_has_no_path_finding(tmp_path):
    assert "meta-local-path" not in codes(meta.inspect_file(make_docx(tmp_path, path_in_template=False)))


def test_pdf_info_dictionary(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"%PDF-1.7\n1 0 obj<< /Author (Anna K.) /Producer (LibreOffice 7.6) /Creator (Writer) >>endobj\n")
    found = meta.inspect_file(p)
    assert {"meta-person", "meta-software"} <= codes(found)
    assert any("Anna K." in f["message"] for f in found)


def test_pdf_hex_string_author(tmp_path):
    p = tmp_path / "h.pdf"
    p.write_bytes(b"%PDF-1.4\n<< /Author <FEFF0410043D043D0430> >>\n")
    assert any("Анна" in f["message"] for f in meta.inspect_file(p))


def test_directory_walk_only_lists_files_with_findings(tmp_path):
    make_docx(tmp_path)
    (tmp_path / "notes.txt").write_text("hello")
    rows = meta.inspect_tree(tmp_path)
    assert [r["file"].endswith("report.docx") for r in rows] == [True]


def test_cli_text_json_and_fail_on(tmp_path, capsys):
    make_jpeg(tmp_path)
    assert main(["meta", str(tmp_path)]) == 0
    assert "GPS" in capsys.readouterr().out
    assert main(["meta", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["findings"]
    assert main(["meta", str(tmp_path), "--fail-on", "high"]) == 3
    assert main(["meta", str(tmp_path / "missing")]) == 1
