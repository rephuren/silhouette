"""Метаданные файлов: что документ или фото рассказывает о владельце, если выложить его как есть.

Читает EXIF из JPEG, свойства OOXML (docx, xlsx, pptx) и словарь Info из PDF без внешних зависимостей.
Ничего не отправляет по сети и не меняет файлы. Предназначено для проверки собственных файлов перед публикацией."""
import re
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .models import HIGH, INFO, LOW, MEDIUM

MAX_READ = 32 * 1024 * 1024  # больше не читаем: метаданные лежат в начале или в небольшой части контейнера
PATH_RE = re.compile(r"(?:[A-Za-z]:\\+Users\\+[^\\\s]+|/Users/[^/\s]+|/home/[^/\s]+)")
EXIF_TYPES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
EXIF_FIELDS = {
    0x010F: ("device", "производитель камеры или устройства"),
    0x0110: ("device", "модель устройства"),
    0x0131: ("software", "программа"),
    0x013B: ("person", "автор (Artist)"),
    0x8298: ("person", "владелец прав (Copyright)"),
    0xA430: ("person", "имя владельца камеры"),
    0xA431: ("serial", "серийный номер корпуса камеры"),
    0xA435: ("serial", "серийный номер объектива"),
}
OOXML_PERSON = {"creator": "автор", "lastModifiedBy": "последним изменил"}
OOXML_ORG = {"Company": "организация", "Manager": "руководитель"}
OOXML_SOFT = {"Application": "программа", "AppVersion": "версия программы"}
PDF_PERSON = {"Author": "автор"}
PDF_SOFT = {"Creator": "создано в", "Producer": "создатель PDF"}
OOXML_EXT = {".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx"}


def _finding(severity, code, message):
    return {"severity": severity, "code": code, "message": message}


def _classify(kind, label, value):
    """Единое правило серьёзности: имена и серийные номера средние, программа и организация низкие, локальные пути средние."""
    out: list[dict] = []
    value = value.strip()
    if not value:
        return out
    path = PATH_RE.search(value)
    if path:
        out.append(_finding(MEDIUM, "meta-local-path", f"{label} содержит локальный путь с именем пользователя: {path.group(0)}"))
    if kind == "person":
        out.append(_finding(MEDIUM, "meta-person", f"{label}: {value}"))
    elif kind == "serial":
        out.append(_finding(MEDIUM, "meta-serial", f"{label}: {value}"))
    elif kind == "org":
        out.append(_finding(LOW, "meta-org", f"{label}: {value}"))
    elif kind in ("software", "device"):
        out.append(_finding(LOW, "meta-software", f"{label}: {value}"))
    return out


# ---------- EXIF (JPEG) ----------

def _rational_list(buf, off, count, end):
    vals = []
    for i in range(count):
        p = off + i * 8
        if p + 8 > len(buf):
            return []
        num, den = struct.unpack(end + "II", buf[p:p + 8])
        vals.append(num / den if den else 0.0)
    return vals


def _read_ifd(tiff, offset, end):
    """Возвращает {тег: значение} одного IFD. Всё читается с проверкой границ: файл может быть повреждён или подделан."""
    tags: dict = {}
    if offset + 2 > len(tiff):
        return tags
    (count,) = struct.unpack(end + "H", tiff[offset:offset + 2])
    for i in range(min(count, 512)):
        p = offset + 2 + i * 12
        if p + 12 > len(tiff):
            break
        tag, typ, n, raw = struct.unpack(end + "HHI4s", tiff[p:p + 12])
        size = EXIF_TYPES.get(typ, 0) * n
        if not size or size > len(tiff):
            continue
        if size <= 4:
            data_off = p + 8
        else:
            (data_off,) = struct.unpack(end + "I", raw)
        if data_off + size > len(tiff):
            continue
        chunk = tiff[data_off:data_off + size]
        if typ == 2:
            tags[tag] = chunk.split(b"\0", 1)[0].decode("utf-8", "replace")
        elif typ in (5, 10):
            tags[tag] = _rational_list(tiff, data_off, n, end)
        elif typ == 4 and n == 1:
            tags[tag] = struct.unpack(end + "I", chunk)[0]
        elif typ == 3 and n == 1:
            tags[tag] = struct.unpack(end + "H", chunk)[0]
        elif typ == 7:
            tags[tag] = chunk
    return tags


def _gps(tags):
    if not all(k in tags for k in (1, 2, 3, 4)):
        return None
    lat, lon = tags[2], tags[4]
    if len(lat) != 3 or len(lon) != 3:
        return None
    to_deg = lambda v: v[0] + v[1] / 60 + v[2] / 3600  # noqa: E731
    la = to_deg(lat) * (-1 if str(tags[1]).startswith("S") else 1)
    lo = to_deg(lon) * (-1 if str(tags[3]).startswith("W") else 1)
    return round(la, 5), round(lo, 5)


def _jpeg(data):
    findings: list[dict] = []
    pos = 2
    tiff = b""
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):
            break
        (seg_len,) = struct.unpack(">H", data[pos + 2:pos + 4])
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\0\0":
            tiff = data[pos + 10:pos + 2 + seg_len]
            break
        pos += 2 + seg_len
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return findings
    end = "<" if tiff[:2] == b"II" else ">"
    (ifd0,) = struct.unpack(end + "I", tiff[4:8])
    tags = _read_ifd(tiff, ifd0, end)
    sub = {}
    for ptr in (0x8769, 0x8825):
        if isinstance(tags.get(ptr), int):
            sub[ptr] = _read_ifd(tiff, tags[ptr], end)
    merged = {**tags, **sub.get(0x8769, {})}
    for tag, (kind, label) in EXIF_FIELDS.items():
        if isinstance(merged.get(tag), str):
            findings += _classify(kind, label, merged[tag])
    where = _gps(sub.get(0x8825, {}))
    if where:
        findings.append(_finding(HIGH, "meta-gps", f"GPS-координаты съёмки: {where[0]}, {where[1]}"))
    return findings


# ---------- OOXML ----------

def _xml_fields(raw):
    out: dict[str, str] = {}
    try:
        root = ElementTree.fromstring(raw)  # внутри zip-контейнера, размер ограничен проверкой ниже
    except ElementTree.ParseError:
        return out
    for el in root.iter():
        name = el.tag.rsplit("}", 1)[-1]
        if el.text and el.text.strip():
            out[name] = el.text.strip()
    return out


def _ooxml(path):
    findings = []
    try:
        with zipfile.ZipFile(path) as z:
            for member, person, org, soft in (("docProps/core.xml", OOXML_PERSON, {}, {}), ("docProps/app.xml", {}, OOXML_ORG, OOXML_SOFT)):
                try:
                    info = z.getinfo(member)
                except KeyError:
                    continue
                if info.file_size > 1_000_000:
                    continue
                fields = _xml_fields(z.read(member))
                for key, label in person.items():
                    findings += _classify("person", label, fields.get(key, ""))
                for key, label in org.items():
                    findings += _classify("org", label, fields.get(key, ""))
                for key, label in soft.items():
                    findings += _classify("software", label, fields.get(key, ""))
                if fields.get("Template"):
                    findings += _classify("software", "шаблон", fields["Template"])
    except (zipfile.BadZipFile, OSError):
        pass
    return findings


# ---------- PDF ----------

def _pdf_string(raw):
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1", "replace")


def _pdf(data):
    findings = []
    for key, kind, label in [(k, "person", v) for k, v in PDF_PERSON.items()] + [(k, "software", v) for k, v in PDF_SOFT.items()]:
        m = re.search(rb"/" + key.encode() + rb"\s*(?:\(((?:\\.|[^\\)])*)\)|<([0-9A-Fa-f\s]+)>)", data)
        if not m:
            continue
        value = _pdf_string(m.group(1).replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")) if m.group(1) is not None \
            else _pdf_string(bytes.fromhex(re.sub(rb"\s", b"", m.group(2)).decode()))
        findings += _classify(kind, label, value)
    return findings


# ---------- общий вход ----------

def inspect_file(path):
    """Возвращает список находок по одному файлу; пустой, если метаданных нет или формат не поддерживается."""
    p = Path(path)
    ext = p.suffix.lower()
    if ext in OOXML_EXT:
        return _ooxml(p)
    data = p.open("rb").read(MAX_READ)
    if data[:2] == b"\xff\xd8":
        return _jpeg(data)
    if data[:5] == b"%PDF-":
        return _pdf(data)
    return []


def inspect_tree(root):
    """Обходит файл или папку. Возвращает [{'file': путь, 'findings': [...]}] только для файлов с находками."""
    base = Path(root)
    files = [base] if base.is_file() else sorted(f for f in base.rglob("*") if f.is_file())
    out = []
    for f in files:
        try:
            found = inspect_file(f)
        except OSError as e:
            found = [_finding(INFO, "meta-unreadable", f"не удалось прочитать: {e}")]
        if found:
            out.append({"file": str(f), "findings": found})
    return out
