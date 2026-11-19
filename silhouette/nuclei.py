"""Запуск nuclei по своим хостам и разбор его JSONL в находки.

nuclei отправляет на цель запросы по шаблонам уязвимостей, поэтому опция доступна только вместе с `--probe --i-am-authorized`.
Нужен установленный nuclei (в пакет он не входит). По умолчанию исключены шаблоны с тегами dos, fuzz, bruteforce и intrusive."""
import json
import shutil
import subprocess

from .models import HIGH, INFO, LOW, MEDIUM, Finding
from .sources import valid_hostname

SEVERITY = {"critical": "critical", "high": HIGH, "medium": MEDIUM, "low": LOW, "info": INFO, "unknown": INFO}
EXCLUDE_TAGS = "dos,fuzz,bruteforce,intrusive"
MAX_FINDINGS_PER_HOST = 20


class NucleiError(RuntimeError):
    pass


class Nuclei:
    """scan(host) -> [Finding]. runner подменяется в тестах: runner(argv, timeout) -> stdout."""

    def __init__(self, binary=None, rps=5, timeout=180, templates=None, runner=None):
        self.binary = binary or shutil.which("nuclei")
        if not self.binary and runner is None:
            raise NucleiError("nuclei не найден в PATH: установите его (https://github.com/projectdiscovery/nuclei) или уберите --nuclei")
        self.rps, self.timeout, self.templates = rps, timeout, templates
        self._run = runner or self._subprocess

    @staticmethod
    def _subprocess(argv, timeout):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 список аргументов, без shell
        except subprocess.TimeoutExpired:
            raise NucleiError("nuclei не уложился во время") from None
        except OSError as e:
            raise NucleiError(f"не удалось запустить nuclei: {e.strerror}") from None
        return proc.stdout

    def argv(self, host):
        argv = [self.binary or "nuclei", "-u", f"https://{host}", "-jsonl", "-silent", "-no-color", "-disable-update-check",
                "-severity", "low,medium,high,critical", "-exclude-tags", EXCLUDE_TAGS, "-rate-limit", str(max(1, int(self.rps)))]
        if self.templates:
            argv += ["-t", self.templates]
        return argv

    def scan(self, host):
        if not valid_hostname(host):
            return []
        return parse(host, self._run(self.argv(host), self.timeout))


def parse(host, output):
    """JSONL nuclei -> находки. Строки не в JSON и чужие формы пропускаются: вывод принадлежит внешней программе."""
    out = []
    for line in (output or "").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict) or not isinstance(item.get("info"), dict):
            continue
        info = item["info"]
        tid = str(item.get("template-id", "?"))[:80]
        name = str(info.get("name", tid))[:120]
        sev = SEVERITY.get(str(info.get("severity", "unknown")).lower(), INFO)
        out.append(Finding(sev, "nuclei", f"nuclei: {name} ({tid})", host))
        if len(out) >= MAX_FINDINGS_PER_HOST:
            break
    return out


def enrich(rec, scanner):
    """Находки nuclei для хоста, который ответил на зондирование. Ошибка запуска превращается в одну находку info."""
    if rec.probe is None or rec.probe.status is None:
        return
    try:
        rec.findings += scanner.scan(rec.name)
    except NucleiError as e:
        rec.findings.append(Finding(INFO, "nuclei-error", str(e), rec.name))
