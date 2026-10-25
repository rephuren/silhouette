from dataclasses import dataclass, field

CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
SEVERITY_WEIGHT = {CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0}
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    host: str | None = None

    def as_dict(self):
        return {"severity": self.severity, "code": self.code, "message": self.message, "host": self.host}


@dataclass
class DNSResult:
    cnames: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    status: str = "ok"  # ok | nodata | nxdomain | dangling | error


@dataclass
class ProbeResult:
    scheme: str | None = None
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: str = ""
    title: str = ""
    tls_error: str | None = None
    tls_days_left: int | None = None
    tls_issuer: str | None = None
    error: str | None = None


@dataclass
class HostRecord:
    name: str
    dns: DNSResult = field(default_factory=DNSResult)
    issuers: list = field(default_factory=list)
    first_seen: str | None = None
    last_not_after: str | None = None
    wildcard: bool = False
    probe: ProbeResult | None = None
    tech: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def score(self):
        return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in self.findings))


@dataclass
class ScanResult:
    domain: str
    started: float
    finished: float
    probed: bool
    hosts: list = field(default_factory=list)
    domain_findings: list = field(default_factory=list)
