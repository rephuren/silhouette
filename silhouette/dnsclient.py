"""DNS: тонкая обёртка над dnspython и разбор цепочки CNAME. Клиент подменяем в тестах."""
import dns.exception
import dns.resolver

from .models import DNSResult

MAX_CHAIN = 8
FALLBACK_NAMESERVERS = ["1.1.1.1", "9.9.9.9"]


class DNSClient:
    """lookup(name, rtype) -> (status, [значения]); status: ok | nxdomain | noanswer | error."""

    def __init__(self, timeout=4.0, nameservers=None):
        try:
            self.resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:  # контейнер или система без resolv.conf: берём публичные резолверы
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = list(FALLBACK_NAMESERVERS)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    def lookup(self, name, rtype):
        try:
            answer = self.resolver.resolve(name, rtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            return "nxdomain", []
        except dns.resolver.NoAnswer:
            return "noanswer", []
        except (dns.exception.DNSException, OSError):
            return "error", []
        values = []
        for r in answer:
            if rtype == "TXT":
                values.append(b"".join(r.strings).decode("utf-8", "replace"))
            elif rtype == "CNAME":
                values.append(str(r.target).rstrip(".").lower())
            else:
                values.append(r.to_text())
        return "ok", values


def resolve_host(dns_client, name) -> DNSResult:
    cnames, cur = [], name
    for _ in range(MAX_CHAIN):
        status, values = dns_client.lookup(cur, "CNAME")
        if status == "ok" and values:
            cur = values[0]
            cnames.append(cur)
            continue
        if status == "nxdomain":
            return DNSResult(cnames, [], "dangling" if cnames else "nxdomain")
        break
    a_status, a = dns_client.lookup(cur, "A")
    _, aaaa = dns_client.lookup(cur, "AAAA")
    ips = sorted(set(a + aaaa))
    if a_status == "nxdomain":
        return DNSResult(cnames, [], "dangling" if cnames else "nxdomain")
    if ips:
        return DNSResult(cnames, ips, "ok")
    return DNSResult(cnames, [], "error" if a_status == "error" else "nodata")
