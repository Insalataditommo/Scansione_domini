"""
modules/dns_whois/_dnsutils.py

Comment:
    Shared utilities for the dns_whois category:
      - extraction of the registered domain from a URL (via tldextract when
        available, with a manual fallback that handles common TLDs);
      - WHOIS query via python-whois with normalization of the messy return
        types (creation_date / expiration_date can be lists, datetimes or
        strings depending on the TLD);
      - DNS queries via dnspython with graceful degradation when the library
        is not installed or the query fails.

    Every function degrades gracefully: on any failure it returns None (or
    an empty structure) so that the calling module can mark itself as
    NOT_EVALUATED rather than crashing the whole analysis.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Registered-domain extraction
# ---------------------------------------------------------------------------
def get_registered_domain(url: str) -> Optional[str]:
    """Comment: extracts the registered domain (eTLD+1) from a URL.

        Uses tldextract when available; otherwise falls back to a manual
        parser that handles the common case of `<sld>.<tld>` and the most
        frequent two-part TLDs (.co.uk, .com.br, etc.).

    Input data:
        url: full URL string.

    Expected output:
        str like "example.com" (lowercase, no subdomain) or None when the
        URL has no usable host (e.g. an IP literal or a malformed URL).
    """
    host = _get_host(url)
    if not host:
        return None
    # IP literal -> not a registered domain.
    try:
        socket.inet_aton(host)
        return None
    except OSError:
        pass

    try:
        import tldextract  # type: ignore

        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None
    except ImportError:
        pass

    # Manual fallback: handle the most common cases.
    parts = host.split(".")
    if len(parts) <= 2:
        return host.lower() if parts else None
    # Two-part TLD heuristic (cheap, not exhaustive).
    two_part_tlds = {
        "co.uk", "ac.uk", "gov.uk", "org.uk", "com.br", "org.br",
        "com.au", "net.au", "co.jp", "co.kr", "co.in", "com.cn",
        "com.tw", "com.hk", "com.sg", "co.za",
    }
    if len(parts) >= 3 and ".".join(parts[-2:]).lower() in two_part_tlds:
        return ".".join(parts[-3:]).lower()
    return ".".join(parts[-2:]).lower()


def _get_host(url: str) -> Optional[str]:
    """Comment: extracts the hostname (lowercased) from a URL.

    Input data:
        url: URL string, with or without scheme.

    Expected output:
        str hostname or None when the URL is invalid.
    """
    if not url or not isinstance(url, str):
        return None
    s = url.strip()
    if "://" not in s:
        s = "https://" + s
    try:
        return (urlparse(s).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# WHOIS query (python-whois)
# ---------------------------------------------------------------------------
class WhoisInfo:
    """Comment: normalized WHOIS record (None on every field that could not
    be retrieved)."""

    def __init__(self) -> None:
        self.creation_date: Optional[datetime] = None
        self.expiration_date: Optional[datetime] = None
        self.updated_date: Optional[datetime] = None
        self.registrar: Optional[str] = None
        self.registrant_name: Optional[str] = None
        self.registrant_org: Optional[str] = None
        self.registrant_email: Optional[str] = None
        self.registrant_country: Optional[str] = None
        self.raw_text: Optional[str] = None
        self.error: Optional[str] = None


def query_whois(domain: str, timeout: float = 8.0) -> WhoisInfo:
    """Comment: runs a WHOIS query and normalizes the result.

    Input data:
        domain: registered domain (eTLD+1) like "example.com".
        timeout: socket timeout in seconds.

    Expected output:
        WhoisInfo with creation_date / expiration_date / registrar /
        registrant_* filled when available; on any failure (library not
        installed, TLD without WHOIS, rate-limit, etc.) the `error` field
        is populated and all other fields remain None.
    """
    info = WhoisInfo()
    try:
        import whois  # type: ignore
    except ImportError:
        info.error = "libreria python-whois non installata (pip install python-whois)"
        return info

    try:
        # python-whois uses its own socket timeout via the NIC handler.
        if hasattr(whois, "socket"):
            whois.socket.setdefaulttimeout(timeout)  # type: ignore[attr-defined]
        w = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        info.error = f"WHOIS fallito: {exc.__class__.__name__}: {exc}"
        return info

    info.creation_date = _coerce_date(w.get("creation_date")) if hasattr(w, "get") else None
    info.expiration_date = _coerce_date(w.get("expiration_date")) if hasattr(w, "get") else None
    info.updated_date = _coerce_date(w.get("updated_date")) if hasattr(w, "get") else None
    info.registrar = w.get("registrar") if hasattr(w, "get") else None
    info.registrant_name = w.get("name") if hasattr(w, "get") else None
    info.registrant_org = w.get("org") if hasattr(w, "get") else None
    info.registrant_email = w.get("email") if hasattr(w, "get") else None
    info.registrant_country = w.get("country") if hasattr(w, "get") else None
    info.raw_text = w.get("text") if hasattr(w, "get") else None
    # Normalize the registrant email: python-whois can return a list.
    if isinstance(info.registrant_email, list):
        info.registrant_email = info.registrant_email[0] if info.registrant_email else None
    # If creation_date is still missing but we have raw text, leave a hint.
    return info


def _coerce_date(value) -> Optional[datetime]:
    """Comment: normalizes a date field from python-whois.

        The library returns either a datetime, a list of datetimes, or a
        string depending on the TLD server. We pick the earliest valid
        datetime (creation) or the latest (expiration).

    Input data:
        value: whatever python-whois put in the field.

    Expected output:
        timezone-aware datetime (UTC) or None when no usable date is found.
    """
    if value is None:
        return None
    candidates: list[datetime] = []
    if isinstance(value, list):
        for v in value:
            dt = _one_date(v)
            if dt is not None:
                candidates.append(dt)
    else:
        dt = _one_date(value)
        if dt is not None:
            candidates.append(dt)
    if not candidates:
        return None
    dt = min(candidates)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _one_date(value) -> Optional[datetime]:
    """Comment: parses a single date value from python-whois.

    Input data:
        value: datetime, string (multiple formats), or anything else.

    Expected output:
        datetime or None when the value cannot be parsed.
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d %b %Y",
            "%Y.%m.%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value.strip(), fmt)
                return dt
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            return None
    return None


# ---------------------------------------------------------------------------
# DNS queries (dnspython)
# ---------------------------------------------------------------------------
def resolve_a_records(domain: str, timeout: float = 5.0) -> tuple[list[str], list[int]]:
    """Comment: resolves the A records of a domain and their TTLs.

    Input data:
        domain: registered domain.
        timeout: DNS timeout in seconds.

    Expected output:
        tuple (list_of_ipv4_strings, list_of_ttls_int_seconds); both lists
        are empty on any failure (library missing, NXDOMAIN, etc.).
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return [], []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if not answers or not answers.rrset:
            return [], []
        ips = [r.address for r in answers]
        ttls = [int(answers.rrset.ttl)] * len(ips)
        return ips, ttls
    except Exception:  # noqa: BLE001
        return [], []


def resolve_txt_records(domain: str, timeout: float = 5.0) -> list[str]:
    """Comment: resolves the TXT records of a domain.

    Input data:
        domain: registered domain.

    Expected output:
        list[str] of TXT record values (each record concatenated into a
        single string); empty list on any failure.
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout + 3.0  # safety margin for TCP retries
        # Some zones (e.g. google.com) have many TXT records that exceed the
        # 512-byte UDP limit. Force TCP to receive the full answer set;
        # dnspython automatically retries on truncation, but some resolvers
        # silently drop the truncated tail instead.
        answers = resolver.resolve(domain, "TXT", raise_on_no_answer=False, tcp=True)
        if not answers or not answers.rrset:
            return []
        out: list[str] = []
        for r in answers:
            # TXT records are lists of byte-strings in dnspython; decode
            # each chunk and concatenate (a single TXT record can span
            # multiple strings when > 255 bytes).
            parts = [s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                     for s in r.strings]
            out.append("".join(parts))
        return out
    except Exception:  # noqa: BLE001
        return []


def resolve_mx_records(domain: str, timeout: float = 5.0) -> list[tuple[int, str]]:
    """Comment: resolves the MX records of a domain.

    Input data:
        domain: registered domain.

    Expected output:
        list of (preference, exchange_host) tuples sorted by preference;
        empty list on any failure.
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        if not answers or not answers.rrset:
            return []
        out: list[tuple[int, str]] = []
        for r in answers:
            out.append((int(r.preference), str(r.exchange).rstrip(".")))
        return sorted(out, key=lambda x: x[0])
    except Exception:  # noqa: BLE001
        return []


def resolve_dnskey(domain: str, timeout: float = 5.0) -> bool:
    """Comment: checks whether a DNSKEY record exists for the domain.

    Input data:
        domain: registered domain.

    Expected output:
        True when at least one DNSKEY record is present (i.e. the zone is
        signed); False otherwise (including any failure).
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        return bool(answers and answers.rrset)
    except Exception:  # noqa: BLE001
        return False


def dnssec_validated(domain: str, timeout: float = 5.0) -> bool:
    """Comment: checks whether a DNS A query for the domain is validated
        (AD bit set) by the local resolver.

    Input data:
        domain: registered domain.

    Expected output:
        True when the AD (Authenticated Data) flag is set on the response
        (i.e. DNSSEC validation succeeded); False otherwise.
    """
    try:
        import dns.resolver  # type: ignore
        import dns.flags  # type: ignore
    except ImportError:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.set_flags(0x1000)  # AD bit (request DNSSEC, ask for validation)
        answers = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if answers is None:
            return False
        # The AD bit lives on the response flags.
        try:
            return bool(dns.flags.AD & answers.response.flags)  # type: ignore[attr-defined]
        except AttributeError:
            return False
    except Exception:  # noqa: BLE001
        return False
