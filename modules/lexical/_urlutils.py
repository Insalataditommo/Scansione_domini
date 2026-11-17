"""
modules/lexical/_urlutils.py

Comment:
    Shared utilities for the lexical modules: safe URL parsing, registrable
    domain extraction, normalization, Shannon entropy computation.

    These functions have no network side effects: they are pure string
    analysis functions, therefore safe and deterministic.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple
from urllib.parse import urlparse

# TLDs considered "free" or historically associated with a high incidence of
# phishing (source: APWG, OpenPhish). Editable list.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country",
     "stream", "loan", "work", "men", "racing", "review", "party",
     "download", "science", "kim", "win"}
)

# Known URL shortener domains.
URL_SHORTENERS: frozenset[str] = frozenset(
    {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
     "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
     "s.id", "lnkd.in", "fb.me", "youtu.be", "amzn.to"}
)

# Sensitive keywords that, on non-official brand domains, are typically
# associated with phishing.
SENSITIVE_KEYWORDS: frozenset[str] = frozenset(
    {"login", "signin", "sign-in", "log-in", "verify", "verification",
     "account", "update", "secure", "security", "bank", "banking",
     "wallet", "paypal", "password", "credential", "reset", "unlock",
     "confirm", "billing", "invoice", "payment", "suspend", "alert",
     "support", "recovery", "activate", "kyc", "mfa", "2fa", "ssn",
     "iban", "card", "cvv"}
)


class ParsedURL(NamedTuple):
    """Comment: data structure with the relevant components of a URL."""
    scheme: str
    netloc: str
    registered_domain: str
    subdomain: str
    tld: str
    path: str
    query: str
    fragment: str
    is_ip: bool


def parse_url(url: str) -> ParsedURL | None:
    """Comment: parses a URL returning a ParsedURL structure.

    Input data:
        url: URL string (with or without scheme).

    Expected output:
        ParsedURL namedtuple, or None if the URL is invalid or no netloc
        can be extracted. Uses tldextract when available, otherwise a
        manual fallback.
    """
    if not url or not isinstance(url, str):
        return None

    url_stripped = url.strip()
    if "://" not in url_stripped:
        # Add a default scheme to allow parsing.
        url_stripped = "http://" + url_stripped

    try:
        parsed = urlparse(url_stripped)
    except Exception:  # noqa: BLE001
        return None

    netloc = (parsed.netloc or "").lower()
    # Strip any userinfo and port.
    host = netloc.split("@")[-1].split(":")[0]
    if not host:
        return None

    is_ip = _looks_like_ip(host)

    if is_ip:
        return ParsedURL(
            scheme=(parsed.scheme or "").lower(),
            netloc=netloc,
            registered_domain=host,
            subdomain="",
            tld="",
            path=parsed.path or "",
            query=parsed.query or "",
            fragment=parsed.fragment or "",
            is_ip=True,
        )

    registered_domain, subdomain, tld = _extract_domain(host)
    return ParsedURL(
        scheme=(parsed.scheme or "").lower(),
        netloc=netloc,
        registered_domain=registered_domain,
        subdomain=subdomain,
        tld=tld,
        path=parsed.path or "",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        is_ip=False,
    )


def _extract_domain(host: str) -> tuple[str, str, str]:
    """Comment: extracts (registered_domain, subdomain, tld) using tldextract.

    Input data:
        host: lowercased host string without userinfo/port.

    Expected output:
        tuple (registered_domain, subdomain, tld). When tldextract is
        missing, a fallback based on '.' splitting is used: less precise
        but sufficient for demos and tests.
    """
    try:
        import tldextract  # type: ignore

        ext = tldextract.extract(host)
        # registered_domain = domain + suffix
        registered = ext.registered_domain or host
        subdomain = ext.subdomain or ""
        tld = ext.suffix or ""
        if not registered:
            # host like 'localhost' or names without a TLD
            parts = host.split(".")
            if len(parts) == 1:
                registered, subdomain, tld = host, "", ""
            else:
                tld = parts[-1]
                registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
                subdomain = ".".join(parts[:-2])
        return registered, subdomain, tld
    except ImportError:
        # Simple fallback: accepts only single-component TLDs.
        parts = host.split(".")
        if len(parts) == 1:
            return host, "", ""
        if len(parts) == 2:
            return host, "", parts[-1]
        tld = parts[-1]
        registered = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])
        return registered, subdomain, tld


def _looks_like_ip(host: str) -> bool:
    """Comment: detects whether `host` is a literal IPv4 or IPv6 address.

    Input data:
        host: host string.

    Expected output:
        bool, True if host matches an IPv4 dotted-quad, a bracketed IPv6
        literal, or a colon-containing IPv6 literal.
    """
    if not host:
        return False
    # IPv4
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return True
    # IPv6 (simplified: starts with '[' or contains ':')
    if host.startswith("[") and host.endswith("]"):
        return True
    if ":" in host and re.fullmatch(r"[0-9a-fA-F:.]+", host):
        return True
    return False


def shannon_entropy(s: str) -> float:
    """Comment: computes the Shannon entropy in bits/character of a string.

    Input data:
        s: input string.

    Expected output:
        float >= 0.0; e.g. "aaaa" -> 0.0, "abcd" -> 2.0, a long random
        string -> ~4.0+.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def subdomain_depth(subdomain: str) -> int:
    """Comment: returns the depth of the subdomain chain.

    Input data:
        subdomain: subdomain string (e.g. "a.b.c" or "").

    Expected output:
        int >= 0; e.g. "" -> 0, "www" -> 1, "a.b.c" -> 3.
    """
    if not subdomain:
        return 0
    return len([p for p in subdomain.split(".") if p])


def count_subdomains(subdomain: str) -> int:
    """Comment: number of labels in the subdomain.

    Input data:
        subdomain: subdomain string.

    Expected output:
        int >= 0; semantic synonym of subdomain_depth, kept for clarity
        at the call site.
    """
    return subdomain_depth(subdomain)


def has_idn(host: str) -> bool:
    """Comment: detects whether the domain contains non-ASCII characters.

    Input data:
        host: host string.

    Expected output:
        bool, True if any character is non-ASCII or the host starts with
        the Punycode prefix "xn--".
    """
    if not host:
        return False
    return any(ord(c) > 127 for c in host) or host.startswith("xn--")


def get_punycode_labels(host: str) -> list[str]:
    """Comment: returns the Punycode-encoded labels of a host.

    Input data:
        host: host string.

    Expected output:
        list[str] of labels starting with "xn--" (Punycode), in order.
    """
    return [p for p in host.split(".") if p.startswith("xn--")]
