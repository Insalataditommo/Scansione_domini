"""
modules/content/_httputils.py

Comment:
    Shared utilities for the content and dynamic categories:
      - HTTP fetch with a desktop User-Agent, timeout, redirect handling
        and graceful failure (never raises);
      - registered-domain extraction (delegates to dns_whois._dnsutils);
      - HTML parsing helpers (BeautifulSoup when available, with a tiny
        regex-based fallback so that the module still runs without bs4).

    Every function degrades gracefully so the calling module can mark
    itself NOT_EVALUATED rather than crashing the whole analysis.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

DEFAULT_TIMEOUT = 8.0
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class HttpResult:
    """Comment: outcome of an HTTP fetch.

    Attributes:
        url:          final URL after redirects.
        status:       HTTP status code (or None on failure).
        headers:      dict of response headers (lowercased keys).
        text:         response body as text (utf-8, errors replaced).
        history:      list of intermediate URLs (one per redirect hop).
        error:        error message when the fetch failed; None on success.
    """

    def __init__(self) -> None:
        self.url: Optional[str] = None
        self.status: Optional[int] = None
        self.headers: dict[str, str] = {}
        self.text: str = ""
        self.history: list[str] = []
        self.error: Optional[str] = None


def fetch_url(url: str, timeout: float = DEFAULT_TIMEOUT, allow_redirects: bool = True) -> HttpResult:
    """Comment: fetches an URL with a desktop User-Agent.

    Input data:
        url:             URL to fetch.
        timeout:         per-request timeout in seconds.
        allow_redirects: follow 3xx redirects when True (default).

    Expected output:
        HttpResult populated on success; on any failure only `error` is
        set and the other fields keep their defaults. Never raises.
    """
    res = HttpResult()
    try:
        import requests  # type: ignore
    except ImportError:
        res.error = "libreria requests non installata (pip install requests)"
        return res

    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
            },
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=True,  # never disable TLS verification on real fetches
        )
    except requests.exceptions.RequestException as exc:  # noqa: BLE001
        res.error = f"HTTP fallito: {exc.__class__.__name__}: {exc}"
        return res
    except Exception as exc:  # noqa: BLE001
        res.error = f"Errore generico: {exc.__class__.__name__}: {exc}"
        return res

    res.url = r.url
    res.status = r.status_code
    res.headers = {k.lower(): v for k, v in r.headers.items()}
    res.text = r.text or ""
    res.history = [h.url for h in r.history]
    return res


def get_registered_domain(url: str) -> Optional[str]:
    """Comment: delegates registered-domain extraction to dns_whois._dnsutils.

    Input data:
        url: URL string.

    Expected output:
        str registered domain or None (same semantics as the original).
    """
    from modules.dns_whois._dnsutils import get_registered_domain as _grd
    return _grd(url)


def same_registered_domain(a: str, b: str) -> bool:
    """Comment: checks whether two URLs share the same registered domain.

    Input data:
        a, b: URL strings.

    Expected output:
        True when both URLs resolve to the same eTLD+1; True when either
        is empty or invalid (so that an empty/relative action is not
        flagged as external); False otherwise.
    """
    if not a or not b:
        return True
    da = get_registered_domain(a)
    db = get_registered_domain(b)
    if da is None or db is None:
        return True  # be lenient on IP / unparseable hosts
    return da.lower() == db.lower()


def parse_html(text: str):
    """Comment: parses an HTML document into a BeautifulSoup tree.

        Falls back to a minimal regex-based parser when bs4 is not
        available, exposing the same minimal API used by the content
        modules (find_all(tag, attrs=...)).

    Input data:
        text: HTML source as a string.

    Expected output:
        an object with a `find_all(tag, attrs=...)` method returning a
        list of node-like objects each exposing `get(attr)` and a
        `string`/`text` attribute. Never raises.
    """
    try:
        from bs4 import BeautifulSoup  # type: ignore
        return BeautifulSoup(text, "html.parser")
    except ImportError:
        return _MinimalHtml(text)


class _MinimalTag:
    """Comment: minimal stand-in for a BeautifulSoup Tag, used when bs4 is
        not installed. Supports get() and a .string attribute."""

    def __init__(self, tag: str, attrs: dict[str, str], text: str = "") -> None:
        self.name = tag
        self._attrs = attrs
        self.string = text or None
        self.text = text

    def get(self, attr: str, default=None):
        return self._attrs.get(attr, default)

    def find_all(self, tag, attrs=None):  # noqa: D401
        return []


class _MinimalHtml:
    """Comment: regex-based minimal HTML parser used only as a fallback
        when bs4 is unavailable. It supports find_all for the small set
        of tags the content modules query (script, form, iframe, a, img)."""

    _TAG_RE = re.compile(
        r"<(script|form|iframe|a|img)\b([^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    _ATTR_RE = re.compile(
        r'([\w-]+)\s*=\s*"([^"]*)"|([\w-]+)\s*=\s*\'([^\']*)\'|([\w-]+)\s*=\s*([^\s>]+)',
    )

    def __init__(self, text: str) -> None:
        self._text = text or ""

    def find_all(self, tag, attrs=None):
        attrs = attrs or {}
        out: list[_MinimalTag] = []
        for m in self._TAG_RE.finditer(self._text):
            tname = m.group(1).lower()
            if isinstance(tag, str) and tname != tag.lower():
                continue
            raw_attrs = self._parse_attrs(m.group(2) or "")
            if not self._attrs_match(raw_attrs, attrs):
                continue
            text = self._extract_text(tname, m.end())
            out.append(_MinimalTag(tname, raw_attrs, text))
        return out

    def get_text(self, separator: str = " ") -> str:
        # Strip tags, collapse whitespace.
        no_tags = re.sub(r"<[^>]+>", separator, self._text)
        return re.sub(r"\s+", " ", no_tags).strip()

    @staticmethod
    def _parse_attrs(s: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for am in _MinimalHtml._ATTR_RE.finditer(s):
            key = am.group(1) or am.group(3) or am.group(5)
            val = am.group(2) or am.group(4) or am.group(6) or ""
            out[key.lower()] = val
        return out

    @staticmethod
    def _attrs_match(node_attrs: dict[str, str], wanted: dict) -> bool:
        for k, v in wanted.items():
            if k not in node_attrs:
                if v is None:
                    continue
                return False
            if v is None:
                continue
            if isinstance(v, str) and v.lower() not in node_attrs[k].lower():
                return False
        return True

    def _extract_text(self, tag: str, start: int) -> str:
        # Find the matching closing tag (no nesting support, good enough
        # for our simple fallback).
        close = re.compile(rf"</{tag}\s*>", re.IGNORECASE)
        m = close.search(self._text, start)
        if not m:
            return ""
        return self._text[start:m.start()]
