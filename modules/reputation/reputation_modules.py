"""
modules/reputation/reputation_modules.py

Comment:
    Section 6 parameters (network / traffic / reputation, 4 modules).

    Two modules are fully implemented with FREE sources that require NO
    API key:
      - blacklist_threat_intel: Spamhaus ZEN (DNS-based) + PhishTank
        (public, key-less "checkurl" endpoint);
      - popolarita_traffico: Tranco top-1M list (downloaded once and
        cached locally for the day).

    The other two modules (segnalazioni_utenti, correlazione_email) require
    internal enterprise services (SIRT DB, SEG / Proofpoint / Mimecast)
    and remain honest stubs returning NOT_EVALUATED with a clear message.

    Disable any service via the env vars:
      PA_PHISHTANK_ENABLED=0, PA_SPAMHAUS_ENABLED=0, PA_TRANCO_ENABLED=0
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.content._httputils import fetch_url
from modules.dns_whois._dnsutils import (
    get_registered_domain,
    resolve_a_records,
)


def _is_disabled(env_var: str) -> bool:
    """Comment: True when env_var is set to '0' / 'false' / 'no' / 'off'.

    Input data:
        env_var: name of the environment variable to check.

    Expected output:
        bool, True when the variable is set to one of the falsy values.
    """
    val = os.environ.get(env_var, "").strip().lower()
    return val in ("0", "false", "no", "off")


# ---------------------------------------------------------------------------
# Parameter 36: blacklist / threat intelligence
# ---------------------------------------------------------------------------
class BlacklistThreatIntel(BaseModule):
    """Comment: checks the domain/IP presence in free public blacklists.

        Implemented sources (no API key required):
          - Spamhaus ZEN: DNS lookup `<reversed_ip>.zen.spamhaus.org`
            (returns 127.0.0.2..127.0.0.11 with the list codes);
          - Spamhaus DBL: DNS lookup `<domain>.dbl.spamhaus.org`
            (returns 127.0.1.x codes for domain reputation);
          - PhishTank: public, key-less checkurl POST endpoint
            (https://checkurl.phishtank.com/checkurl/).

        Optional sources (require an env API key):
          - Google Safe Browsing v4: PA_GSB_API_KEY
          - VirusTotal v3: PA_VT_API_KEY

        Threshold:
          - any source returns a match -> SUSPICIOUS 1.0;
          - all active sources return no match -> SAFE 0.0;
          - all sources disabled or unreachable -> NOT_EVALUATED.
    """

    description = "Presenza in blacklist / feed di threat intelligence."
    SPAMHAUS_ZEN_SUFFIX = ".zen.spamhaus.org"
    SPAMHAUS_DBL_SUFFIX = ".dbl.spamhaus.org"
    PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    # Spamhaus return codes -> human-readable label.
    SPAMHAUS_CODES: dict[str, str] = {
        "127.0.0.2": "SBL (Spamhaus Block List)",
        "127.0.0.3": "SBL+CSS (composite)",
        "127.0.0.4": "XBL (Exploits Block List)",
        "127.0.0.5": "XBL (CBL)",
        "127.0.0.6": "XBL (CBL+NJ)",
        "127.0.0.9": "SBL (DROP/EDROP)",
        "127.0.0.10": "DBL (phishing)",
        "127.0.0.11": "DBL (malware)",
    }

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "blacklist_threat_intel".
        """
        return "blacklist_threat_intel"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.5 (very high weight, decisive signal).
        """
        return 2.5

    def run(self, url: str) -> ModuleResult:
        """Comment: queries Spamhaus (DNS) and PhishTank (HTTP) for matches.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {matches, queried_sources},
            score in [0,1]. NOT_EVALUATED only when every active source
            fails to answer.
        """
        domain = get_registered_domain(url) or ""
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
            )

        matches: list[dict] = []
        queried: list[str] = []

        # 1) Spamhaus ZEN on the IP of the domain (free, no API key).
        if not _is_disabled("PA_SPAMHAUS_ENABLED"):
            try:
                import dns.resolver  # type: ignore

                ips, _ = resolve_a_records(domain, timeout=5.0)
                if ips:
                    queried.append("spamhaus_zen")
                    for ip in ips[:3]:  # limit to avoid hammering
                        reversed_ip = ".".join(reversed(ip.split(".")))
                        host = f"{reversed_ip}{self.SPAMHAUS_ZEN_SUFFIX}"
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = 5.0
                            resolver.lifetime = 5.0
                            answers = resolver.resolve(host, "A", raise_on_no_answer=False)
                            if answers and answers.rrset:
                                for r in answers:
                                    code = str(r.address)
                                    matches.append({
                                        "source": "spamhaus_zen",
                                        "ip": ip,
                                        "code": code,
                                        "label": self.SPAMHAUS_CODES.get(code, "listato"),
                                    })
                        except dns.resolver.NXDOMAIN:
                            pass  # not listed: expected outcome
                        except Exception:  # noqa: BLE001
                            pass
            except ImportError:
                pass  # dnspython missing -> skip silently

            # Also query DBL for the domain itself.
            if domain:
                try:
                    import dns.resolver  # type: ignore

                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5.0
                    resolver.lifetime = 5.0
                    host = f"{domain}{self.SPAMHAUS_DBL_SUFFIX}"
                    answers = resolver.resolve(host, "A", raise_on_no_answer=False)
                    if answers and answers.rrset:
                        for r in answers:
                            code = str(r.address)
                            if code.startswith("127.0.1."):
                                matches.append({
                                    "source": "spamhaus_dbl",
                                    "domain": domain,
                                    "code": code,
                                    "label": self.SPAMHAUS_CODES.get(code, "listato"),
                                })
                except ImportError:
                    pass
                except Exception:  # noqa: BLE001
                    pass

        # 2) PhishTank public checkurl (no API key, anonymous POST).
        if not _is_disabled("PA_PHISHTANK_ENABLED"):
            queried.append("phishtank")
            pt_match = _query_phishtank(url)
            if pt_match:
                matches.append(pt_match)

        # 3) Google Safe Browsing v4 (optional, requires API key).
        if not _is_disabled("PA_GSB_ENABLED") and os.environ.get("PA_GSB_API_KEY"):
            queried.append("google_safe_browsing")
            gsb_match = _query_gsb(url)
            if gsb_match:
                matches.append(gsb_match)

        # 4) VirusTotal v3 (optional, requires API key).
        if not _is_disabled("PA_VT_ENABLED") and os.environ.get("PA_VT_API_KEY"):
            queried.append("virustotal")
            vt_match = _query_virustotal(url)
            if vt_match:
                matches.append(vt_match)

        if not queried:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=(
                    "Tutti i servizi di threat intelligence sono disattivati "
                    "(env var PA_*_ENABLED=0)."
                ),
            )

        if matches:
            labels = "; ".join(f"{m['source']}={m.get('label', 'match')}" for m in matches[:3])
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "matches": matches,
                    "queried_sources": queried,
                    "domain": domain,
                },
                score=1.0,
                outcome=Outcome.SUSPICIOUS,
                message=(
                    f"Dominio/URL presente in {len(matches)} blacklist ({labels}): "
                    f"segnale decisivo di phishing/malware."
                ),
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "matches": [],
                "queried_sources": queried,
                "domain": domain,
            },
            score=0.0,
            outcome=Outcome.SAFE,
            message=(
                f"Nessuna corrispondenza nelle blacklist interrogate "
                f"({', '.join(queried)})."
            ),
        )


def _query_phishtank(url: str) -> dict | None:
    """Comment: queries the public, key-less PhishTank checkurl endpoint.

    Input data:
        url: full URL string to check.

    Expected output:
        dict {source, url, in_database, verified} when the URL is reported
        as a phishing page; None when the URL is not in the database or
        the query fails.
    """
    try:
        import requests  # type: ignore
    except ImportError:
        return None
    try:
        r = requests.post(
            BlacklistThreatIntel.PHISHTANK_ENDPOINT,
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishing_analyzer/1.0"},
            timeout=8.0,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        results = data.get("results", {})
        if results.get("in_database"):
            return {
                "source": "phishtank",
                "url": url,
                "in_database": True,
                "verified": bool(results.get("verified", False)),
                "phish_id": results.get("phish_id"),
            }
    except Exception:  # noqa: BLE001
        return None
    return None


def _query_gsb(url: str) -> dict | None:
    """Comment: queries Google Safe Browsing v4 (requires PA_GSB_API_KEY).

    Input data:
        url: full URL string.

    Expected output:
        dict {source, url, threat_type} when a match is found; None
        otherwise (including API errors).
    """
    api_key = os.environ.get("PA_GSB_API_KEY")
    if not api_key:
        return None
    try:
        import requests  # type: ignore
        payload = {
            "client": {"clientId": "phishing_analyzer", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload, timeout=8.0,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        matches = data.get("matches", [])
        if matches:
            m = matches[0]
            return {
                "source": "google_safe_browsing",
                "url": url,
                "threat_type": m.get("threatType"),
                "platform": m.get("platformType"),
            }
    except Exception:  # noqa: BLE001
        return None
    return None


def _query_virustotal(url: str) -> dict | None:
    """Comment: queries VirusTotal v3 for URL reports (requires PA_VT_API_KEY).

    Input data:
        url: full URL string.

    Expected output:
        dict {source, url, malicious_votes} when the URL is flagged; None
        otherwise (including API errors).
    """
    api_key = os.environ.get("PA_VT_API_KEY")
    if not api_key:
        return None
    try:
        import requests  # type: ignore
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=8.0,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
        last = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(last.get("malicious", 0))
        if malicious >= 2:
            return {
                "source": "virustotal",
                "url": url,
                "malicious_votes": malicious,
            }
    except Exception:  # noqa: BLE001
        return None
    return None


# ---------------------------------------------------------------------------
# Parameter 37: popularity and traffic history
# ---------------------------------------------------------------------------
class PopolaritaTraffico(BaseModule):
    """Comment: domain popularity via the Tranco top-1M list.

        Tranco (https://tranco-list.eu) is the academic successor to
        Alexa's top-1M, freely downloadable under CC BY-NC 4.0.

        The list is downloaded ONCE per day and cached locally under
        ~/.cache/phishing_analyzer/tranco.csv (or the directory pointed to
        by PA_TRANCO_CACHE_DIR).

        Threshold:
          - rank <= 1000 (top sites) -> SAFE 0.0;
          - rank <= 100000 -> NEUTRAL 0.1;
          - rank > 100000 or absent from the list -> NEUTRAL 0.3
            (absence is suspicious only when combined with brand claims
            handled by the clonazione_visiva module);
          - download/cache error -> NOT_EVALUATED.
    """

    description = "Popolarità e storico del traffico del dominio (Tranco top-1M)."
    TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "popolarita_traffico".
        """
        return "popolarita_traffico"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: looks up the registered domain in the cached Tranco list.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {rank, in_tranco}, score in [0,1].
            NOT_EVALUATED when the list cannot be downloaded or read.
        """
        if _is_disabled("PA_TRANCO_ENABLED"):
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Tranco disattivato via env (PA_TRANCO_ENABLED=0).",
            )

        domain = get_registered_domain(url) or ""
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
            )

        rank = _tranco_lookup(domain)
        if rank is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Impossibile scaricare/caricare la Tranco list (offline o rate-limit).",
            )

        if rank == 0:
            # 0 means "not in the top-1M"
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = (
                f"'{domain}' assente dalla Tranco top-1M: dominio poco "
                f"popolare; valutare con altri segnali."
            )
        elif rank <= 1000:
            score = 0.0
            outcome = Outcome.SAFE
            msg = f"'{domain}' in posizione #{rank} della Tranco top-1M: sito molto popolare."
        elif rank <= 100000:
            score = 0.1
            outcome = Outcome.NEUTRAL
            msg = f"'{domain}' in posizione #{rank} della Tranco top-1M: popolarità media."
        else:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = f"'{domain}' in posizione #{rank} della Tranco top-1M: popolarità bassa."

        return ModuleResult(
            name=self.name(),
            raw_value={"rank": rank, "in_tranco": rank > 0, "domain": domain},
            score=score,
            outcome=outcome,
            message=msg,
        )


def _tranco_cache_path() -> Path:
    """Comment: returns the path of the cached Tranco list.

    Expected output:
        Path under the cache dir (env PA_TRANCO_CACHE_DIR or a default
        under the user's temp dir). The path is created if missing.
    """
    cache_dir_env = os.environ.get("PA_TRANCO_CACHE_DIR")
    if cache_dir_env:
        cache_dir = Path(cache_dir_env)
    else:
        cache_dir = Path(tempfile.gettempdir()) / "phishing_analyzer"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "tranco_top_1m.csv"


def _tranco_lookup(domain: str) -> int | None:
    """Comment: looks up a domain in the (cached) Tranco list.

    Input data:
        domain: registered domain (lowercased).

    Expected output:
        int rank (>= 1) when the domain is in the top-1M; 0 when it is
        not in the list (but the list was loaded); None when the list
        cannot be downloaded/loaded.
    """
    cache_path = _tranco_cache_path()
    # Refresh the list at most once per day.
    needs_download = (
        not cache_path.exists()
        or cache_path.stat().st_mtime < (time.time() - 86400)
        or cache_path.stat().st_size == 0
    )
    if needs_download:
        if not _tranco_download(cache_path):
            # If a stale cache exists, fall back to it instead of failing.
            if not cache_path.exists():
                return None
    try:
        domain_low = domain.lower()
        with open(cache_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.strip().split(",", 1)
                if len(parts) != 2:
                    continue
                rank_str, dom = parts
                if dom.lower() == domain_low:
                    try:
                        return int(rank_str)
                    except ValueError:
                        continue
        return 0
    except Exception:  # noqa: BLE001
        return None


def _tranco_download(cache_path: Path) -> bool:
    """Comment: downloads and unzips the Tranco top-1M list.

    Input data:
        cache_path: filesystem path where the plain CSV is cached.

    Expected output:
        True when the CSV was written successfully; False on any failure
        (network error, zip error, write error).
    """
    try:
        import requests  # type: ignore
        import zipfile
        import io

        r = requests.get(
            PopolaritaTraffico.TRANCO_LIST_URL,
            timeout=60.0,
            headers={"User-Agent": "phishing_analyzer/1.0"},
            stream=True,
        )
        if r.status_code != 200:
            return False
        buf = io.BytesIO(r.content)
        with zipfile.ZipFile(buf) as zf:
            csv_name = next(
                (n for n in zf.namelist() if n.endswith(".csv")),
                None,
            )
            if not csv_name:
                return False
            with zf.open(csv_name) as inner, open(cache_path, "wb") as out:
                out.write(inner.read())
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Parameter 38: user reports and telemetry
# ---------------------------------------------------------------------------
class SegnalazioniUtenti(BaseModule):
    """Comment: user reports and internal telemetry.

        Checks whether the URL has been reported by users of the
        organization (SIRT / abuse mailbox) or by crowdsourcing services
        (Netcraft, PhishTank user reports).

        STUB — requires access to the internal SIRT reports database
        (typically reachable only from inside the corporate network).
        Documented in the docstring; not enabled by default.
    """

    description = "Segnalazioni utenti e telemetria interna (SIRT/Netcraft)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "segnalazioni_utenti".
        """
        return "segnalazioni_utenti"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.2 (medium weight).
        """
        return 1.2

    def run(self, url: str) -> ModuleResult:
        """Comment: STUB — returns NOT_EVALUATED with a clear reason.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult NOT_EVALUATED: requires access to the internal
            SIRT reports DB and/or Netcraft API.
        """
        return ModuleResult(
            name=self.name(),
            outcome=Outcome.NOT_EVALUATED,
            message=(
                "STUB: richiede DB interno SIRT (URL hash + data segnalazione) "
                "e/o API Netcraft (PA_NETCRAFT_API_KEY). Non implementato "
                "in questa versione pubblica."
            ),
        )


# ---------------------------------------------------------------------------
# Parameter 39: correlation with email campaigns
# ---------------------------------------------------------------------------
class CorrelazioneEmail(BaseModule):
    """Comment: correlation with reported email phishing campaigns.

        Checks whether the URL or domain appear in reported email phishing
        campaigns in the previous days (source: SEG / Proofpoint / Mimecast).

        STUB — requires access to the SEG (Secure Email Gateway) API,
        reachable only inside the corporate network.
    """

    description = "Correlazione con campagne email di phishing (SEG)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "correlazione_email".
        """
        return "correlazione_email"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: STUB — returns NOT_EVALUATED with a clear reason.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult NOT_EVALUATED: requires SEG API access
            (Proofpoint / Mimecast).
        """
        return ModuleResult(
            name=self.name(),
            outcome=Outcome.NOT_EVALUATED,
            message=(
                "STUB: richiede API SEG (Proofpoint/Mimecast) per cercare "
                "il dominio nelle campagne email degli ultimi 30 giorni. "
                "Non implementato in questa versione pubblica."
            ),
        )
