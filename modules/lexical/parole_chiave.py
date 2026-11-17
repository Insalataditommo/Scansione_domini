"""
modules/lexical/parole_chiave.py

Comment:
    Parameter 4: sensitive keywords present on non-official domains.

    Phishing pages often contain words like "login", "verify", "account",
    "bank", "secure", "wallet" directly in the domain or in the path, to
    deceive the user. The presence of these words on a domain that does NOT
    belong to the legitimate brand is a suspicious signal.
"""

from __future__ import annotations

import re

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, SENSITIVE_KEYWORDS

# Known legitimate brands whose official domain may legitimately contain
# these words (exemplary list, to be extended in production).
LEGIT_BRAND_DOMAINS: frozenset[str] = frozenset(
    {"google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
     "github.com", "linkedin.com", "facebook.com", "instagram.com",
     "twitter.com", "x.com", "office.com", "live.com", "outlook.com",
     "yahoo.com", "docusign.com", "adobe.com", "dropbox.com", "intuit.com"}
)


class ParoleChiaveSensibili(BaseModule):
    """Comment: detects sensitive keywords on non-official domains."""

    description = "Parole chiave sensibili (login, verify, bank, ...) in domini non ufficiali."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "parole_chiave_sensibili".
        """
        return "parole_chiave_sensibili"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.2 (medium weight).
        """
        return 1.2

    def run(self, url: str) -> ModuleResult:
        """Comment: detects sensitive keywords on the URL host and path.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {keywords, count?}, score in [0,1],
            outcome SAFE (no keywords) / NEUTRAL (on official brand domain) /
            SUSPICIOUS (on non-official domain), threshold dict.
            NOT_EVALUATED when the URL or domain cannot be extracted.
        """
        parsed = parse_url(url)
        if parsed is None or not parsed.registered_domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o dominio non estraibile.",
            )

        # Build the "textual target": full host + path.
        target_text = " ".join([
            parsed.subdomain,
            parsed.registered_domain,
            parsed.path,
            parsed.query,
        ]).lower()

        # Strip separators to capture "login" even inside "my-login-page".
        tokenized = re.split(r"[^a-z0-9]+", target_text)
        found = sorted({t for t in tokenized if t in SENSITIVE_KEYWORDS})

        is_official_brand = parsed.registered_domain in LEGIT_BRAND_DOMAINS

        if not found:
            return ModuleResult(
                name=self.name(),
                raw_value={"keywords": []},
                score=0.0,
                outcome=Outcome.SAFE,
                message="Nessuna parola chiave sensibile rilevata.",
            )

        # On official brand domain: neutral (legitimate use).
        if is_official_brand:
            return ModuleResult(
                name=self.name(),
                raw_value={"keywords": found},
                score=0.0,
                outcome=Outcome.NEUTRAL,
                message=(
                    f"Trovate parole sensibili {found} ma su dominio brand ufficiale "
                    f"({parsed.registered_domain}): uso legittimo."
                ),
            )

        # On non-official domain: score grows with the number of matches.
        score = min(1.0, 0.3 * len(found) + 0.2)
        outcome = Outcome.SUSPICIOUS
        keywords_str = ", ".join(found[:5])
        msg = (
            f"Trovate {len(found)} parole chiave sensibili ({keywords_str}) "
            f"su dominio non ufficiale ({parsed.registered_domain}): tipico di phishing."
        )

        return ModuleResult(
            name=self.name(),
            raw_value={"keywords": found, "count": len(found)},
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"keywords_set": "SENSITIVE_KEYWORDS"},
            details={"official_brand": False},
        )
