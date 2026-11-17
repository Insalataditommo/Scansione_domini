"""
modules/lexical/url_shortener.py

Comment:
    Parameter 9: URL shortener.

    URL shortening services (bit.ly, t.co, tinyurl.com, ...) hide the final
    destination of the link and are therefore commonly used in email/SMS
    phishing campaigns. They are not malicious per se, but their use always
    requires an additional level of analysis (redirect expansion).
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, URL_SHORTENERS


class UrlShortener(BaseModule):
    """Comment: detects whether the URL uses a shortening service."""

    description = "Uso di URL shortener (bit.ly, t.co, tinyurl, ...)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "url_shortener".
        """
        return "url_shortener"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: checks whether the URL host is a known shortener.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {domain, is_shortener}, score 0.0
            or 0.6, outcome SAFE/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the URL or domain cannot be extracted.
        """
        parsed = parse_url(url)
        if parsed is None or not parsed.registered_domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o dominio non estraibile.",
            )

        domain = parsed.registered_domain.lower()
        if domain in URL_SHORTENERS:
            return ModuleResult(
                name=self.name(),
                raw_value={"domain": domain, "is_shortener": True},
                score=0.6,
                outcome=Outcome.SUSPICIOUS,
                message=(
                    f"URL shortener rilevato ({domain}): la destinazione finale è "
                    f"nascosta; raccomandata espansione del redirect prima di valutare."
                ),
                threshold={"shortener_set": "URL_SHORTENERS"},
            )

        return ModuleResult(
            name=self.name(),
            raw_value={"domain": domain, "is_shortener": False},
            score=0.0,
            outcome=Outcome.SAFE,
            message="Dominio non in lista URL shortener noti.",
        )
