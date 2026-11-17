"""
modules/lexical/ip_in_url.py

Comment:
    Parameter 8: literal IP instead of a domain.

    A URL pointing directly to an IP address (e.g. http://192.168.1.1/login)
    instead of a domain name is almost always suspicious in phishing
    contexts: the attacker does not want to register a domain (traceable)
    and hosts the phishing page on a compromised host or on an ephemeral
    hosting service.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url


class IpInUrl(BaseModule):
    """Comment: detects the presence of a literal IP instead of a domain."""

    description = "IP letterale al posto del nome di dominio."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "ip_in_url".
        """
        return "ip_in_url"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, strong signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: checks whether the URL host is a literal IP address.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {host, is_ip}, score 0.0 or 1.0,
            outcome SAFE/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the URL cannot be parsed.
        """
        parsed = parse_url(url)
        if parsed is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o non parseable.",
            )

        if parsed.is_ip:
            return ModuleResult(
                name=self.name(),
                raw_value={"host": parsed.registered_domain, "is_ip": True},
                score=1.0,
                outcome=Outcome.SUSPICIOUS,
                message=(
                    f"L'URL usa un IP letterale ({parsed.registered_domain}) invece di un "
                    f"dominio: fortemente sospetto in contesti di phishing."
                ),
                threshold={"is_ip_expected": False},
            )

        return ModuleResult(
            name=self.name(),
            raw_value={"host": parsed.registered_domain, "is_ip": False},
            score=0.0,
            outcome=Outcome.SAFE,
            message="L'URL usa un nome di dominio, non un IP letterale.",
        )
