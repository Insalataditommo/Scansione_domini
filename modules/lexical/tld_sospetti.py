"""
modules/lexical/tld_sospetti.py

Comment:
    Parameter 7: suspicious TLDs.

    Some TLDs (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .click, ...) are
    historically associated with a disproportionate incidence of phishing
    because they are free or cheap and have lightweight registration
    procedures. Sources: APWG Trends Reports, OpenPhish statistics.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, SUSPICIOUS_TLDS


class TldSospetti(BaseModule):
    """Comment: detects TLDs considered high-risk."""

    description = "TLD storicamente associati a campagne di phishing."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "tld_sospetti".
        """
        return "tld_sospetti"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: checks whether the URL's TLD is in the suspicious list.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {tld, last_tld}, score 0.0 or 0.8,
            outcome SAFE/NEUTRAL/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the URL or domain cannot be extracted.
        """
        parsed = parse_url(url)
        if parsed is None or not parsed.registered_domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o dominio non estraibile.",
            )

        tld = (parsed.tld or "").lower()
        # For composite TLDs (e.g. co.uk) we compare the last component.
        last_tld = tld.split(".")[-1] if tld else ""

        if not tld:
            return ModuleResult(
                name=self.name(),
                raw_value={"tld": "", "last_tld": ""},
                score=0.0,
                outcome=Outcome.NEUTRAL,
                message="TLD non determinato (probabile host locale o IP).",
            )

        if last_tld in SUSPICIOUS_TLDS:
            return ModuleResult(
                name=self.name(),
                raw_value={"tld": tld, "last_tld": last_tld},
                score=0.8,
                outcome=Outcome.SUSPICIOUS,
                message=(
                    f"TLD .{last_tld} presente in lista TLD ad alto rischio "
                    f"(gratuito/leggero): associato statisticamente a campagne di phishing."
                ),
                threshold={"suspicious_set": "SUSPICIOUS_TLDS"},
            )

        return ModuleResult(
            name=self.name(),
            raw_value={"tld": tld, "last_tld": last_tld},
            score=0.0,
            outcome=Outcome.SAFE,
            message=f"TLD .{last_tld} non in lista sospetti.",
        )
