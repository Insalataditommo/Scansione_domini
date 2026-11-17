"""
modules/lexical/entropia.py

Comment:
    Parameter 2: Shannon entropy of the domain characters.

    A very high entropy (typically > 4.0 bits/char) on a domain is often
    indicative of algorithmically generated names (DGA - Domain Generation
    Algorithm) used by malware and phishing campaigns. It must however be
    correlated with other signals because CDNs and hosting services may
    have high-entropy names without being malicious.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, shannon_entropy


class EntropiaCaratteri(BaseModule):
    """Comment: computes the Shannon entropy of the registered domain."""

    description = "Entropia di Shannon del dominio (indicatore di DGA)."

    # Default thresholds (bits/char).
    NEUTRO_MAX = 3.5
    SOSPETTO_MIN = 4.0

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "entropia_caratteri".
        """
        return "entropia_caratteri"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.7 (medium-low weight).
        """
        return 0.7

    def run(self, url: str) -> ModuleResult:
        """Comment: computes Shannon entropy of the host.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value (rounded entropy), score in [0,1],
            outcome SAFE/NEUTRAL/SUSPICIOUS, threshold dict and details
            with the analyzed host. NOT_EVALUATED when the URL or domain
            cannot be extracted.
        """
        parsed = parse_url(url)
        if parsed is None or not parsed.registered_domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o dominio non estraibile.",
            )

        # Use the full registered_domain (e.g. "sub.example.com" -> "example.com").
        # We also include the subdomain because DGAs often fill subdomains.
        host_for_entropy = parsed.subdomain + "." + parsed.registered_domain \
            if parsed.subdomain else parsed.registered_domain

        entropy = shannon_entropy(host_for_entropy)
        score = _entropy_score(entropy, self.NEUTRO_MAX, self.SOSPETTO_MIN)

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Entropia {entropy:.2f} bit/car: elevata, possibile DGA o dominio "
                f"generato algoritmicamente."
            )
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = f"Entropia {entropy:.2f} bit/car: nella fascia di guardia."
        else:
            outcome = Outcome.SAFE
            msg = f"Entropia {entropy:.2f} bit/car: nella norma per un dominio legittimo."

        return ModuleResult(
            name=self.name(),
            raw_value=round(entropy, 4),
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"neutro_max": self.NEUTRO_MAX, "sospetto_min": self.SOSPETTO_MIN},
            details={"host_analizzato": host_for_entropy},
        )


def _entropy_score(value: float, neutro_max: float, sospetto_min: float) -> float:
    """Comment: linear score for the entropy.

    Input data:
        value:        measured entropy.
        neutro_max:   threshold below which score is 0.
        sospetto_min: threshold above which score is 1.

    Expected output:
        float in [0.0, 1.0]; 0 below neutro_max, 1 above sospetto_min.
    """
    if value <= neutro_max:
        return 0.0
    if value >= sospetto_min:
        return 1.0
    return (value - neutro_max) / (sospetto_min - neutro_max)
