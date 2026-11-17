"""
modules/lexical/lunghezza.py

Comment:
    Parameter 1: URL and domain length.

    Very long URLs and very long domain labels are often used to hide the
    real target of the link or to host obfuscated payloads. On their own
    they are not decisive indicators (low weight) but they contribute to
    the overall score.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url


class LunghezzaUrlDominio(BaseModule):
    """Comment: evaluates the overall URL length and the registered domain length."""

    description = "Lunghezza dell'URL e del dominio registrato."

    # Default thresholds (overridable from config/weights.yaml -> thresholds).
    URL_NEUTRO_MAX = 75
    URL_SOSPETTO_MIN = 100
    DOMAIN_NEUTRO_MAX = 20
    DOMAIN_SOSPETTO_MIN = 30

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "lunghezza_url_dominio".
        """
        return "lunghezza_url_dominio"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.5 (low weight, many false positives).
        """
        return 0.5

    def run(self, url: str) -> ModuleResult:
        """Comment: analyzes URL and domain length.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {url_length, domain_length},
            score in [0,1] (max of url and domain linear scores), outcome
            SAFE/NEUTRAL/SUSPICIOUS, and the thresholds dict. NOT_EVALUATED
            if the URL is unparseable.
        """
        parsed = parse_url(url)
        if parsed is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o non parseable.",
            )

        url_len = len(url)
        domain_len = len(parsed.registered_domain) if parsed.registered_domain else 0

        # URL score: linear interpolation between neutro_max and sospetto_min.
        url_score = _linear_score(
            url_len, self.URL_NEUTRO_MAX, self.URL_SOSPETTO_MIN
        )
        domain_score = _linear_score(
            domain_len, self.DOMAIN_NEUTRO_MAX, self.DOMAIN_SOSPETTO_MIN
        )
        # Combine: take the max of the two.
        score = max(url_score, domain_score)

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"URL lungo {url_len} caratteri, dominio {domain_len} caratteri: "
                f"lunghezze elevate possono nascondere il reale target del link."
            )
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = (
                f"URL di lunghezza intermedia ({url_len} car.), dominio {domain_len} car."
            )
        else:
            outcome = Outcome.SAFE
            msg = f"URL ({url_len} car.) e dominio ({domain_len} car.) di lunghezza normale."

        return ModuleResult(
            name=self.name(),
            raw_value={"url_length": url_len, "domain_length": domain_len},
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "url_neutro_max": self.URL_NEUTRO_MAX,
                "url_sospetto_min": self.URL_SOSPETTO_MIN,
                "domain_neutro_max": self.DOMAIN_NEUTRO_MAX,
                "domain_sospetto_min": self.DOMAIN_SOSPETTO_MIN,
            },
        )


def _linear_score(value: float, neutro_max: float, sospetto_min: float) -> float:
    """Comment: linear score between two thresholds.

    Input data:
        value:        measured value.
        neutro_max:   threshold below which score is 0.
        sospetto_min: threshold above which score is 1.

    Expected output:
        float in [0.0, 1.0]; 0 below neutro_max, 1 above sospetto_min,
        linearly interpolated in between.
    """
    if value <= neutro_max:
        return 0.0
    if value >= sospetto_min:
        return 1.0
    return (value - neutro_max) / (sospetto_min - neutro_max)
