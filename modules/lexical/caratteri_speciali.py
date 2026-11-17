"""
modules/lexical/caratteri_speciali.py

Comment:
    Parameter 6: special characters and digits in the domain.

    Excessive use of hyphens, digits or symbols in the domain (e.g.
    "login-account-secure-1.com") is typical of phishing because:
      - hyphens increase readability for the attacker of keywords
        without making them appear as a single string;
      - digits are used for numeric typosquatting (e.g. goog1e) or to
        distinguish algorithmically generated domains.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url


class CaratteriSpecialiNumeri(BaseModule):
    """Comment: counts special characters and digits in the domain."""

    description = "Caratteri speciali e numeri nel dominio."

    # Thresholds.
    DASH_NEUTRO_MAX = 0       # 0 hyphens = neutral
    DASH_SOSPETTO_MIN = 3     # >= 3 hyphens in the registered domain = suspicious
    DIGIT_RATIO_NEUTRO_MAX = 0.1
    DIGIT_RATIO_SOSPETTO_MIN = 0.3

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "caratteri_speciali_numeri".
        """
        return "caratteri_speciali_numeri"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.5 (low weight, many false positives).
        """
        return 0.5

    def run(self, url: str) -> ModuleResult:
        """Comment: counts hyphens and digits in the host.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {dash_count, digit_count,
            digit_ratio}, score in [0,1] (max of dash and digit scores),
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

        # Consider only the host part (without the TLD) to avoid counting
        # separators of multi-component TLDs (.co.uk etc.).
        host = parsed.subdomain + "." + parsed.registered_domain \
            if parsed.subdomain else parsed.registered_domain

        dash_count = host.count("-")
        digit_count = sum(c.isdigit() for c in host)
        length = max(1, len(host))
        digit_ratio = digit_count / length

        dash_score = _linear_score(dash_count, self.DASH_NEUTRO_MAX, self.DASH_SOSPETTO_MIN)
        digit_score = _linear_score(digit_ratio, self.DIGIT_RATIO_NEUTRO_MAX, self.DIGIT_RATIO_SOSPETTO_MIN)
        score = max(dash_score, digit_score)

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Dominio con {dash_count} trattini e ratio cifre={digit_ratio:.2f}: "
                f"configurazione atipica per domini legittimi."
            )
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = (
                f"Dominio con alcuni caratteri speciali/cifre "
                f"(trattini={dash_count}, digit_ratio={digit_ratio:.2f})."
            )
        else:
            outcome = Outcome.SAFE
            msg = f"Dominio senza caratteri speciali/cifre rilevanti (trattini={dash_count})."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "dash_count": dash_count,
                "digit_count": digit_count,
                "digit_ratio": round(digit_ratio, 3),
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "dash_neutro_max": self.DASH_NEUTRO_MAX,
                "dash_sospetto_min": self.DASH_SOSPETTO_MIN,
                "digit_ratio_neutro_max": self.DIGIT_RATIO_NEUTRO_MAX,
                "digit_ratio_sospetto_min": self.DIGIT_RATIO_SOSPETTO_MIN,
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
        linearly interpolated in between; 1.0 when the two thresholds are
        equal to avoid division by zero.
    """
    if value <= neutro_max:
        return 0.0
    if value >= sospetto_min:
        return 1.0
    if sospetto_min == neutro_max:
        return 1.0
    return (value - neutro_max) / (sospetto_min - neutro_max)
