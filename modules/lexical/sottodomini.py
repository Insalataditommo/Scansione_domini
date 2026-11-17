"""
modules/lexical/sottodomini.py

Comment:
    Parameter 3: number and depth of subdomains.

    A large number of labels in the subdomain (e.g. a.b.c.d.e.example.com)
    is a technique used to make the domain look legitimate (e.g. aggregating
    "login.bank.com" as a subdomain of a malicious domain) and to evade
    filters based solely on the registered domain.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, subdomain_depth, count_subdomains


class Sottodomini(BaseModule):
    """Comment: evaluates number and depth of subdomains."""

    description = "Numero e profondità dei sottodomini."

    DEPTH_NEUTRO_MAX = 3
    DEPTH_SOSPETTO_MIN = 5
    COUNT_NEUTRO_MAX = 3
    COUNT_SOSPETTO_MIN = 6

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "sottodomini".
        """
        return "sottodomini"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.6 (low weight, many false positives).
        """
        return 0.6

    def run(self, url: str) -> ModuleResult:
        """Comment: analyzes subdomain depth and count.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {depth, count, subdomain},
            score in [0,1] (max of depth and count linear scores),
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

        depth = subdomain_depth(parsed.subdomain)
        count = count_subdomains(parsed.subdomain)

        depth_score = _linear_score(depth, self.DEPTH_NEUTRO_MAX, self.DEPTH_SOSPETTO_MIN)
        count_score = _linear_score(count, self.COUNT_NEUTRO_MAX, self.COUNT_SOSPETTO_MIN)
        score = max(depth_score, count_score)

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Sottodomini profondi/numerosi (depth={depth}, count={count}): "
                f"tecnica tipica per mascherare domini malevoli."
            )
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = f"Sottodomini nella fascia di guardia (depth={depth}, count={count})."
        else:
            outcome = Outcome.SAFE
            msg = f"Sottodomini nella norma (depth={depth}, count={count})."

        return ModuleResult(
            name=self.name(),
            raw_value={"depth": depth, "count": count, "subdomain": parsed.subdomain},
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "depth_neutro_max": self.DEPTH_NEUTRO_MAX,
                "depth_sospetto_min": self.DEPTH_SOSPETTO_MIN,
                "count_neutro_max": self.COUNT_NEUTRO_MAX,
                "count_sospetto_min": self.COUNT_SOSPETTO_MIN,
            },
        )


def _linear_score(value: float, neutro_max: float, sospetto_min: float) -> float:
    """Comment: linear score between two thresholds.

    Input data:
        value:        measured value.
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
