"""
core/base_module.py

Comment:
    Defines the common interface for all analysis modules (BaseModule) and
    the standardized result returned by each module (ModuleResult).

    Every analysis parameter (lexical, dns_whois, tls, content, dynamic,
    reputation) must expose a class that inherits from BaseModule and
    implements the abstract methods `name`, `weight` and `run(url)`.
"""

from __future__ import annotations

import abc
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Outcome(str, Enum):
    """Comment:
        Possible outcome of a single analysis parameter.

        - SUSPICIOUS:    the parameter signals phishing (contributes to the score).
        - NEUTRAL:       the parameter signals nothing relevant (no score added).
        - SAFE:          the parameter signals a positive safety condition (may reduce risk).
        - NOT_EVALUATED: the parameter could not be evaluated (timeout, API down, error).
                         Excluded from the final risk percentage calculation.
    """

    SUSPICIOUS = "sospetto"
    NEUTRAL = "neutro"
    SAFE = "sicuro"
    NOT_EVALUATED = "non valutato"


@dataclass
class ModuleResult:
    """Comment:
        Standardized result returned by an analysis module.

    Attributes:
        name:      parameter name (e.g. "lunghezza_url").
        raw_value: raw detected value (e.g. 85, "0.8.2", "DV", list of IPs).
        score:     normalized score in [0.0, 1.0]; 0 = safe, 1 = max suspicious.
                   Ignored when outcome == NOT_EVALUATED.
        outcome:   qualitative outcome (Outcome).
        message:   short human-readable explanation (Italian, shown in report).
        threshold: threshold applied to decide the outcome (optional, for auditability).
        details:   optional additional metadata (free-form dict).
    """

    name: str
    raw_value: Any = None
    score: float = 0.0
    outcome: Outcome = Outcome.NEUTRAL
    message: str = ""
    threshold: Optional[Any] = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Comment:
            Ensures the score is always finite and within [0, 1].

        Input data:
            self.score (float, possibly NaN/inf/out-of-range),
            self.outcome (Outcome).

        Expected output:
            self.score normalized to a float in [0.0, 1.0]; forced to 0.0
            when outcome is NOT_EVALUATED or when score is not a finite number.
        """
        try:
            if self.outcome == Outcome.NOT_EVALUATED:
                self.score = 0.0
            elif not math.isfinite(self.score):
                self.score = 0.0
            else:
                self.score = max(0.0, min(1.0, float(self.score)))
        except (TypeError, ValueError):
            self.score = 0.0


class BaseModule(abc.ABC):
    """Comment:
        Abstract base class for all phishing analysis modules.

        Each concrete module must implement:
            - name(self) -> str
            - weight(self) -> float
            - run(self, url: str) -> ModuleResult

        Concrete implementations should also override `description` to
        document briefly what the parameter measures.
    """

    # Optional short label used in reports and menus.
    description: str = "(no description)"

    @abc.abstractmethod
    def name(self) -> str:
        """Comment: returns the parameter identifier (snake_case).

        Input data:  self (concrete module instance).
        Expected output: str, e.g. "lunghezza_url_dominio".
        """

    @abc.abstractmethod
    def weight(self) -> float:
        """Comment:
            Returns the parameter weight (>= 0). Weights are read from
            config/weights.yaml by the orchestrator; here a reasoned default
            is provided, overridable by subclassing.

        Input data:  self (concrete module instance).
        Expected output: float >= 0.0.
        """

    @abc.abstractmethod
    def run(self, url: str) -> ModuleResult:
        """Comment:
            Analyzes a single URL and returns a ModuleResult.

            If the analysis fails (timeout, external service down), the
            implementation must return a ModuleResult with
            outcome=Outcome.NOT_EVALUATED and a descriptive message: the
            module must NEVER propagate exceptions to the orchestrator.

        Input data:
            url: full URL string to analyze.

        Expected output:
            ModuleResult populated with name, raw_value, score, outcome,
            message and (optional) threshold/details.
        """

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------
    @staticmethod
    def safe_run(runner: "BaseModule", url: str) -> ModuleResult:
        """Comment:
            Executes `runner.run(url)` catching every exception.

            Used by the orchestrator to guarantee that a failing module
            does not break the whole analysis: on exception it returns a
            ModuleResult with outcome=NOT_EVALUATED.

        Input data:
            runner: a BaseModule instance with a callable `run`.
            url:    URL string to analyze.

        Expected output:
            ModuleResult; on success it is the one returned by runner.run,
            on any exception it is a NOT_EVALUATED result with the
            exception class and message in `message`.
        """
        try:
            result = runner.run(url)
            if not isinstance(result, ModuleResult):
                raise TypeError(
                    f"Module {runner.name()} returned {type(result).__name__} "
                    f"instead of ModuleResult."
                )
            return result
        except Exception as exc:  # noqa: BLE001 - intentionally broad
            return ModuleResult(
                name=runner.name() if callable(getattr(runner, "name", None)) else "unknown",
                raw_value=None,
                score=0.0,
                outcome=Outcome.NOT_EVALUATED,
                message=f"Module not evaluated due to internal error: {exc.__class__.__name__}: {exc}",
                details={"exception": exc.__class__.__name__},
            )

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return f"<{self.__class__.__name__} name={getattr(self, 'name', lambda: '?')()}>"
