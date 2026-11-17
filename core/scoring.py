"""
core/scoring.py

Comment:
    Aggregation of the active modules' scores and computation of the final
    risk percentage, normalized between 0% and 100%.

    The adopted formula is a weighted average:

        risk_pct = 100 * sum(score_i * weight_i) / sum(weight_i)

    computed only on the modules actually evaluated (outcome != NOT_EVALUATED).
    `SAFE` modules contribute a low (or 0) score, `SUSPICIOUS` modules a high
    score (up to 1). Not-evaluated modules are excluded from both numerator
    and denominator, so that a temporarily down external service does not
    falsify the result.

    Weights are defined in config/weights.yaml and loaded by the orchestrator;
    an internal default is provided here so the system can be used without
    a configuration file.
"""

from __future__ import annotations

from typing import Iterable

from core.base_module import BaseModule, ModuleResult, Outcome


class ScoringError(Exception):
    """Comment: error raised during score aggregation."""


def aggregate(results: Iterable[ModuleResult], weights: dict[str, float] | None = None) -> dict:
    """Comment: aggregates per-module results into a normalized final score.

    Input data:
        results: iterable of ModuleResult for a single URL.
        weights: optional map module_name -> weight (defaults to 1.0 when missing).

    Expected output:
        dict with:
        - "risk_pct":       float in [0, 100].
        - "weighted_sum":   sum of score*weight (numerator).
        - "weight_sum":     sum of used weights (denominator).
        - "evaluated":      list of evaluated module names.
        - "not_evaluated":  list of not-evaluated module names.
        - "label":          qualitative label ("basso"|"medio"|"alto"|"critico"|"indeterminato").
    """
    weights = weights or {}
    weighted_sum = 0.0
    weight_sum = 0.0
    evaluated: list[str] = []
    not_evaluated: list[str] = []

    for r in results:
        if r.outcome == Outcome.NOT_EVALUATED:
            not_evaluated.append(r.name)
            continue
        w = float(weights.get(r.name, 1.0))
        w = max(0.0, w)  # negative weights are not allowed
        weighted_sum += float(r.score) * w
        weight_sum += w
        evaluated.append(r.name)

    if weight_sum <= 0:
        # No module evaluated: a risk cannot be computed.
        risk_pct = 0.0
        label = "indeterminato"
    else:
        risk_pct = 100.0 * weighted_sum / weight_sum
        risk_pct = max(0.0, min(100.0, risk_pct))
        label = _label_for(risk_pct)

    return {
        "risk_pct": round(risk_pct, 2),
        "weighted_sum": round(weighted_sum, 4),
        "weight_sum": round(weight_sum, 4),
        "evaluated": evaluated,
        "not_evaluated": not_evaluated,
        "label": label,
    }


def _label_for(risk_pct: float) -> str:
    """Comment: maps the risk percentage to a qualitative label.

    Input data:
        risk_pct: float in [0, 100].

    Expected output:
        str, one of "basso" (<25), "medio" (25-49), "alto" (50-74),
        "critico" (75-100). Thresholds are tunable here or in
        config/weights.yaml under the `thresholds` key.
    """
    if risk_pct < 25.0:
        return "basso"
    if risk_pct < 50.0:
        return "medio"
    if risk_pct < 75.0:
        return "alto"
    return "critico"


def load_weights(path: str) -> dict[str, float]:
    """Comment: loads weights from a YAML file.

        Tries `pyyaml` first; when not installed, falls back to a tiny
        built-in parser that understands the subset of YAML used by the
        shipped weights.yaml: a top-level `weights:` block of
        `key: number` lines and inline comments.

    Input data:
        path: filesystem path to a YAML file with structure:

            weights:
              lunghezza_url: 0.5
              eta_dominio:   2.0
              ...

            thresholds:
              basso: 25
              medio: 50
              alto:  75

    Expected output:
        dict[str, float] mapping module name -> non-negative weight.
        On missing file or both parsers failing, returns an empty dict
        (the orchestrator will then fall back to per-module default weights).
    """
    import os

    if not os.path.exists(path):
        return {}

    # 1) Prefer pyyaml when available.
    try:
        import yaml  # type: ignore

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            raw = data.get("weights", {}) or {}
            weights: dict[str, float] = {}
            for k, v in raw.items():
                try:
                    weights[str(k)] = max(0.0, float(v))
                except (TypeError, ValueError):
                    continue
            return weights
    except ImportError:
        pass

    # 2) Minimal fallback parser for our weights.yaml subset, used when
    #    pyyaml is not installed. It only reads the top-level `weights:`
    #    block; nested blocks (thresholds, risk_labels, external_apis) are
    #    skipped because they are not needed by the scoring engine.
    try:
        return _parse_weights_block_minimal(path)
    except Exception:  # noqa: BLE001
        return {}


def _parse_weights_block_minimal(path: str) -> dict[str, float]:
    """Comment: tiny YAML subset parser for the `weights:` block.

        Reads only lines of the form `  key: number` (with optional inline
        comment) inside a top-level `weights:` block, until a line at
        column 0 introduces a new top-level key.

    Input data:
        path: filesystem path of the YAML file.

    Expected output:
        dict[str, float] of module name -> weight (>= 0.0). Lines that
        cannot be parsed as `key: number` are skipped silently.
    """
    weights: dict[str, float] = {}
    in_block = False
    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            # Strip full-line comments and blank lines.
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Detect top-level keys (no leading whitespace).
            if not line[0].isspace():
                # Enter the weights block on "weights:" and exit it on any
                # other top-level key.
                in_block = stripped.rstrip(":").lower() == "weights"
                continue
            if not in_block:
                continue
            # Inside the block: parse "  key: value   # comment".
            # Drop the inline comment (only if the # is outside a string,
            # which is always true for our numeric weights).
            code = stripped.split("#", 1)[0].strip()
            if ":" not in code:
                continue
            key, _, val = code.partition(":")
            key = key.strip()
            val = val.strip()
            if not key or not val:
                continue
            try:
                weights[key] = max(0.0, float(val))
            except ValueError:
                continue
    return weights


def effective_weight(module: BaseModule, weights: dict[str, float]) -> float:
    """Comment: returns the effective weight of a module.

    Input data:
        module:  a BaseModule instance.
        weights: dict[str, float] loaded from config (may be partial).

    Expected output:
        float >= 0.0; the value from `weights` if present, otherwise the
        module's own default weight (module.weight()), or 1.0 if that
        call itself raises.
    """
    w = weights.get(module.name())
    if w is None:
        try:
            w = module.weight()
        except Exception:  # noqa: BLE001
            w = 1.0
    return max(0.0, float(w))
