"""
core/report.py

Comment:
    Report generation for each analyzed URL.

    Two formats are supported:
        - text (CLI, for stdout and logs)
        - JSON  (for programmatic integration and CI/CD pipelines)

    The per-URL report shows, for each active parameter:
        - parameter name
        - raw detected value
        - applied threshold
        - outcome (sospetto / neutro / sicuro / non valutato)
        - short human-readable message
    At the bottom it shows the final risk percentage with the qualitative
    label and the list of not-evaluated modules.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from core.base_module import ModuleResult, Outcome


# Outcome -> visual symbol mapping (for the text report).
_OUTCOME_SYMBOL = {
    Outcome.SUSPICIOUS: "[!]",
    Outcome.NEUTRAL: "[ ]",
    Outcome.SAFE: "[+]",
    Outcome.NOT_EVALUATED: "[?]",
}

# Outcome -> localized label mapping.
_OUTCOME_LABEL = {o: o.value for o in Outcome}


def render_text(url: str, results: Iterable[ModuleResult], aggregate_result: dict) -> str:
    """Comment: renders the text report for a single URL.

    Input data:
        url:              the analyzed URL.
        results:          iterable of ModuleResult for the URL.
        aggregate_result: dict returned by scoring.aggregate().

    Expected output:
        str, formatted multi-line text ready for stdout or a log file.
    """
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("REPORT DI ANALISI PHISHING")
    lines.append("=" * 78)
    lines.append(f"URL              : {url}")
    lines.append(f"Timestamp (UTC)  : {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("-" * 78)
    lines.append(f"{'Parametro':<32} {'Esito':<14} {'Score':>6}  Dettagli")
    lines.append("-" * 78)

    for r in results:
        symbol = _OUTCOME_SYMBOL.get(r.outcome, "[?]")
        label = _OUTCOME_LABEL.get(r.outcome, "?")
        score_str = "n/a" if r.outcome == Outcome.NOT_EVALUATED else f"{r.score:.2f}"
        # Truncate raw_value to avoid very long lines.
        raw = _truncate(_format_value(r.raw_value), 40)
        lines.append(
            f"{r.name:<32} {symbol} {label:<10} {score_str:>6}  {raw}"
        )
        if r.message:
            lines.append(f"{'':<34} → {r.message}")
        if r.threshold is not None:
            lines.append(f"{'':<34} soglia: {_format_value(r.threshold)}")

    lines.append("-" * 78)
    risk = aggregate_result.get("risk_pct", 0.0)
    label = aggregate_result.get("label", "indeterminato")
    lines.append(f"RISCHIO FINALE: {risk:.2f}%  [{label.upper()}]")
    lines.append(
        f"Moduli valutati: {len(aggregate_result.get('evaluated', []))} "
        f"| Non valutati: {len(aggregate_result.get('not_evaluated', []))}"
    )
    if aggregate_result.get("not_evaluated"):
        lines.append(
            "Non valutati: " + ", ".join(aggregate_result["not_evaluated"])
        )
    lines.append("=" * 78)
    return "\n".join(lines)


def render_json(url: str, results: Iterable[ModuleResult], aggregate_result: dict) -> str:
    """Comment: renders the report as JSON.

    Input data:
        url:              the analyzed URL.
        results:          iterable of ModuleResult for the URL.
        aggregate_result: dict returned by scoring.aggregate().

    Expected output:
        str, JSON document consumable by SIEM/SOAR/CI-CD pipelines.
    """
    payload = {
        "url": url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk_pct": aggregate_result.get("risk_pct", 0.0),
        "label": aggregate_result.get("label", "indeterminato"),
        "weighted_sum": aggregate_result.get("weighted_sum", 0.0),
        "weight_sum": aggregate_result.get("weight_sum", 0.0),
        "evaluated": aggregate_result.get("evaluated", []),
        "not_evaluated": aggregate_result.get("not_evaluated", []),
        "modules": [
            {
                "name": r.name,
                "raw_value": r.raw_value,
                "score": r.score if r.outcome != Outcome.NOT_EVALUATED else None,
                "outcome": r.outcome.value,
                "threshold": r.threshold,
                "message": r.message,
                "details": r.details,
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def render_markdown_table(url: str, results: Iterable[ModuleResult], aggregate_result: dict) -> str:
    """Comment: renders the report as a Markdown table.

    Input data:
        url:              the analyzed URL.
        results:          iterable of ModuleResult for the URL.
        aggregate_result: dict returned by scoring.aggregate().

    Expected output:
        str, Markdown table useful for PRs/issues/reports.
    """
    lines = [
        f"## Report: `{url}`",
        "",
        f"**Rischio finale:** {aggregate_result.get('risk_pct', 0.0):.2f}% "
        f"— _{aggregate_result.get('label', 'indeterminato')}_",
        "",
        "| Parametro | Esito | Score | Soglia | Messaggio |",
        "|---|---|---:|---|---|",
    ]
    for r in results:
        score_str = "n/a" if r.outcome == Outcome.NOT_EVALUATED else f"{r.score:.2f}"
        thr = _format_value(r.threshold) if r.threshold is not None else "—"
        msg = _format_value(r.message).replace("|", "\\|")
        lines.append(
            f"| `{r.name}` | {r.outcome.value} | {score_str} | {thr} | {msg} |"
        )
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Formatting helpers
# ----------------------------------------------------------------------
def _format_value(v) -> str:
    """Comment: formats an arbitrary value as a compact string.

    Input data:
        v: any value (None, list, tuple, set, dict, scalar).

    Expected output:
        str; "—" for None or empty collections, JSON string for dicts,
        comma-separated for list/tuple/set, str(v) otherwise.
    """
    if v is None:
        return "—"
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v) if v else "—"
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v)


def _truncate(s: str, n: int) -> str:
    """Comment: truncates a string to at most n characters, adding an ellipsis.

    Input data:
        s: input string.
        n: maximum length (including the ellipsis).

    Expected output:
        str of length <= n; unchanged if len(s) <= n, otherwise s truncated
        to n-1 chars plus the "…" ellipsis.
    """
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"
