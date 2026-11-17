"""
modules/tls/eta_durata_certificato.py

Comment:
    Parameter 12: certificate age and duration.

    A certificate issued a few days earlier on a young domain is often an
    indicator of infrastructure just set up for a campaign. Also a long
    validity (> 1 year on a DV cert) can be unusual after 2020 (Let's
    Encrypt issues 90-day certificates).
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.tls._tlsutils import fetch_tls_info

# Thresholds.
ETA_SOSPETTO_MAX_GIORNI = 14     # < 14 days = suspicious
DURATA_SOSPETTO_MAX_GIORNI = 0   # negative = already expired
DURATA_LUNGA_MIN_GIORNI = 397    # > ~13 months on DV: unusual


class EtaDurataCertificato(BaseModule):
    """Comment: evaluates the age and duration of the X.509 certificate."""

    description = "Età e durata del certificato TLS."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "eta_durata_certificato".
        """
        return "eta_durata_certificato"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: evaluates certificate age and validity duration.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {not_before, not_after, age_days,
            validity_days, remaining_days?}, score in [0,1], outcome
            SAFE/NEUTRAL/SUSPICIOUS, threshold dict. NOT_EVALUATED when the
            certificate or its validity dates cannot be retrieved.
        """
        info = fetch_tls_info(url, timeout=5.0)
        if info.error or info.certificate is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Certificato non valutato: {info.error or 'cert assente'}",
            )

        cert = info.certificate
        not_before = _parse_dt(cert.not_before)
        not_after = _parse_dt(cert.not_after)

        if not_before is None or not_after is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Date di validità non estraibili dal certificato.",
            )

        now = datetime.now(timezone.utc)
        age_days = (now - not_before).total_seconds() / 86400.0
        validity_days = (not_after - not_before).total_seconds() / 86400.0
        remaining_days = (not_after - now).total_seconds() / 86400.0

        # Case 1: expired.
        if remaining_days < 0:
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "age_days": round(age_days, 1),
                    "validity_days": round(validity_days, 1),
                    "remaining_days": round(remaining_days, 1),
                },
                score=1.0,
                outcome=Outcome.SUSPICIOUS,
                message="Certificato SCADUTO: illegittimo o infrastruttura abbandonata.",
            )

        # Case 2: too young.
        if age_days < ETA_SOSPETTO_MAX_GIORNI:
            score = 1.0 - (age_days / ETA_SOSPETTO_MAX_GIORNI)
            score = max(0.5, min(1.0, score))
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "age_days": round(age_days, 1),
                    "validity_days": round(validity_days, 1),
                },
                score=score,
                outcome=Outcome.SUSPICIOUS,
                message=(
                    f"Certificato emesso da {age_days:.0f} giorni "
                    f"(< soglia {ETA_SOSPETTO_MAX_GIORNI}gg): possibile infrastruttura "
                    f"di recente creazione per una campagna."
                ),
                threshold={"eta_sospetto_max_giorni": ETA_SOSPETTO_MAX_GIORNI},
            )

        # Case 3: unusual duration (very long on DV).
        if validity_days > DURATA_LUNGA_MIN_GIORNI:
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "age_days": round(age_days, 1),
                    "validity_days": round(validity_days, 1),
                },
                score=0.3,
                outcome=Outcome.NEUTRAL,
                message=(
                    f"Durata certificato insolitamente lunga ({validity_days:.0f} giorni): "
                    f"inusuale dopo la standardizzazione a 90gg."
                ),
                threshold={"durata_lunga_min_giorni": DURATA_LUNGA_MIN_GIORNI},
            )

        # Case 4: normal.
        return ModuleResult(
            name=self.name(),
            raw_value={
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "age_days": round(age_days, 1),
                "validity_days": round(validity_days, 1),
            },
            score=0.0,
            outcome=Outcome.SAFE,
            message=(
                f"Certificato valido, età {age_days:.0f} giorni, "
                f"scadenza tra {remaining_days:.0f} giorni: nella norma."
            ),
        )


def _parse_dt(s: str | None) -> datetime | None:
    """Comment: tries to parse dates in RFC 4514 / ISO 8601 / legacy formats.

    Input data:
        s: date string (or None).

    Expected output:
        timezone-aware datetime, or None when the string cannot be parsed
        by any of the candidate formats.
    """
    if not s:
        return None
    candidates = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%b %d %H:%M:%S %Y %Z",  # legacy ssl format (e.g. "Jun  1 12:00:00 2025 GMT")
        "%Y%m%d%H%M%SZ",  # ASN.1 UTCTime
    ]
    for fmt in candidates:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Fallback: fromisoformat (Python 3.11+ accepts 'Z').
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None
