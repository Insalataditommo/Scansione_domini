"""
modules/tls/tipo_certificato.py

Comment:
    Parameter 11: certificate type (DV / OV / EV).

    Certificates are classified into:
      - DV (Domain Validation):      verifies only domain control.
        They are free (e.g. Let's Encrypt) and usable by anyone: on their
        own they are not a signal of trustworthiness.
      - OV (Organization Validation): the CA verifies the organization's existence.
      - EV (Extended Validation):     extended validation of the organization.

    A phishing site that requests banking credentials with a DV certificate
    is more suspicious than one with EV. The module estimates the type by
    analyzing the presence of Organization in the subject (heuristic: EV
    when `serialNumber` / `businessCategory` are also present, OV when
    Organization is present without EV-specific OIDs, DV otherwise).
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.tls._tlsutils import fetch_tls_info


class TipoCertificato(BaseModule):
    """Comment: classifies the certificate as DV/OV/EV (heuristic)."""

    description = "Tipo di certificato (DV/OV/EV)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "tipo_certificato".
        """
        return "tipo_certificato"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.2 (medium weight).
        """
        return 1.2

    def run(self, url: str) -> ModuleResult:
        """Comment: classifies the server certificate as DV/OV/EV.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {type, subject, issuer}, score 0.0
            (OV/EV) or 0.5 (DV), outcome SAFE/NEUTRAL, threshold dict.
            NOT_EVALUATED when the certificate cannot be retrieved.
        """
        info = fetch_tls_info(url, timeout=5.0)
        if info.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Certificato non valutato: {info.error}",
            )
        if info.certificate is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Nessun certificato restituito dal server.",
            )

        subj = info.certificate.subject or {}
        issuer = info.certificate.issuer or {}

        # Heuristic based on subject fields.
        has_org = bool(subj.get("organizationName"))
        has_ev_fields = bool(
            subj.get("serialNumber") or subj.get("businessCategory")
            or subj.get("jurisdictionCountryName")
        )

        if has_ev_fields and has_org:
            cert_type = "EV"
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Certificato Extended Validation (EV): validazione organizzazione forte."
        elif has_org:
            cert_type = "OV"
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Certificato Organization Validation (OV): organizzazione verificata."
        else:
            cert_type = "DV"
            score = 0.5
            outcome = Outcome.NEUTRAL
            msg = (
                "Certificato Domain Validation (DV): verifica solo il controllo "
                "del dominio. Da solo non è prova di affidabilità."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "type": cert_type,
                "subject": subj,
                "issuer": issuer,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"ev_fields": ["serialNumber", "businessCategory"]},
        )
