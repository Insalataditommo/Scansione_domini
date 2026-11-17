"""
modules/tls/ca_catena_fiducia.py

Comment:
    Parameter 13: issuing CA and trust chain.

    Verifies that the certificate is signed by a recognized CA and that
    the trust chain is valid up to a known root. The absence of trust
    (self-signed cert, unknown CA, hostname mismatch) is a serious signal
    because it allows anyone to issue an apparently valid certificate for
    an arbitrary domain.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.tls._tlsutils import fetch_tls_info, verify_tls_chain


# Set of known and generally trusted CAs (Common Name or Organization Name).
# Exemplary list; not a formal validation of the trust store.
KNOWN_CAS: frozenset[str] = frozenset(
    {"Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "Entrust",
     "GeoTrust", "Comodo CA", "USERTrust", "GoDaddy", "Amazon",
     "Google Trust Services", "Microsoft Azure", "Cloudflare Inc",
     "Buypass", "ZeroSSL", "Google Internet Authority", "Symantec",
     "Thawte", "D-TRUST", "Actalis", "HARICA", "SSL.com"}
)


class CaCatenaFiducia(BaseModule):
    """Comment: verifies the issuing CA and the validity of the trust chain."""

    description = "CA emittente e catena di fiducia del certificato."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "ca_catena_fiducia".
        """
        return "ca_catena_fiducia"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.2 (medium weight).
        """
        return 1.2

    def run(self, url: str) -> ModuleResult:
        """Comment: verifies the trust chain and the issuing CA.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {issuer_cn, issuer_org,
            chain_valid, chain_error, is_known_ca}, score in [0,1],
            outcome SAFE/NEUTRAL/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the certificate cannot be retrieved.
        """
        # 1) Formal verification of the trust chain (with check_hostname).
        chain_ok, chain_err = verify_tls_chain(url, timeout=5.0)

        # 2) Retrieve certificate info (even when the chain verification fails).
        info = fetch_tls_info(url, timeout=5.0)
        if info.error or info.certificate is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Certificato non valutato: {info.error or 'cert assente'}",
            )

        issuer = info.certificate.issuer or {}
        # Look for the Organization / CommonName under either the long
        # (cryptography backend: commonName/organizationName) or short
        # (manual fallback: CN/O) attribute names, depending on the parser.
        issuer_org = (
            issuer.get("organizationName")
            or issuer.get("O")
            or issuer.get("organizationName".upper())
            or ""
        )
        issuer_cn = (
            issuer.get("commonName")
            or issuer.get("CN")
            or issuer.get("commonName".upper())
            or ""
        )
        # Some certificates carry only the Organization; also search for
        # businessCategory / organizationalUnitName as a further fallback.
        if not issuer_org and not issuer_cn:
            issuer_org = (
                issuer.get("organizationalUnitName")
                or issuer.get("OU")
                or ""
            )

        is_known_ca = any(
            name.lower() in (issuer_org + " " + issuer_cn).lower()
            for name in KNOWN_CAS
        )

        if not chain_ok:
            # Chain NOT verified: serious signal.
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Catena di trust NON valida ({chain_err}). "
                f"CA emittente: {issuer_cn or issuer_org or 'sconosciuta'}."
            )
        elif not is_known_ca:
            # Chain verified but CA not in the known list.
            score = 0.5
            outcome = Outcome.NEUTRAL
            msg = (
                f"Catena valida ma CA emittente non riconosciuta "
                f"({issuer_cn or issuer_org}): da approfondire manualmente."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Catena di trust valida, CA nota ({issuer_cn or issuer_org})."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "issuer_cn": issuer_cn,
                "issuer_org": issuer_org,
                "chain_valid": chain_ok,
                "chain_error": chain_err,
                "is_known_ca": is_known_ca,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"known_cas": list(sorted(KNOWN_CAS))[:5] + ["..."]},
        )
