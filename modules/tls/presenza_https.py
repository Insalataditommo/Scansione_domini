"""
modules/tls/presenza_https.py

Comment:
    Parameter 10: presence of HTTPS.

    The absence of HTTPS on pages that collect credentials or sensitive
    data is a very serious signal. The module checks the URL scheme and,
    when HTTPS is missing, attempts to verify reachability on port 443.
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.tls._tlsutils import fetch_tls_info


class PresenzaHttps(BaseModule):
    """Comment: checks the presence of HTTPS and the reachability of TLS."""

    description = "Presenza di HTTPS nello scheme dell'URL."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "presenza_https".
        """
        return "presenza_https"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.8 (high weight, critical signal).
        """
        return 1.8

    def run(self, url: str) -> ModuleResult:
        """Comment: checks the URL scheme and the TLS handshake.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {scheme, ...}, score 0.0 (HTTPS ok),
            0.6 (HTTPS but handshake failed) or 1.0 (plain HTTP),
            outcome SAFE/SUSPICIOUS. NOT_EVALUATED when the URL is empty.
        """
        if not url or not isinstance(url, str):
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL vuoto o non valido.",
            )

        s = url.strip()
        if "://" not in s:
            # Missing scheme: assume HTTP (worst case).
            scheme = "http"
            s_analyzed = "http://" + s
        else:
            try:
                scheme = (urlparse(s).scheme or "").lower()
            except Exception:  # noqa: BLE001
                scheme = "http"
            s_analyzed = s

        if scheme == "https":
            # Verify the server actually responds with TLS.
            info = fetch_tls_info(s_analyzed, timeout=4.0)
            if info.error:
                return ModuleResult(
                    name=self.name(),
                    raw_value={"scheme": "https", "tls_error": info.error},
                    score=0.6,
                    outcome=Outcome.SUSPICIOUS,
                    message=(
                        f"URL in https ma handshake TLS fallita ({info.error}): "
                        f"possibile downgrade o server mal configurato."
                    ),
                )
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "scheme": "https",
                    "protocol": info.protocol_version,
                    "cipher": info.cipher_name,
                },
                score=0.0,
                outcome=Outcome.SAFE,
                message="HTTPS presente e handshake TLS riuscita.",
            )

        # scheme == http
        return ModuleResult(
            name=self.name(),
            raw_value={"scheme": scheme},
            score=1.0,
            outcome=Outcome.SUSPICIOUS,
            message=(
                "URL in HTTP chiaro: nessuna cifratura. Su pagine di login/dati "
                "sensibili è gravissimo e quasi certamente phishing."
            ),
        )
