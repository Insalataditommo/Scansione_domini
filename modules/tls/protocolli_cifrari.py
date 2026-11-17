"""
modules/tls/protocolli_cifrari.py

Comment:
    Parameter 14: supported protocol versions and ciphers.

    Verifies that the server uses modern TLS protocols (>= 1.2) and strong
    ciphers. The use of SSLv3, TLS 1.0 or 1.1, or ciphers with XOR/RC4/3DES
    is considered deprecated and potentially exploitable (BEAST, POODLE,
    etc.). It is not per se a phishing indicator, but it signals a
    neglected infrastructure, often typical of pages quickly created for
    a campaign.
"""

from __future__ import annotations

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.tls._tlsutils import fetch_tls_info

# Protocols considered insecure (deprecated or with known vulnerabilities).
INSECURE_PROTOCOLS: frozenset[str] = frozenset(
    {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
)

# Ciphers considered weak (by name or keywords in the name).
INSECURE_CIPHER_KEYWORDS: tuple[str, ...] = (
    "RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon", "CBC",
    "IDEA", "RC2",
)


class ProtocolliCifrari(BaseModule):
    """Comment: evaluates the TLS protocol version and the negotiated cipher."""

    description = "Versione protocollo TLS e cifrario negoziato."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "protocolli_cifrari".
        """
        return "protocolli_cifrari"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: evaluates the negotiated TLS protocol and cipher.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {protocol, cipher, cipher_bits},
            score in [0,1], outcome SAFE/NEUTRAL/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the TLS handshake fails.
        """
        info = fetch_tls_info(url, timeout=5.0)
        if info.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Handshake TLS non valutata: {info.error}",
            )

        protocol = info.protocol_version or ""
        cipher = info.cipher_name or ""
        bits = info.cipher_bits

        protocol_score = _protocol_score(protocol)
        cipher_score = _cipher_score(cipher, bits)
        score = max(protocol_score, cipher_score)

        signals: list[str] = []
        if protocol in INSECURE_PROTOCOLS:
            signals.append(f"protocollo {protocol} deprecato")
        if cipher and _cipher_is_weak(cipher):
            signals.append(f"cifrario debole ({cipher})")
        if bits is not None and bits < 128:
            signals.append(f"chiave {bits} bit (< 128)")

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = "Configurazione TLS debole: " + "; ".join(signals) + "."
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = "Configurazione TLS migliorabile: " + "; ".join(signals) + "."
        else:
            outcome = Outcome.SAFE
            msg = f"Protocollo {protocol} e cifrario {cipher} ({bits} bit): nella norma."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "protocol": protocol,
                "cipher": cipher,
                "cipher_bits": bits,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "insecure_protocols": sorted(INSECURE_PROTOCOLS),
                "min_bits": 128,
            },
        )


def _protocol_score(protocol: str) -> float:
    """Comment: score based on the protocol version.

    Input data:
        protocol: protocol name (e.g. "TLSv1.2").

    Expected output:
        float in [0, 1]; 1.0 for SSLv2/SSLv3, 0.8 for TLSv1/TLSv1.1,
        0.1 for TLSv1.2, 0.0 for TLSv1.3, 0.3 for unknown (cautious).
    """
    p = (protocol or "").upper()
    if p in ("SSLV2", "SSLV3"):
        return 1.0
    if p in ("TLSV1", "TLSV1.1"):
        return 0.8
    if p == "TLSV1.2":
        return 0.1
    if p == "TLSV1.3":
        return 0.0
    return 0.3  # unknown: cautious


def _cipher_is_weak(cipher: str) -> bool:
    """Comment: detects whether the cipher is weak.

    Input data:
        cipher: cipher name (e.g. "ECDHE-RSA-AES256-GCM-SHA384").

    Expected output:
        bool, True if any INSECURE_CIPHER_KEYWORDS substring is in the name.
    """
    c = (cipher or "").upper()
    return any(kw in c for kw in INSECURE_CIPHER_KEYWORDS)


def _cipher_score(cipher: str, bits: int | None) -> float:
    """Comment: score based on the cipher strength.

    Input data:
        cipher: cipher name.
        bits:   key length in bits (or None).

    Expected output:
        float in [0, 1]; 0.9 for weak ciphers, 0.7 when bits < 128,
        0.0 otherwise.
    """
    if _cipher_is_weak(cipher):
        return 0.9
    if bits is not None and bits < 128:
        return 0.7
    return 0.0
