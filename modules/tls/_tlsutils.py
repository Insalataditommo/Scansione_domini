"""
modules/tls/_tlsutils.py

Comment:
    Shared utilities for the TLS modules:
      - host extraction from a URL;
      - X.509 certificate retrieval via SSL socket (no external dependency
        beyond the standard library `ssl`, with an optional fallback to
        `cryptography` when installed);
      - normalization of the results into a `TlsInfo` dataclass.

    To avoid blocking the analysis on unreachable hosts, all network
    operations use a timeout (default 5 s) and catch exceptions.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 5.0


@dataclass
class CertificateInfo:
    """Comment: information extracted from the server's X.509 certificate."""
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial_number: Optional[str] = None
    version: Optional[int] = None
    san_list: list[str] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    is_ca: Optional[bool] = None
    raw_cert_der: Optional[bytes] = None  # for advanced parsing


@dataclass
class TlsInfo:
    """Comment: result of a TLS handshake."""
    protocol_version: Optional[str] = None
    cipher_name: Optional[str] = None
    cipher_bits: Optional[int] = None
    certificate: Optional[CertificateInfo] = None
    verified: bool = False
    error: Optional[str] = None


def extract_host_port(url: str, default_port: int = 443) -> tuple[str, int] | None:
    """Comment: extracts (host, port) from a URL.

    Input data:
        url:          URL string (with or without scheme).
        default_port: fallback port when not present in the URL.

    Expected output:
        tuple (host, port) lowercased, or None when the URL is invalid or
        has no host.
    """
    if not url or not isinstance(url, str):
        return None
    s = url.strip()
    if "://" not in s:
        s = "https://" + s
    try:
        parsed = urlparse(s)
    except Exception:  # noqa: BLE001
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    port = parsed.port or default_port
    return host, port


def fetch_tls_info(url: str, timeout: float = DEFAULT_TIMEOUT) -> TlsInfo:
    """Comment: performs a TLS handshake against the URL host and collects info.

        Does not actively validate any policy: it only collects metadata.
        On error (timeout, connection refused, handshake failure) returns a
        TlsInfo with `error` populated.

    Input data:
        url:     URL to connect to.
        timeout: socket timeout in seconds.

    Expected output:
        TlsInfo with protocol_version, cipher_name, cipher_bits and
        certificate populated on success; on failure only `error` is set.
    """
    hp = extract_host_port(url)
    if hp is None:
        return TlsInfo(error="URL non valido o host non estraibile.")

    host, port = hp
    info = TlsInfo()

    # Build a TLS context that also accepts invalid certificates: we want
    # to collect information EVEN from servers with unverified certificates,
    # because a self-signed or expired certificate is itself a signal.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                info.protocol_version = ssock.version()
                cipher = ssock.cipher()
                # cipher() returns a 3-tuple: (cipher_name, protocol_version_str,
                # secret_bits). The 2nd element is a STRING (e.g. "TLSv1.3"),
                # NOT the key length — using cipher[1] for bits caused a
                # TypeError when compared with int later. Use cipher[2].
                if cipher and len(cipher) >= 3:
                    info.cipher_name = cipher[0]
                    try:
                        info.cipher_bits = int(cipher[2])
                    except (TypeError, ValueError):
                        info.cipher_bits = None
                elif cipher:
                    info.cipher_name = cipher[0]
                der = ssock.getpeercert(binary_form=True)
                if der:
                    info.certificate = _parse_der(der)
                # check_hostname=False + CERT_NONE => verified always False here
                info.verified = False
    except ssl.SSLError as e:
        info.error = f"SSLError: {e}"
    except socket.timeout:
        info.error = f"Timeout ({timeout}s) durante handshake TLS."
    except socket.gaierror as e:
        info.error = f"DNS resolution fallita: {e}"
    except ConnectionRefusedError:
        info.error = "Connessione rifiutata (porta 443 chiusa?)."
    except OSError as e:
        info.error = f"Errore di rete: {e}"
    except Exception as e:  # noqa: BLE001
        info.error = f"Errore generico TLS: {e}"
    return info


def verify_tls_chain(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, str | None]:
    """Comment: performs a TLS handshake with full trust chain verification.

    Input data:
        url:     URL to connect to.
        timeout: socket timeout in seconds.

    Expected output:
        tuple (ok, error_message); (True, None) on a verified chain,
        (False, message) on any failure. Used by the `ca_catena_fiducia` module.
    """
    hp = extract_host_port(url)
    if hp is None:
        return False, "URL non valido o host non estraibile."
    host, port = hp

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                _ = ssock.version()
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, f"Verifica catena fallita: {e.verify_message}"
    except ssl.SSLError as e:
        return False, f"SSLError: {e}"
    except socket.timeout:
        return False, "Timeout durante handshake TLS."
    except socket.gaierror as e:
        return False, f"DNS resolution fallita: {e}"
    except ConnectionRefusedError:
        return False, "Connessione rifiutata."
    except OSError as e:
        return False, f"Errore di rete: {e}"
    except Exception as e:  # noqa: BLE001
        return False, f"Errore generico: {e}"


def _parse_der(der: bytes) -> CertificateInfo:
    """Comment: extracts information from a DER-encoded certificate.

        First tries the `cryptography` library (when installed); otherwise
        uses the dict returned by ssl.DER_cert_to_PEM_cert + the `ssl`
        parser (which gives limited access to subject/issuer/notBefore/
        notAfter).

    Input data:
        der: DER bytes of the X.509 certificate.

    Expected output:
        CertificateInfo populated with subject, issuer, validity, serial,
        version, SAN list, signature algorithm and is_ca flag.
    """
    cert = CertificateInfo(raw_cert_der=der)

    # 1) Try with cryptography.
    try:
        from cryptography import x509  # type: ignore
        from cryptography.x509.oid import ExtensionOID  # type: ignore

        xc = x509.load_der_x509_certificate(der)
        cert.subject = _name_to_dict(xc.subject)
        cert.issuer = _name_to_dict(xc.issuer)
        try:
            cert.not_before = xc.not_valid_before_utc.isoformat()
        except AttributeError:
            cert.not_before = xc.not_valid_before.isoformat()
        try:
            cert.not_after = xc.not_valid_after_utc.isoformat()
        except AttributeError:
            cert.not_after = xc.not_valid_after.isoformat()
        cert.serial_number = format(xc.serial_number, "x")
        cert.version = int(xc.version.value) if xc.version else None
        try:
            cert.signature_algorithm = xc.signature_algorithm_oid._name
        except Exception:  # noqa: BLE001
            cert.signature_algorithm = None
        try:
            basic = xc.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            cert.is_ca = bool(basic.ca)
        except x509.ExtensionNotFound:
            cert.is_ca = False
        except Exception:  # noqa: BLE001
            cert.is_ca = None
        try:
            san = xc.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            cert.san_list = list(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            cert.san_list = []
        except Exception:  # noqa: BLE001
            cert.san_list = []
        return cert
    except ImportError:
        pass

    # 2) Fallback: use the standard ssl library via _ssl._test_decode_cert.
    #    Returns a dict with subject/issuer as a list of 2-tuples (not a dict),
    #    notBefore/notAfter as RFC strings, serialNumber as hex string.
    #    This works without cryptography installed.
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = ssl._ssl._test_decode_cert(pem)  # type: ignore[attr-defined]
        cert.subject = _rfc4514_tuples_to_dict(parsed.get("subject", []))
        cert.issuer = _rfc4514_tuples_to_dict(parsed.get("issuer", []))
        cert.not_before = parsed.get("notBefore")
        cert.not_after = parsed.get("notAfter")
        cert.serial_number = parsed.get("serialNumber")
        cert.san_list = _extract_san_list(parsed.get("subjectAltName", []))
        return cert
    except Exception:  # noqa: BLE001
        return cert


def _rfc4514_tuples_to_dict(name_field) -> dict[str, str]:
    """Comment: converts an ssl-parsed subject/issuer (list of tuples of
    tuples) into a flat {oid_name: value} dict, mirroring the format
    produced by the `cryptography` backend.

    Input data:
        name_field: ssl._test_decode_cert output for subject/issuer, which is
                    a list of tuples like [("commonName", "example.com")] or
                    a nested list of such tuples.

    Expected output:
        dict[str, str] mapping attribute name -> value (last value wins on
        duplicates, mirroring _name_to_dict behaviour); empty dict on any
        error.
    """
    out: dict[str, str] = {}
    try:
        flat: list = []
        if isinstance(name_field, list):
            flat.extend(name_field)
        # The standard ssl parser returns a list of lists of 2-tuples:
        #   [[("commonName", "x.com"), ("organizationName", "Y")]]
        for item in flat:
            if isinstance(item, tuple) and len(item) == 2:
                k, v = item
                out[str(k)] = v
            elif isinstance(item, list):
                for sub in item:
                    if isinstance(sub, tuple) and len(sub) == 2:
                        out[str(sub[0])] = sub[1]
    except Exception:  # noqa: BLE001
        pass
    return out


def _extract_san_list(san_field) -> list[str]:
    """Comment: extracts the DNS names from an ssl-parsed subjectAltName field.

    Input data:
        san_field: list of tuples like [("DNS", "example.com"),
                   ("DNS", "www.example.com"), ("IP Address", "1.2.3.4")].

    Expected output:
        list[str] of DNS SAN entries only; non-DNS entries are skipped.
    """
    out: list[str] = []
    try:
        for item in san_field or []:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "DNS":
                out.append(str(item[1]))
    except Exception:  # noqa: BLE001
        pass
    return out


def _name_to_dict(name) -> dict[str, str]:
    """Comment: converts a cryptography.x509.Name into a {oid_name: value} dict.

    Input data:
        name: cryptography.x509.Name object.

    Expected output:
        dict[str, str]; empty dict on any error.
    """
    out: dict[str, str] = {}
    try:
        for attr in name:
            out[attr.oid._name] = attr.value
    except Exception:  # noqa: BLE001
        pass
    return out
