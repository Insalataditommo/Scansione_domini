"""Comment: TLS / certificate modules (parameters 10-14)."""

from modules.tls.presenza_https import PresenzaHttps
from modules.tls.tipo_certificato import TipoCertificato
from modules.tls.eta_durata_certificato import EtaDurataCertificato
from modules.tls.ca_catena_fiducia import CaCatenaFiducia
from modules.tls.protocolli_cifrari import ProtocolliCifrari

MODULES: dict[str, type] = {
    "presenza_https": PresenzaHttps,
    "tipo_certificato": TipoCertificato,
    "eta_durata_certificato": EtaDurataCertificato,
    "ca_catena_fiducia": CaCatenaFiducia,
    "protocolli_cifrari": ProtocolliCifrari,
}

__all__ = [
    "PresenzaHttps",
    "TipoCertificato",
    "EtaDurataCertificato",
    "CaCatenaFiducia",
    "ProtocolliCifrari",
    "MODULES",
]
