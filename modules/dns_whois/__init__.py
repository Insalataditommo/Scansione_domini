"""Comment: WHOIS / DNS modules (parameters 15-22, full implementation)."""

from modules.dns_whois.whois_dns_modules import (
    EtaDominio,
    DurataRegistrazione,
    AnonimatoWhois,
    ReputazioneIpAsn,
    FastFluxDns,
    TtlDns,
    SpfDkimDmarc,
    Dnssec,
)

MODULES: dict[str, type] = {
    "eta_dominio": EtaDominio,
    "durata_registrazione": DurataRegistrazione,
    "anonimato_whois": AnonimatoWhois,
    "reputazione_ip_asn": ReputazioneIpAsn,
    "fast_flux_dns": FastFluxDns,
    "ttl_dns": TtlDns,
    "spf_dkim_dmarc": SpfDkimDmarc,
    "dnssec": Dnssec,
}

__all__ = [
    "EtaDominio", "DurataRegistrazione", "AnonimatoWhois",
    "ReputazioneIpAsn", "FastFluxDns", "TtlDns", "SpfDkimDmarc", "Dnssec",
    "MODULES",
]
