"""Comment: lexical and structural URL modules (parameters 1-9)."""

from modules.lexical.lunghezza import LunghezzaUrlDominio
from modules.lexical.entropia import EntropiaCaratteri
from modules.lexical.sottodomini import Sottodomini
from modules.lexical.parole_chiave import ParoleChiaveSensibili
from modules.lexical.typosquatting import TyposquattingOmografi
from modules.lexical.caratteri_speciali import CaratteriSpecialiNumeri
from modules.lexical.tld_sospetti import TldSospetti
from modules.lexical.ip_in_url import IpInUrl
from modules.lexical.url_shortener import UrlShortener

# Registry: module name -> module class. The orchestrator uses this map
# for targeted import based on the parameters selected by the user.
MODULES: dict[str, type] = {
    "lunghezza_url_dominio": LunghezzaUrlDominio,
    "entropia_caratteri": EntropiaCaratteri,
    "sottodomini": Sottodomini,
    "parole_chiave_sensibili": ParoleChiaveSensibili,
    "typosquatting_omografi": TyposquattingOmografi,
    "caratteri_speciali_numeri": CaratteriSpecialiNumeri,
    "tld_sospetti": TldSospetti,
    "ip_in_url": IpInUrl,
    "url_shortener": UrlShortener,
}

__all__ = [
    "LunghezzaUrlDominio",
    "EntropiaCaratteri",
    "Sottodomini",
    "ParoleChiaveSensibili",
    "TyposquattingOmografi",
    "CaratteriSpecialiNumeri",
    "TldSospetti",
    "IpInUrl",
    "UrlShortener",
    "MODULES",
]
