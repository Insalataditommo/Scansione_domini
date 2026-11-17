"""Comment: reputation / traffic modules (parameters 36-39; 36+37 implemented, 38+39 honest stubs)."""

from modules.reputation.reputation_modules import (
    BlacklistThreatIntel,
    PopolaritaTraffico,
    SegnalazioniUtenti,
    CorrelazioneEmail,
)

MODULES: dict[str, type] = {
    "blacklist_threat_intel": BlacklistThreatIntel,
    "popolarita_traffico": PopolaritaTraffico,
    "segnalazioni_utenti": SegnalazioniUtenti,
    "correlazione_email": CorrelazioneEmail,
}

__all__ = [
    "BlacklistThreatIntel", "PopolaritaTraffico",
    "SegnalazioniUtenti", "CorrelazioneEmail", "MODULES",
]
