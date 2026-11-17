"""Comment: `modules` package — all categories of analysis parameters.

    Each subpackage exposes the MODULES constant, a map
    `{parameter_name: module_class}` that the orchestrator uses for the
    targeted import of only the modules selected by the user.
"""

# Map category -> {name: class} dict.
# Imported here for convenience, but the orchestrator prefers to import
# the individual categories explicitly to respect the constraint of
# "targeted import of only the necessary modules".
from modules import lexical, tls, dns_whois, content, dynamic, reputation

CATEGORIES: dict[str, dict] = {
    "lexical": lexical.MODULES,
    "tls": tls.MODULES,
    "dns_whois": dns_whois.MODULES,
    "content": content.MODULES,
    "dynamic": dynamic.MODULES,
    "reputation": reputation.MODULES,
}

# Human-readable labels for each category (used in the CLI menu).
CATEGORY_LABELS: dict[str, str] = {
    "lexical":   "1. Lessicali e strutturali dell'URL",
    "dns_whois": "2. Registrazione e storico (WHOIS/DNS)",
    "tls":       "3. Cifratura e certificati (SSL/TLS)",
    "content":   "4. Codice sorgente e contenuti",
    "dynamic":   "5. Comportamentali (sandbox)",
    "reputation":"6. Rete, traffico e reputazione",
}

__all__ = ["CATEGORIES", "CATEGORY_LABELS"]
