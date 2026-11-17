"""Comment: behavioral / HTTP-observable modules (parameters 29-35, implemented except exploit/richieste_c2 stubs)."""

from modules.dynamic.dynamic_modules import (
    RedirectChain,
    Cloaking,
    DriveByDownload,
    Exploit,
    RichiesteC2,
    BrowserManipolation,
    Cryptojacking,
)

MODULES: dict[str, type] = {
    "redirect_chain": RedirectChain,
    "cloaking": Cloaking,
    "drive_by_download": DriveByDownload,
    "exploit": Exploit,
    "richieste_c2": RichiesteC2,
    "browser_manipolation": BrowserManipolation,
    "cryptojacking": Cryptojacking,
}

__all__ = [
    "RedirectChain", "Cloaking", "DriveByDownload", "Exploit",
    "RichiesteC2", "BrowserManipolation", "Cryptojacking", "MODULES",
]
