"""
modules/dynamic/dynamic_modules.py

Comment:
    Section 5 parameters (behavioral / HTTP-observable) — implementation.

    SECURITY CONSTRAINTS (from the user's prompt):
     - Dynamic analysis MUST happen in an isolated sandbox:
       * container without access to the internal corporate network;
       * headless browser with a throwaway profile;
       * strict timeouts (5-15 s per page, 30 s overall);
       * full network traffic logging (PCAP/HAR);
       * no execution of code received from the URLs;
       * no implementation of exploits nor mechanisms to execute
         downloaded content.
     - The modules below implement ONLY the collection of HTTP-observable
       metadata (redirect chain, headers, response body). No headless
       browser is launched, no script is executed.
     - The `exploit` parameter is an explicit stub: exploit detection
       requires a dedicated sandbox (e.g. Cuckoo Sandbox) external to
       this project and is not implemented.
     - The `richieste_c2` parameter requires Playwright + network logging;
       it stays as a stub documenting the recommended approach.
"""

from __future__ import annotations

import hashlib
import re

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.content._httputils import fetch_url, get_registered_domain, parse_html, same_registered_domain


# ---------------------------------------------------------------------------
# Parameter 29: redirect chain
# ---------------------------------------------------------------------------
class RedirectChain(BaseModule):
    """Comment: analyzes the HTTP redirect chain (3xx) up to the final
        destination.

        A long redirect chain that ends on a different registered domain
        is a classic phishing evasion tactic (the user sees the initial
        "safe" URL, the browser silently lands on the attacker's domain).

        Threshold:
          - 0-2 hops, same registered domain -> SAFE 0.0;
          - 3-5 hops OR final domain != initial -> NEUTRAL 0.5;
          - > 5 hops OR https -> http downgrade -> SUSPICIOUS 0.9.
    """

    description = "Catena di redirect HTTP fino alla destinazione finale."

    MAX_HOPS_NEUTRO = 2
    MAX_HOPS_SOSPETTO = 5

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "redirect_chain".
        """
        return "redirect_chain"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: fetches the URL following redirects and analyzes the chain.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hops, chain, initial_domain,
            final_domain, scheme_downgrade}, score in [0,1].
        """
        res = fetch_url(url, allow_redirects=True)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={
                    "max_hops_neutro": self.MAX_HOPS_NEUTRO,
                    "max_hops_sospetto": self.MAX_HOPS_SOSPETTO,
                },
            )

        hops = len(res.history)
        chain = res.history + [res.url or url]
        initial_domain = get_registered_domain(url) or ""
        final_domain = get_registered_domain(res.url or url) or ""
        scheme_downgrade = (
            url.lower().startswith("https://")
            and (res.url or "").lower().startswith("http://")
        )

        if scheme_downgrade:
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Downgrade di schema https -> http durante la catena: "
                f"perdita di cifratura, fortemente sospetto."
            )
        elif hops > self.MAX_HOPS_SOSPETTO:
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Catena di redirect lunga ({hops} hop, > {self.MAX_HOPS_SOSPETTO}): "
                f"pattern tipico di offuscamento della destinazione."
            )
        elif hops > self.MAX_HOPS_NEUTRO or (
            initial_domain and final_domain and initial_domain != final_domain
        ):
            score = 0.5
            outcome = Outcome.NEUTRAL
            msg = (
                f"Catena di redirect con cambio di dominio ({initial_domain} -> "
                f"{final_domain}, {hops} hop): valutare contesto."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Catena di redirect lineare ({hops} hop, dominio finale "
                f"{final_domain})."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hops": hops,
                "chain": chain,
                "initial_domain": initial_domain,
                "final_domain": final_domain,
                "scheme_downgrade": scheme_downgrade,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "max_hops_neutro": self.MAX_HOPS_NEUTRO,
                "max_hops_sospetto": self.MAX_HOPS_SOSPETTO,
            },
        )


# ---------------------------------------------------------------------------
# Parameter 30: cloaking
# ---------------------------------------------------------------------------
class Cloaking(BaseModule):
    """Comment: detects user-agent based cloaking.

        Phishing pages often serve different content to bots/crawlers vs
        real browsers, to evade detection by Google Safe Browsing and
        security scanners.

        Approach: fetch the URL twice (desktop UA + a search-engine UA),
        compare the response body hashes. A significant difference is a
        strong cloaking signal.

        Threshold:
          - identical hashes -> SAFE 0.0;
          - different hashes, same length (minor variation) -> NEUTRAL 0.4;
          - different hashes, very different length (> 30%) -> SUSPICIOUS 0.9.
    """

    description = "Cloaking basato su User-Agent (confronto 2 fetch)."

    SEARCH_ENGINE_UA = (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "cloaking".
        """
        return "cloaking"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, strong evasion signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: fetches the URL twice with different UAs and compares.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hash_browser, hash_bot,
            length_browser, length_bot, length_ratio}, score in [0,1].
        """
        res_browser = fetch_url(url, allow_redirects=False)
        # Override the User-Agent via a direct requests call to use the
        # search-engine UA. We import lazily so that requests is only
        # required for this specific module.
        bot_text = ""
        bot_status = None
        bot_error = None
        try:
            import requests  # type: ignore

            r = requests.get(
                url,
                headers={"User-Agent": self.SEARCH_ENGINE_UA},
                timeout=8.0,
                allow_redirects=False,
                verify=True,
            )
            bot_text = r.text or ""
            bot_status = r.status_code
        except ImportError:
            bot_error = "requests non installato"
        except Exception as exc:  # noqa: BLE001
            bot_error = f"{exc.__class__.__name__}: {exc}"

        if res_browser.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch browser fallito: {res_browser.error}",
            )
        if bot_error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch bot fallito: {bot_error}",
            )

        hash_b = hashlib.sha256(res_browser.text.encode("utf-8", errors="replace")).hexdigest()
        hash_bot = hashlib.sha256(bot_text.encode("utf-8", errors="replace")).hexdigest()
        len_b = len(res_browser.text)
        len_bot = len(bot_text)
        ratio = min(len_b, len_bot) / max(1, max(len_b, len_bot))

        if hash_b == hash_bot:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Risposta identica a browser e bot: nessun cloaking basato su UA."
        elif ratio < 0.7:
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Risposte molto diverse tra browser ({len_b} byte) e bot "
                f"({len_bot} byte, ratio {ratio:.2f}): cloaking probabile."
            )
        else:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"Risposte diverse ma di lunghezza simile (ratio {ratio:.2f}): "
                f"variazione minore, possibile A/B testing o bot mitigation."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hash_browser": hash_b,
                "hash_bot": hash_bot,
                "length_browser": len_b,
                "length_bot": len_bot,
                "length_ratio": round(ratio, 3),
                "status_browser": res_browser.status,
                "status_bot": bot_status,
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# ---------------------------------------------------------------------------
# Parameter 31: drive-by download
# ---------------------------------------------------------------------------
class DriveByDownload(BaseModule):
    """Comment: detects automatic download of executable content.

        A page that returns an executable MIME type (application/octet-stream,
        application/x-msdownload, application/vnd.android.package-archive)
        on a non-download URL (i.e. not a software vendor's download page)
        is a strong drive-by signal.

        Threshold:
          - executable MIME type on the response -> SUSPICIOUS 0.9;
          - Content-Disposition attachment with executable extension -> SUSPICIOUS 0.9;
          - otherwise -> SAFE 0.0.
    """

    description = "Drive-by download (Content-Type / Disposition eseguibile)."

    EXEC_MIMES: tuple[str, ...] = (
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
        "application/vnd.android.package-archive",
        "application/x-sh",
        "application/java-archive",
    )
    EXEC_EXTS: tuple[str, ...] = (
        ".exe", ".apk", ".jar", ".scr", ".msi", ".bat", ".dll", ".deb",
        ".rpm", ".pif", ".hta", ".ps1",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "drive_by_download".
        """
        return "drive_by_download"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, malware delivery signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: inspects Content-Type / Content-Disposition of the response.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {content_type, content_disposition,
            is_exec}, score in [0,1].
        """
        res = fetch_url(url, allow_redirects=True)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={"exec_mimes": list(self.EXEC_MIMES)},
            )

        ct = (res.headers.get("content-type") or "").split(";")[0].strip().lower()
        cd = (res.headers.get("content-disposition") or "").lower()
        # Try to extract filename extension from Content-Disposition.
        ext_match = re.search(r'filename[^;=\n]*=([^;\n]+)', cd)
        filename = ext_match.group(1).strip().strip('"\'') if ext_match else ""
        is_exec_mime = ct in self.EXEC_MIMES
        is_exec_ext = any(filename.lower().endswith(ext) for ext in self.EXEC_EXTS)

        if is_exec_mime or is_exec_ext:
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Risposta con content-type eseguibile ('{ct}') "
                f"o filename '{filename}': drive-by download probabile."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Content-Type '{ct}' non eseguibile, nessun drive-by rilevato."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "content_type": ct,
                "content_disposition": cd,
                "filename": filename,
                "is_exec": is_exec_mime or is_exec_ext,
                "status": res.status,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"exec_mimes": list(self.EXEC_MIMES)},
        )


# ---------------------------------------------------------------------------
# Parameter 32: exploit (sandbox stub)
# ---------------------------------------------------------------------------
class Exploit(BaseModule):
    """Comment: stub for exploit detection.

        Real exploit detection requires a dedicated sandbox (Cuckoo,
        ANY.RUN, Joe Sandbox) that instruments the process, file system
        and registry activity of a browser visiting the URL. This is
        out of scope for a pure-Python static/HTTP analyzer.

        STUB INTENTIONAL — not implemented for security constraints.
    """

    description = "STUB: rilevamento exploit (richiede sandbox esterna)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "exploit".
        """
        return "exploit"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.0 (stub, never contributes).
        """
        return 0.0

    def run(self, url: str) -> ModuleResult:
        """Comment: STUB — returns NOT_EVALUATED with a clear message.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult NOT_EVALUATED with a message explaining that
            real exploit detection requires an external sandbox.
        """
        return ModuleResult(
            name=self.name(),
            outcome=Outcome.NOT_EVALUATED,
            message=(
                "STUB intenzionale: il rilevamento di exploit richiede sandbox "
                "esterna (Cuckoo/ANY.RUN). Non implementato per vincoli di sicurezza."
            ),
        )


# ---------------------------------------------------------------------------
# Parameter 33: C2 requests (sandbox stub)
# ---------------------------------------------------------------------------
class RichiesteC2(BaseModule):
    """Comment: stub for C2 (command & control) request detection.

        Requires a headless browser with full network logging (Playwright
        + HAR/PCAP capture) to observe outbound requests to known C2
        infrastructure. Out of scope for the HTTP-only analyzer.

        STUB — implementation documented in the docstring, not enabled.
    """

    description = "STUB: richieste C2 (richiede Playwright + network logging)."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "richieste_c2".
        """
        return "richieste_c2"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (would be high weight when implemented).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: STUB — returns NOT_EVALUATED.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult NOT_EVALUATED explaining the Playwright requirement.
        """
        return ModuleResult(
            name=self.name(),
            outcome=Outcome.NOT_EVALUATED,
            message=(
                "STUB: richiede headless browser con logging rete (Playwright + HAR). "
                "Non implementato in questa versione."
            ),
        )


# ---------------------------------------------------------------------------
# Parameter 34: browser manipulation (scareware / scare tactics)
# ---------------------------------------------------------------------------
class BrowserManipolation(BaseModule):
    """Comment: detects browser manipulation patterns (scareware, fake
        alerts, "your PC is infected" popups).

        These are pure-content patterns visible in the HTML/JS, so they
        can be detected without a sandbox. The dictionary covers Italian
        and English scareware phrases.

        Threshold:
          - 0 hits -> SAFE 0.0;
          - 1-2 hits -> NEUTRAL 0.5;
          - >= 3 hits -> SUSPICIOUS 1.0.
    """

    description = "Manipolazione browser (scareware, falsi allarmi virus)."

    SCAREWARE_PATTERNS: tuple[str, ...] = (
        "your pc is infected", "virus detected", "download antivirus",
        "il tuo pc è infetto", "il tuo pc e infetto", "scarica l'antivirus",
        "your computer is infected", "malware detected",
        "trojan detected", "system infected", "mac is infected",
        "5 virus sul tuo pc", "your iphone has been infected",
        "your device has been compromised", "alerta de virus",
        "windows defender alert", "pornographic spyware",
        "suspicious activity detected", "your apple id has been locked",
        "il tuo account apple è stato bloccato",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "browser_manipolation".
        """
        return "browser_manipolation"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: searches for scareware phrases in the page source.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hits, patterns_matched}, score.
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={"patterns": list(self.SCAREWARE_PATTERNS)[:8]},
            )
        # Scan the full response (HTML + inline JS) lowercased.
        haystack = (res.text or "").lower()
        matched = [p for p in self.SCAREWARE_PATTERNS if p in haystack]
        n = len(matched)
        if n == 0:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Nessun pattern di scareware/manipolazione browser rilevato."
        elif n <= 2:
            score = 0.5
            outcome = Outcome.NEUTRAL
            msg = (
                f"Trovati {n} pattern di scareware ({', '.join(matched[:3])}): "
                f"valutare contesto."
            )
        else:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovati {n} pattern di scareware ({', '.join(matched[:5])}): "
                f"pagina di manipolazione browser tipica di tech support scam."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hits": n,
                "patterns_matched": matched,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"patterns": list(self.SCAREWARE_PATTERNS)[:8]},
        )


# ---------------------------------------------------------------------------
# Parameter 35: cryptojacking
# ---------------------------------------------------------------------------
class Cryptojacking(BaseModule):
    """Comment: detects cryptojacking scripts (in-browser miners).

        Phishing pages and compromised sites sometimes embed in-browser
        cryptocurrency miners (Coinhive, CryptoLoot, JSEcoin) that drain
        the visitor's CPU. Detection is straightforward: look for the
        known miner domains in <script src> attributes.

        Threshold:
          - 0 miner scripts -> SAFE 0.0;
          - >= 1 miner script -> SUSPICIOUS 1.0.
    """

    description = "Cryptojacking (script di mining in-browser)."

    MINER_DOMAINS: tuple[str, ...] = (
        "coinhive.com", "authedmine.com", "cryptoloot.com", "coin-have.com",
        "load.jsecoin.com", "coinerra.com", "crypto-loot.com",
        "deepmine.io", "webmine.cz", "monerominer.rocks",
        "minero.cc", "projectpoi.com", "coinhive.lib",
        "miner.pr0gramm.com", "authmine", "coin-hive",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "cryptojacking".
        """
        return "cryptojacking"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: scans <script src> for known miner domains.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {miner_count, matched_domains,
            script_srcs}, score in [0,1].
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={"domains": list(self.MINER_DOMAINS)},
            )

        soup = parse_html(res.text)
        scripts = soup.find_all("script") if hasattr(soup, "find_all") else []
        srcs = [s.get("src") for s in scripts if s.get("src")]
        # Also scan the raw HTML for the miner domains (covers inline
        # loaders and obfuscated bootstraps).
        haystack = (res.text or "").lower() + " " + " ".join(srcs).lower()
        matched = [d for d in self.MINER_DOMAINS if d in haystack]

        if matched:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovati {len(matched)} domini di miner in-browser "
                f"({', '.join(matched[:3])}): cryptojacking attivo."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Nessuno script di mining in-browser rilevato."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "miner_count": len(matched),
                "matched_domains": matched,
                "script_srcs": srcs[:10],
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"domains": list(self.MINER_DOMAINS)},
        )
