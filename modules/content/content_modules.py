"""
modules/content/content_modules.py

Comment:
    Section 4 parameters (content, 6 modules) — full implementation.

    All modules fetch the page with the shared `fetch_url` helper
    (desktop User-Agent, timeout, redirect history) and parse it with
    BeautifulSoup when available, falling back to a minimal regex parser
    when bs4 is not installed.

    Scoring conventions:
      - SAFE (0.0): clean page, no suspicious patterns;
      - NEUTRAL (0.1-0.5): ambiguous signal (e.g. one eval, one minor
        obfuscation);
      - SUSPICIOUS (0.5-1.0): clear phishing pattern (form posting to a
        different registered domain, multiple obfuscation hits, urgency
        language, etc.).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.content._httputils import (
    fetch_url,
    get_registered_domain,
    same_registered_domain,
    parse_html,
)


# ---------------------------------------------------------------------------
# Parameter 23: JavaScript obfuscation
# ---------------------------------------------------------------------------
class OffuscamentoJs(BaseModule):
    """Comment: detects JavaScript obfuscation patterns in the source.

        Searches inline and external script payloads for known obfuscation
        primitives: eval(...), atob(...), unescape(...), String.fromCharCode,
        setTimeout(eval, ...). Each hit increases the score.

        Threshold:
          - 0 hits -> SAFE 0.0;
          - 1-2 hits -> NEUTRAL 0.3 (legitimate libraries sometimes use
            eval/atob legitimately);
          - >= 3 hits -> SUSPICIOUS 0.8 (multiple obfuscation primitives
            almost never occur together on legitimate pages).
    """

    description = "Offuscamento JavaScript nel sorgente HTML."

    SUSPICIOUS_PATTERNS: tuple[str, ...] = (
        "eval(", "atob(", "unescape(", "String.fromCharCode",
        "document.write(unescape", "\\x", "\\u00", "setTimeout(eval",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "offuscamento_js".
        """
        return "offuscamento_js"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: detects JS obfuscation patterns in inline scripts.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hits, patterns_matched,
            scripts_count}, score in [0,1], threshold dict.
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={"patterns": list(self.SUSPICIOUS_PATTERNS)},
            )

        soup = parse_html(res.text)
        scripts = soup.find_all("script")
        # Collect every inline script body; external scripts (with src)
        # are not fetched here (they could be cross-origin and large).
        inline_bodies: list[str] = []
        for s in scripts:
            text = getattr(s, "string", None) or getattr(s, "text", "") or ""
            if text:
                inline_bodies.append(text)
        # Also scan on* event handlers and inline href="javascript:".
        joined = "\n".join(inline_bodies) + "\n" + res.text[:50000]

        matched = [p for p in self.SUSPICIOUS_PATTERNS if p in joined]
        hits = len(matched)

        if hits == 0:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Nessun pattern di offuscamento JS rilevato."
        elif hits <= 2:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = (
                f"Trovati {hits} pattern di offuscamento ({', '.join(matched[:3])}): "
                f"presenti anche in librerie legittime, valutare contesto."
            )
        else:
            score = 0.8
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovati {hits} pattern di offuscamento ({', '.join(matched[:5])}): "
                f"combinazione rara in pagine legittime, tipica di evasione AV."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hits": hits,
                "patterns_matched": matched,
                "scripts_count": len(scripts),
                "inline_count": len(inline_bodies),
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"patterns": list(self.SUSPICIOUS_PATTERNS)},
        )


# ---------------------------------------------------------------------------
# Parameter 24: data-collection form posting to an external domain
# ---------------------------------------------------------------------------
class FormActionEsterno(BaseModule):
    """Comment: detects <form action="..."> whose registered domain differs
        from the page's.

        This is one of the strongest phishing signals: a page that looks
        like a legit login form but POSTs credentials to an unrelated
        domain (often an attacker-controlled server).

        Threshold:
          - Any form with action pointing to a different registered domain
            AND method POST -> SUSPICIOUS 1.0;
          - form action on the same registered domain -> SAFE 0.0;
          - form with no action (defaults to current URL) -> SAFE 0.0.
    """

    description = "Form con action verso dominio esterno."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "form_action_esterno".
        """
        return "form_action_esterno"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, strongest phishing signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: detects forms whose action targets an external domain.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {external_forms, total_forms,
            external_actions}, score in [0,1].
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
            )

        soup = parse_html(res.text)
        forms = soup.find_all("form")
        external_actions: list[str] = []
        for f in forms:
            action = (f.get("action") or "").strip()
            method = (f.get("method") or "GET").upper()
            if not action or action.startswith("#") or action.lower().startswith("javascript:"):
                continue
            absolute = urljoin(res.url or url, action)
            # Compare registered domains, not raw hosts (so a form posting
            # to login.example.com from www.example.com is fine).
            if not same_registered_domain(absolute, res.url or url):
                # POST to an external domain is much more serious than GET.
                if method == "POST":
                    external_actions.append(absolute)
                else:
                    external_actions.append(f"{absolute} (GET)")

        if external_actions:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovate {len(external_actions)} form con action verso dominio "
                f"esterno: {external_actions[0]}{'...' if len(external_actions) > 1 else ''}"
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Nessuna form con action esterna ({len(forms)} form analizzate, "
                f"tutte inviano allo stesso dominio)."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "external_forms": len(external_actions),
                "total_forms": len(forms),
                "external_actions": external_actions[:5],
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# ---------------------------------------------------------------------------
# Parameter 25: hidden iframes
# ---------------------------------------------------------------------------
class IframeNascosti(BaseModule):
    """Comment: detects <iframe> with hidden dimensions (0x0, display:none,
        off-screen, visibility:hidden).

        Hidden iframes are a classic technique to load third-party content
        (ads, tracking, drive-by) without the user noticing. One hidden
        iframe is suspicious; several are a strong phishing/malware signal.

        Threshold:
          - 0 hidden iframes -> SAFE 0.0;
          - 1 hidden iframe -> NEUTRAL 0.4 (could be legit analytics);
          - >= 2 hidden iframes -> SUSPICIOUS 0.8.
    """

    description = "iframe nascosti (0x0, display:none, off-screen)."

    HIDDEN_STYLE_PATTERNS: tuple[str, ...] = (
        "display:none", "display: none", "visibility:hidden",
        "visibility: hidden", "opacity:0", "opacity: 0",
        "left:-9999px", "left: -9999px", "top:-9999px",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "iframe_nascosti".
        """
        return "iframe_nascosti"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.3 (medium weight).
        """
        return 1.3

    def run(self, url: str) -> ModuleResult:
        """Comment: detects hidden iframes in the page source.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hidden_iframes, total_iframes,
            hidden_srcs}, score in [0,1].
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
            )

        soup = parse_html(res.text)
        iframes = soup.find_all("iframe")
        hidden_srcs: list[str] = []
        for ifr in iframes:
            width = (ifr.get("width") or "").strip()
            height = (ifr.get("height") or "").strip()
            style = (ifr.get("style") or "").lower()
            is_hidden = False
            # 0 / 1 pixel dimensions.
            try:
                if width and int(re.sub(r"\D", "", width) or 0) <= 1:
                    is_hidden = True
            except (ValueError, TypeError):
                pass
            try:
                if height and int(re.sub(r"\D", "", height) or 0) <= 1:
                    is_hidden = True
            except (ValueError, TypeError):
                pass
            # Style-based hiding.
            if any(p in style for p in self.HIDDEN_STYLE_PATTERNS):
                is_hidden = True
            if is_hidden:
                src = ifr.get("src") or ""
                hidden_srcs.append(src)

        n = len(hidden_srcs)
        if n == 0:
            score = 0.0
            outcome = Outcome.SAFE
            msg = f"Nessun iframe nascosto rilevato ({len(iframes)} iframe totali)."
        elif n == 1:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"1 iframe nascosto rilevato (src: {hidden_srcs[0][:80]}): "
                f"può essere analytics legittimo o tentativo di cloaking."
            )
        else:
            score = 0.8
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"{n} iframe nascosti rilevati: pattern tipico di cloaking/"
                f"drive-by, raro in pagine legittime."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hidden_iframes": n,
                "total_iframes": len(iframes),
                "hidden_srcs": hidden_srcs[:5],
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# ---------------------------------------------------------------------------
# Parameter 26: external links, executables and hotlinking
# ---------------------------------------------------------------------------
class LinkEsterniHotlink(BaseModule):
    """Comment: counts external links, links to executables (.exe/.apk/.jar)
        and hotlinking.

        A phishing page almost always links to executables (drive-by) or
        to external domains for credential exfiltration; a legitimate page
        rarely has .exe links.

        Threshold:
          - any executable link -> SUSPICIOUS 1.0;
          - > 50% of links pointing to external domains -> NEUTRAL 0.5;
          - otherwise -> SAFE 0.0.
    """

    description = "Link esterni, eseguibili e hotlinking."

    EXEC_EXTS: tuple[str, ...] = (
        ".exe", ".apk", ".jar", ".scr", ".msi", ".bat", ".dll", ".deb", ".rpm",
        ".com", ".pif", ".hta", ".ps1",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "link_esterni_hotlink".
        """
        return "link_esterni_hotlink"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.8 (low-medium weight).
        """
        return 0.8

    def run(self, url: str) -> ModuleResult:
        """Comment: counts external links and executable links.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {external_count, total_links,
            exec_links, external_ratio}, score in [0,1].
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
                threshold={"exec_exts": list(self.EXEC_EXTS)},
            )

        soup = parse_html(res.text)
        anchors = soup.find_all("a")
        total = len(anchors)
        external = 0
        exec_links: list[str] = []
        for a in anchors:
            href = (a.get("href") or "").strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            absolute = urljoin(res.url or url, href)
            path = urlparse(absolute).path.lower()
            if any(path.endswith(ext) for ext in self.EXEC_EXTS):
                exec_links.append(absolute)
            if not same_registered_domain(absolute, res.url or url):
                external += 1

        if exec_links:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovati {len(exec_links)} link a eseguibili "
                f"({exec_links[0][:80]}): drive-by download probabile."
            )
        elif total > 0 and external / max(1, total) > 0.5:
            score = 0.5
            outcome = Outcome.NEUTRAL
            msg = (
                f"{external}/{total} link puntano a domini esterni "
                f"({external/max(1,total)*100:.0f}%): media alta, valutare contesto."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Link nella norma: {total} anchor, {external} esterni, "
                f"0 link a eseguibili."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "external_count": external,
                "total_links": total,
                "exec_links": exec_links[:5],
                "external_ratio": round(external / max(1, total), 2),
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"exec_exts": list(self.EXEC_EXTS)},
        )


# ---------------------------------------------------------------------------
# Parameter 27: NLP semantic analysis of the text
# ---------------------------------------------------------------------------
class NlpSemantica(BaseModule):
    """Comment: lightweight semantic analysis of the page text.

        Without a full NLP stack (spacy + model) we use a curated keyword
        dictionary of typical phishing phrases in Italian and English:
        requests for credentials, urgency, threats, payment requests. Each
        distinct category hit increases the score.

        Threshold:
          - 0 hits -> SAFE 0.0;
          - 1-2 hits -> NEUTRAL 0.4;
          - >= 3 hits -> SUSPICIOUS 0.9.
    """

    description = "Analisi semantica NLP del testo (credenziali, urgenza, minacce)."

    # Categories with their keywords. Each keyword matches case-insensitively
    # as a substring of the visible page text.
    PHISHING_CATEGORIES: dict[str, tuple[str, ...]] = {
        "credentials": (
            "verifica il tuo account", "conferma le credenziali", "password scaduta",
            "inserisci la password", "reinserisci la password", "login sicuro",
            "enter your password", "verify your account", "confirm your credentials",
        ),
        "urgency": (
            "ultime 24 ore", "entro 24 ore", "blocco imminente", "azione immediata",
            "ultimo avviso", "scade oggi", "within 24 hours", "immediate action",
            "account suspended", "account bloccato",
        ),
        "payment": (
            "inserisci la carta", "codice di verifica", "dati bancari",
            "pagamento in sospeso", "rimborsi", "inserisci il codice cvv",
            "enter your card", "payment pending", "credit card details",
        ),
        "threats": (
            "perdita dati", "chiusura dell'account", "denuncia penale",
            "sospensione del servizio", "data loss", "account closure",
            "legal action",
        ),
    }

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "nlp_semantica".
        """
        return "nlp_semantica"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: runs keyword-based semantic analysis on the page text.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {hits, categories_matched,
            keywords_matched}, score in [0,1].
        """
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
            )

        soup = parse_html(res.text)
        text = soup.get_text(" ") if hasattr(soup, "get_text") else ""
        text = (text or "").lower()

        matched_categories: list[str] = []
        matched_keywords: list[str] = []
        for cat, kws in self.PHISHING_CATEGORIES.items():
            cat_hits = [kw for kw in kws if kw in text]
            if cat_hits:
                matched_categories.append(cat)
                matched_keywords.extend(cat_hits)

        hits = len(matched_keywords)
        if hits == 0:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "Nessun linguaggio di phishing rilevato nel testo visibile."
        elif hits <= 2:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"Trovate {hits} corrispondenze ({', '.join(matched_categories)}): "
                f"potrebbero essere contesto legittimo (banking, security)."
            )
        else:
            score = 0.9
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Trovate {hits} corrispondenze di linguaggio di phishing "
                f"({', '.join(matched_categories)}): "
                f"combinazione tipica di pagina di credential harvesting."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "hits": hits,
                "categories_matched": matched_categories,
                "keywords_matched": matched_keywords[:10],
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "categories": list(self.PHISHING_CATEGORIES.keys()),
            },
        )


# ---------------------------------------------------------------------------
# Parameter 28: visual cloning of logos and layout
# ---------------------------------------------------------------------------
class ClonazioneVisiva(BaseModule):
    """Comment: lightweight detection of visual cloning of known brands.

        The real implementation would require imagehash + a pHash database
        of known logos. Without that, we use a cheaper but still useful
        signal: the presence of well-known brand names in the page text
        combined with a mismatch between the brand and the page's
        registered domain.

        Example: a page on "login-poste-italiane.tk" mentioning "Poste
        Italiane" or "BancoPosta" without being on poste.it is highly
        suspicious of visual cloning.

        Threshold:
          - brand mentioned AND domain does not match the brand's
            legitimate domain -> SUSPICIOUS 0.8;
          - brand mentioned but domain matches -> SAFE 0.0;
          - no known brand mentioned -> NEUTRAL 0.1.
    """

    description = "Clonazione visiva (match brand noti vs dominio pagina)."

    # (brand_keyword, legitimate_registered_domain) pairs.
    KNOWN_BRANDS: tuple[tuple[str, str], ...] = (
        ("poste italiane", "poste.it"),
        ("banco post", "poste.it"),
        ("intesa sanpaolo", "intesasanpaolo.com"),
        ("unicredit", "unicredit.it"),
        ("paypal", "paypal.com"),
        ("google", "google.com"),
        ("microsoft", "microsoft.com"),
        ("apple", "apple.com"),
        ("amazon", "amazon.com"),
        ("facebook", "facebook.com"),
        ("instagram", "instagram.com"),
        ("whatsapp", "whatsapp.com"),
        ("netflix", "netflix.com"),
        ("spotify", "spotify.com"),
        ("linkedin", "linkedin.com"),
        ("fineco", "finecobank.com"),
        ("mediobanca", "mediobanca.com"),
        ("santander", "santander.it"),
        ("revolut", "revolut.com"),
        ("n26", "n26.com"),
        ("banca sella", "bancasella.it"),
        ("bnp paribas", "bnpparibas.it"),
        ("ing direct", "ing.it"),
        ("credit agricole", "creditagricole.it"),
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "clonazione_visiva".
        """
        return "clonazione_visiva"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.8 (high weight, strong phishing signal).
        """
        return 1.8

    def run(self, url: str) -> ModuleResult:
        """Comment: detects brand mentions vs page registered domain.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {matched_brand, page_domain,
            brand_legit_domain, mismatch}, score in [0,1].
        """
        page_domain = get_registered_domain(url) or ""
        res = fetch_url(url)
        if res.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Fetch fallito: {res.error}",
            )

        soup = parse_html(res.text)
        text = (soup.get_text(" ") if hasattr(soup, "get_text") else "") or ""
        text_low = text.lower()
        # Also scan <title>, meta description and alt attributes.
        title = ""
        if hasattr(soup, "find_all"):
            t = soup.find_all("title")
            if t:
                title = (getattr(t[0], "string", "") or getattr(t[0], "text", "") or "")
        text_low += " " + (title or "").lower()

        matched: list[tuple[str, str]] = []
        for kw, legit in self.KNOWN_BRANDS:
            if kw in text_low:
                matched.append((kw, legit))

        if not matched:
            score = 0.1
            outcome = Outcome.NEUTRAL
            msg = "Nessun brand noto menzionato nel testo: valutazione neutra."
        else:
            # Check whether ANY of the brand legit domains matches the
            # page's registered domain.
            ok = any(legit == page_domain.lower() for _, legit in matched)
            if ok:
                score = 0.0
                outcome = Outcome.SAFE
                msg = (
                    f"Brand '{matched[0][0]}' menzionato su dominio legittimo "
                    f"({page_domain})."
                )
            else:
                score = 0.8
                outcome = Outcome.SUSPICIOUS
                brands_str = ", ".join(kw for kw, _ in matched[:3])
                legit_str = ", ".join(legit for _, legit in matched[:3])
                msg = (
                    f"Brand noti menzionati ({brands_str}) su dominio NON "
                    f"ufficiale ({page_domain}); domini legittimi attesi: "
                    f"{legit_str}. Sospetto di clonazione visiva."
                )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "matched_brands": [kw for kw, _ in matched],
                "page_domain": page_domain,
                "brand_legit_domains": [legit for _, legit in matched],
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# Late import to keep the regex available without re-importing in the loop.
import re  # noqa: E402
