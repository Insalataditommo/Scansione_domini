"""
modules/lexical/typosquatting.py

Comment:
    Parameter 5: typosquatting and homographs (IDN homograph).

    Detects variants of a known brand domain obtained by:
      - single-character substitutions (e.g. goog1e.com vs google.com)
      - insertions/omissions (e.g. gooogle.com, gogle.com)
      - use of similar Unicode characters (IDN homograph, e.g. аpple.com
        with Cyrillic 'а') -> Punycode label "xn--..."
      - use of confusable characters (e.g. 0/O, 1/l/I)

    The algorithm is lightweight and based on:
      - Levenshtein distance (<= 1 or 2) against a set of known brands
      - detection of Punycode labels (xn--) with visual char comparison
"""

from __future__ import annotations

import unicodedata

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.lexical._urlutils import parse_url, has_idn, get_punycode_labels

# Reference brands (second-level label) for the typosquatting comparison.
KNOWN_BRANDS: frozenset[str] = frozenset(
    {"google", "facebook", "amazon", "apple", "microsoft", "paypal",
     "instagram", "netflix", "linkedin", "twitter", "github", "dropbox",
     "whatsapp", "yahoo", "outlook", "office", "live", "bank", "banking",
     "poste", "intesasanpaolo", "unicredit", "santander", "revolut",
     "coinbase", "binance", "metamask", "docusign", "adobe"}
)

# Commonly confusable characters (homoglyphs).
CONFUSABLE_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a", "1": "i", "|": "l", "ì": "i",
}


class TyposquattingOmografi(BaseModule):
    """Comment: detects typosquatting and IDN homographs against known brands."""

    description = "Typosquatting e omografi (IDN homograph) rispetto a brand noti."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "typosquatting_omografi".
        """
        return "typosquatting_omografi"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.8 (high weight, strong signal).
        """
        return 1.8

    def run(self, url: str) -> ModuleResult:
        """Comment: detects typosquatting and IDN homographs in the URL host.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {domain, sld, idn_detected,
            punycode_labels, closest_brand, levenshtein,
            levenshtein_after_confusables}, score in [0,1], outcome
            SAFE/NEUTRAL/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when the URL or domain cannot be extracted.
        """
        parsed = parse_url(url)
        if parsed is None or not parsed.registered_domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="URL non valido o dominio non estraibile.",
            )

        domain = parsed.registered_domain
        # Second-level label (e.g. "google" from "google.com").
        sld = domain.split(".")[0] if domain else ""

        # 1) IDN homograph: presence of Punycode labels in the full host.
        host_for_idn = parsed.subdomain + "." + domain if parsed.subdomain else domain
        punycode_labels = get_punycode_labels(host_for_idn)
        idn_detected = bool(punycode_labels) or has_idn(host_for_idn)

        # 2) Typosquatting: Levenshtein distance vs known brands.
        best_brand, best_dist = _closest_brand(sld)
        normalized = _normalize_confusables(sld)
        norm_brand, norm_dist = (None, 99)
        if best_brand:
            norm_brand = _normalize_confusables(best_brand)
            norm_dist = _levenshtein(normalized, norm_brand)

        score = 0.0
        signals: list[str] = []

        # IDN homograph weight: maximum (IDN homographs are almost always malicious).
        if idn_detected:
            score = max(score, 0.9)
            signals.append("IDN homograph (Punycode xn--) rilevato")

        # Typosquatting by small Levenshtein distance.
        if best_dist == 0 and sld in KNOWN_BRANDS:
            # exact brand -> not typosquatting
            pass
        elif best_dist == 1:
            score = max(score, 0.8)
            signals.append(f"Levenshtein=1 da brand '{best_brand}'")
        elif best_dist == 2:
            score = max(score, 0.5)
            signals.append(f"Levenshtein=2 da brand '{best_brand}'")
        elif norm_dist == 1:
            # confusables that reduce the distance after normalization
            score = max(score, 0.7)
            signals.append(
                f"omografo dopo normalizzazione confusables (vicino a '{best_brand}')"
            )

        if score >= 0.5:
            outcome = Outcome.SUSPICIOUS
            msg = (
                "Possibile typosquatting/omografia: " + "; ".join(signals) +
                f". Dominio: {domain}."
            )
        elif score > 0.0:
            outcome = Outcome.NEUTRAL
            msg = "Segnali deboli di somiglianza con brand noto: " + "; ".join(signals) + "."
        else:
            outcome = Outcome.SAFE
            msg = "Nessuna somiglianza rilevante con brand noti."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "domain": domain,
                "sld": sld,
                "idn_detected": idn_detected,
                "punycode_labels": punycode_labels,
                "closest_brand": best_brand,
                "levenshtein": best_dist,
                "levenshtein_after_confusables": norm_dist if best_brand else None,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"levenshtein_sospetto": 1, "levenshtein_debole": 2},
        )


def _levenshtein(a: str, b: str) -> int:
    """Comment: classic Levenshtein distance (DP, O(m*n)).

    Input data:
        a, b: two strings to compare.

    Expected output:
        int >= 0, the edit distance between a and b.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            ))
        prev = cur
    return prev[-1]


def _closest_brand(sld: str) -> tuple[str | None, int]:
    """Comment: returns (brand, distance) of the closest brand to the SLD.

    Input data:
        sld: second-level domain label (e.g. "goog1e").

    Expected output:
        tuple (brand_name_or_None, distance); (None, 99) when sld is empty.
    """
    if not sld:
        return None, 99
    best_brand, best_dist = None, 99
    for brand in KNOWN_BRANDS:
        # Compare only when lengths are similar (optimization).
        if abs(len(brand) - len(sld)) > 3:
            continue
        d = _levenshtein(sld, brand)
        if d < best_dist:
            best_dist = d
            best_brand = brand
            if d == 0:
                break
    return best_brand, best_dist


def _normalize_confusables(s: str) -> str:
    """Comment: replaces confusable chars (e.g. 0->o, 1->l) and NFKD-normalizes.

    Input data:
        s: input string.

    Expected output:
        str lowercased, NFKD-normalized, with confusable characters replaced
        using CONFUSABLE_MAP.
    """
    if not s:
        return s
    s = unicodedata.normalize("NFKD", s)
    s = s.lower()
    return "".join(CONFUSABLE_MAP.get(c, c) for c in s)
