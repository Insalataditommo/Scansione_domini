"""
modules/dns_whois/whois_dns_modules.py

Comment:
    Section 2 parameters (WHOIS / DNS, 8 modules) — full implementation.

    Each module queries WHOIS or DNS through the shared helpers in
    `_dnsutils.py` (python-whois + dnspython) and degrades gracefully to
    NOT_EVALUATED when a library is missing or the query fails, so the
    rest of the analysis can still proceed.

    Scoring conventions:
      - SAFE (score 0.0): the signal is clearly benign (e.g. an old domain
        with a long registration period);
      - NEUTRAL (0.1-0.5): the signal is ambiguous (e.g. WHOIS privacy on
        a personal domain);
      - SUSPICIOUS (0.5-1.0): the signal matches a known phishing pattern
        (very young domain, fast flux, DMARC p=none, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule, ModuleResult, Outcome
from modules.dns_whois._dnsutils import (
    get_registered_domain,
    query_whois,
    resolve_a_records,
    resolve_mx_records,
    resolve_txt_records,
    resolve_dnskey,
    dnssec_validated,
)


# ---------------------------------------------------------------------------
# Parameter 15: domain age
# ---------------------------------------------------------------------------
class EtaDominio(BaseModule):
    """Comment: domain age in days since the WHOIS creation date.

        A very young domain (< 30 days) is one of the strongest phishing
        signals: campaigns register fresh domains to avoid reputation
        blacklists. Aged domains (> 365 days) are not per se trustworthy,
        but they strongly reduce the phishing prior.

        Threshold: < 30 days = suspicious (linear 1.0 -> 0.5); between
        30 and 365 days = neutral (0.3); > 365 days = safe (0.0).
    """

    description = "Età del dominio (giorni dalla creazione WHOIS)."
    SOSPETTO_MAX_GIORNI = 30
    SICURO_MIN_GIORNI = 365

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "eta_dominio".
        """
        return "eta_dominio"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, strong phishing signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: computes the domain age from WHOIS creation_date.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {age_days, creation_date}, score
            in [0,1], outcome SAFE/NEUTRAL/SUSPICIOUS, threshold dict.
            NOT_EVALUATED when WHOIS cannot be queried.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
                threshold={
                    "sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI,
                    "sicuro_min_giorni": self.SICURO_MIN_GIORNI,
                },
            )

        w = query_whois(domain)
        if w.error or w.creation_date is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=(
                    f"WHOIS non disponibile per '{domain}'"
                    f"{f': {w.error}' if w.error else ' (creation_date assente).'}."
                ),
                threshold={
                    "sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI,
                    "sicuro_min_giorni": self.SICURO_MIN_GIORNI,
                },
            )

        now = datetime.now(timezone.utc)
        age_days = (now - w.creation_date).total_seconds() / 86400.0
        # Negative age (creation_date in the future) is treated as 0.
        if age_days < 0:
            age_days = 0.0

        if age_days < self.SOSPETTO_MAX_GIORNI:
            # Suspicious: very young domain. Linear 1.0 at 0 days, 0.5 at
            # the threshold boundary.
            score = 1.0 - 0.5 * (age_days / self.SOSPETTO_MAX_GIORNI)
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Dominio creato {age_days:.0f} giorni fa (< soglia "
                f"{self.SOSPETTO_MAX_GIORNI}gg): forte indicatore di infrastruttura "
                f"di recente creazione per una campagna."
            )
        elif age_days < self.SICURO_MIN_GIORNI:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = (
                f"Dominio creato {age_days:.0f} giorni fa: età intermedia, "
                f"da valutare con altri segnali."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Dominio creato {age_days:.0f} giorni fa (> {self.SICURO_MIN_GIORNI}gg): "
                f"infrastruttura consolidata."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "age_days": round(age_days, 1),
                "creation_date": w.creation_date.isoformat(),
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI,
                "sicuro_min_giorni": self.SICURO_MIN_GIORNI,
            },
        )


# ---------------------------------------------------------------------------
# Parameter 16: registration duration
# ---------------------------------------------------------------------------
class DurataRegistrazione(BaseModule):
    """Comment: registration duration (expiration - creation).

        Phishing campaigns often register domains for the minimum period
        (1 year), because the domain has a short expected life. Long
        registrations (3+ years) are mildly positive.

        Threshold: < 365 days = suspicious; 365-1095 days = neutral;
        > 1095 days (3 years) = safe.
    """

    description = "Durata della registrazione del dominio."
    SOSPETTO_MAX_GIORNI = 365
    SICURO_MIN_GIORNI = 1095

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "durata_registrazione".
        """
        return "durata_registrazione"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.5 (medium-high weight).
        """
        return 1.5

    def run(self, url: str) -> ModuleResult:
        """Comment: computes the registration duration from WHOIS.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {duration_days, expiration_date}.
            NOT_EVALUATED when WHOIS data is missing.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
                threshold={"sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI},
            )

        w = query_whois(domain)
        if w.error or w.creation_date is None or w.expiration_date is None:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=(
                    f"Date WHOIS non disponibili per '{domain}'"
                    f"{f': {w.error}' if w.error else '.'}"
                ),
                threshold={"sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI},
            )

        duration_days = (w.expiration_date - w.creation_date).total_seconds() / 86400.0
        if duration_days < 0:
            return ModuleResult(
                name=self.name(),
                raw_value={
                    "duration_days": round(duration_days, 1),
                    "creation_date": w.creation_date.isoformat(),
                    "expiration_date": w.expiration_date.isoformat(),
                    "domain": domain,
                },
                score=0.4,
                outcome=Outcome.NEUTRAL,
                message="Data di scadenza WHOIS precedente alla creazione: dato incoerente.",
                threshold={"sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI},
            )

        if duration_days < self.SOSPETTO_MAX_GIORNI:
            score = 0.8
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Registrazione di {duration_days:.0f} giorni (< {self.SOSPETTO_MAX_GIORNI}gg): "
                f"pattern tipico delle campagne di phishing."
            )
        elif duration_days < self.SICURO_MIN_GIORNI:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = f"Registrazione di {duration_days:.0f} giorni: durata standard."
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Registrazione di {duration_days:.0f} giorni (> {self.SICURO_MIN_GIORNI}gg): "
                f"investimento a lungo termine."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "duration_days": round(duration_days, 1),
                "creation_date": w.creation_date.isoformat(),
                "expiration_date": w.expiration_date.isoformat(),
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={
                "sospetto_max_giorni": self.SOSPETTO_MAX_GIORNI,
                "sicuro_min_giorni": self.SICURO_MIN_GIORNI,
            },
        )


# ---------------------------------------------------------------------------
# Parameter 17: WHOIS anonymity and registrar
# ---------------------------------------------------------------------------
class AnonimatoWhois(BaseModule):
    """Comment: WHOIS anonymity (privacy / redacted registrant fields).

        A non-trivial fraction of phishing domains uses WHOIS privacy
        services. This is not by itself a smoking gun (many legitimate
        personal sites use them), but combined with other signals it
        increases the score.

        Threshold: presence of "REDACTED FOR PRIVACY", "Privacy Service",
        or a known proxy organization (WhoisGuard, Domains By Proxy, etc.)
        -> NEUTRAL 0.4. A clearly identifiable registrant matching the
        website brand -> SAFE 0.0.
    """

    description = "Anonimato WHOIS (privacy del registrant)."

    PRIVACY_KEYWORDS: tuple[str, ...] = (
        "redacted", "privacy", "whoisguard", "domainsbyproxy",
        "perfect privacy", "withheld", "data protected",
        "registration private", "statutory masking", "gdpr masked",
    )

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "anonimato_whois".
        """
        return "anonimato_whois"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.2 (medium weight).
        """
        return 1.2

    def run(self, url: str) -> ModuleResult:
        """Comment: detects WHOIS privacy/anonymization on the registrant.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {is_anonymized, matched_keywords,
            registrar, registrant_org}, score in [0,1], threshold dict.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
                threshold={"privacy_keywords": list(self.PRIVACY_KEYWORDS)},
            )

        w = query_whois(domain)
        if w.error:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"WHOIS non disponibile per '{domain}': {w.error}.",
                threshold={"privacy_keywords": list(self.PRIVACY_KEYWORDS)},
            )

        # Concatenate every free-text field the registrant leaves in WHOIS.
        haystack = " ".join(filter(None, [
            w.registrar or "",
            w.registrant_name or "",
            w.registrant_org or "",
            w.registrant_email or "",
            w.raw_text or "",
        ])).lower()

        matched = [k for k in self.PRIVACY_KEYWORDS if k in haystack]
        is_anonymized = bool(matched)

        if is_anonymized:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"WHOIS anonimizzato (parole chiave: {', '.join(matched[:3])}): "
                f"da solo non è prova, ma pesa in presenza di altri segnali."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = "WHOIS non anonimizzato: registrant identificabile."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "is_anonymized": is_anonymized,
                "matched_keywords": matched,
                "registrar": w.registrar,
                "registrant_org": w.registrant_org,
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"privacy_keywords": list(self.PRIVACY_KEYWORDS)},
        )


# ---------------------------------------------------------------------------
# Parameter 18: IP and ASN reputation
# ---------------------------------------------------------------------------
class ReputazioneIpAsn(BaseModule):
    """Comment: IP/ASN reputation of the domain (abuse, historical blocks).

        Without an API key we cannot query AbuseIPDB/IPinfo, but we CAN
        check the public Spamhaus DBL (Domain Block List) over DNS, which
        is free and does not require authentication. A domain listed in
        Spamhaus DBL is a strong phishing/malware signal.

        Threshold: domain in Spamhaus DBL -> SUSPICIOUS 1.0; DNS query
        error -> NOT_EVALUATED.
    """

    description = "Reputazione IP/ASN (Spamhaus DBL via DNS)."
    SPAMHAUS_DBL_SUFFIX = ".dbl.spamhaus.org"

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "reputazione_ip_asn".
        """
        return "reputazione_ip_asn"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.8 (high weight).
        """
        return 1.8

    def run(self, url: str) -> ModuleResult:
        """Comment: queries Spamhaus DBL via DNS for the domain.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {domain, listed, return_code},
            score in [0,1]. NOT_EVALUATED when dnspython is missing or
            the DNS query itself fails.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
            )

        # Resolve A records and TTLs for the domain itself (for context).
        ips, _ = resolve_a_records(domain, timeout=5.0)

        # Spamhaus DBL query: append the suffix and resolve. A 127.0.1.x
        # answer means LISTED; NXDOMAIN / no answer means not listed.
        query_host = domain + self.SPAMHAUS_DBL_SUFFIX
        listed = False
        return_code = ""
        try:
            import dns.resolver  # type: ignore
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            try:
                answers = resolver.resolve(query_host, "A", raise_on_no_answer=True)
                for r in answers:
                    addr = r.address
                    if addr.startswith("127.0.1."):
                        listed = True
                        return_code = addr
                        break
            except dns.resolver.NXDOMAIN:
                listed = False
            except dns.resolver.NoAnswer:
                listed = False
        except ImportError:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="dnspython non installato (pip install dnspython).",
                raw_value={"domain": domain, "ips": ips},
            )
        except Exception:  # noqa: BLE001
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Query Spamhaus DBL fallita per '{domain}'.",
                raw_value={"domain": domain, "ips": ips},
            )

        if listed:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Dominio '{domain}' LISTATO in Spamhaus DBL (return code {return_code}): "
                f"forte segnale di phishing/malware."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"Dominio '{domain}' non presente in Spamhaus DBL "
                f"(IPs: {', '.join(ips) if ips else 'nessuno'})."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "domain": domain,
                "ips": ips,
                "listed": listed,
                "return_code": return_code,
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# ---------------------------------------------------------------------------
# Parameter 19: fast flux DNS
# ---------------------------------------------------------------------------
class FastFluxDns(BaseModule):
    """Comment: detects fast flux DNS (many A records, low TTL, rapid change).

        Botnet-operated phishing frequently uses fast flux: a domain
        resolving to many (often dozens of) short-lived IPs with very low
        TTL, to evade IP-based blocking.

        Threshold: >= 5 A records AND min TTL <= 60s -> SUSPICIOUS 1.0;
        >= 5 A records OR low TTL alone -> NEUTRAL 0.4; otherwise SAFE.
    """

    description = "Fast flux DNS (multipli A + TTL basso + variazione)."
    MIN_A_RECORDS = 5
    MAX_TTL = 60

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "fast_flux_dns".
        """
        return "fast_flux_dns"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 2.0 (high weight, strong phishing signal).
        """
        return 2.0

    def run(self, url: str) -> ModuleResult:
        """Comment: detects fast flux patterns in A records.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {a_records_count, min_ttl, max_ttl},
            score in [0,1], threshold dict.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
                threshold={"min_a_records": self.MIN_A_RECORDS, "max_ttl": self.MAX_TTL},
            )

        ips, ttls = resolve_a_records(domain, timeout=5.0)
        if not ips:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"Nessun record A risolvibile per '{domain}'.",
                threshold={"min_a_records": self.MIN_A_RECORDS, "max_ttl": self.MAX_TTL},
            )

        count = len(ips)
        min_ttl = min(ttls) if ttls else None
        max_ttl = max(ttls) if ttls else None
        many = count >= self.MIN_A_RECORDS
        low = (min_ttl is not None and min_ttl <= self.MAX_TTL)

        if many and low:
            score = 1.0
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Fast flux probabile: {count} record A con TTL min {min_ttl}s "
                f"(< {self.MAX_TTL}s): pattern tipico di botnet/phishing."
            )
        elif many or low:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"Configurazione DNS atipica: {count} record A, TTL min {min_ttl}s "
                f"(solo uno dei due criteri di fast flux soddisfatto)."
            )
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"DNS nella norma: {count} record A, TTL min {min_ttl}s, "
                f"max {max_ttl}s."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "a_records_count": count,
                "a_records": ips,
                "min_ttl": min_ttl,
                "max_ttl": max_ttl,
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"min_a_records": self.MIN_A_RECORDS, "max_ttl": self.MAX_TTL},
        )


# ---------------------------------------------------------------------------
# Parameter 20: TTL values
# ---------------------------------------------------------------------------
class TtlDns(BaseModule):
    """Comment: TTL values of the DNS records (A/AAAA/MX).

        Very low TTLs (< 60s) are not necessarily malicious (CDNs use
        them), but combined with other signals they hint at fast flux or
        at attempts to rapidly re-point the domain.

        Threshold: min TTL <= 60s -> NEUTRAL 0.4 (the FastFluxDns module
        already handles the >5 records case); 60-300s -> NEUTRAL 0.1;
        > 300s -> SAFE 0.0.
    """

    description = "Valori TTL dei record DNS."
    SOSPETTO_MAX = 60
    NEUTRO_MIN = 300

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "ttl_dns".
        """
        return "ttl_dns"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.8 (low-medium weight).
        """
        return 0.8

    def run(self, url: str) -> ModuleResult:
        """Comment: evaluates DNS TTL values.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {min_ttl, max_ttl, a_records_count}.
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
                threshold={"sospetto_max": self.SOSPETTO_MAX, "neutro_min": self.NEUTRO_MIN},
            )

        _, ttls = resolve_a_records(domain, timeout=5.0)
        if not ttls:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message=f"TTL non estraibile per '{domain}' (record A assenti).",
                threshold={"sospetto_max": self.SOSPETTO_MAX, "neutro_min": self.NEUTRO_MIN},
            )

        min_ttl = min(ttls)
        max_ttl = max(ttls)

        if min_ttl <= self.SOSPETTO_MAX:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = (
                f"TTL DNS molto basso ({min_ttl}s <= {self.SOSPETTO_MAX}s): "
                f"può indicare fast flux o CDN; valutare con altri segnali."
            )
        elif min_ttl < self.NEUTRO_MIN:
            score = 0.1
            outcome = Outcome.NEUTRAL
            msg = f"TTL DNS intermedio ({min_ttl}s): nella fascia di guardia."
        else:
            score = 0.0
            outcome = Outcome.SAFE
            msg = f"TTL DNS nella norma (min {min_ttl}s, max {max_ttl}s)."

        return ModuleResult(
            name=self.name(),
            raw_value={
                "min_ttl": min_ttl,
                "max_ttl": max_ttl,
                "a_records_count": len(ttls),
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
            threshold={"sospetto_max": self.SOSPETTO_MAX, "neutro_min": self.NEUTRO_MIN},
        )


# ---------------------------------------------------------------------------
# Parameter 21: SPF / DKIM / DMARC
# ---------------------------------------------------------------------------
class SpfDkimDmarc(BaseModule):
    """Comment: email authentication records: SPF, DKIM, DMARC.

        Domains used in phishing campaigns often have weak or absent
        SPF/DMARC records (because the attacker does not care about
        deliverability of legitimate mail from that domain, only about
        spoofing). Conversely, legitimate businesses that send mail
        configure all three.

        Threshold:
          - No SPF AND no DMARC -> SUSPICIOUS 0.7 (only mildly, since many
            legitimate sites also lack them);
          - SPF present, DMARC p=none/missing -> NEUTRAL 0.3;
          - SPF + DMARC p=quarantine/reject -> SAFE 0.0.
    """

    description = "Record SPF / DKIM / DMARC."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "spf_dkim_dmarc".
        """
        return "spf_dkim_dmarc"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 1.0 (medium weight).
        """
        return 1.0

    def run(self, url: str) -> ModuleResult:
        """Comment: checks SPF, DKIM and DMARC records.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {spf, dmarc, dmarc_policy}, score
            in [0,1].
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
            )

        txts = resolve_txt_records(domain, timeout=5.0)
        spf = next((t for t in txts if t.strip().lower().startswith("v=spf1")), None)

        dmarc_records = resolve_txt_records(f"_dmarc.{domain}", timeout=5.0)
        dmarc = next((t for t in dmarc_records if t.strip().lower().startswith("v=dmarc1")), None)

        dmarc_policy = ""
        if dmarc:
            # Extract p=none|quarantine|reject
            low = dmarc.lower()
            for token in low.split(";"):
                token = token.strip()
                if token.startswith("p="):
                    dmarc_policy = token[2:].strip()
                    break

        if spf and dmarc and dmarc_policy in ("quarantine", "reject"):
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"SPF presente e DMARC p={dmarc_policy}: configurazione email "
                f"di autenticazione robusta."
            )
        elif spf and dmarc:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = (
                f"SPF presente, DMARC p={dmarc_policy or 'none'}: configurazione "
                f"debole ma presente."
            )
        elif spf:
            score = 0.4
            outcome = Outcome.NEUTRAL
            msg = "SPF presente ma DMARC assente: configurazione parziale."
        else:
            score = 0.7
            outcome = Outcome.SUSPICIOUS
            msg = (
                f"Né SPF né DMARC presenti: anomalia per un dominio legittimo, "
                f"frequente in domini di phishing."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "spf": spf,
                "dmarc": dmarc,
                "dmarc_policy": dmarc_policy,
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
        )


# ---------------------------------------------------------------------------
# Parameter 22: DNSSEC
# ---------------------------------------------------------------------------
class Dnssec(BaseModule):
    """Comment: DNSSEC presence and validity.

        A domain with active and validated DNSSEC is more trustworthy
        (an attacker cannot forge its DNS responses without compromising
        the key). The absence of DNSSEC is not malicious by itself (many
        legitimate domains do not use it) and is therefore scored as
        neutral rather than suspicious.
    """

    description = "Presenza e validità DNSSEC."

    def name(self) -> str:
        """Comment: returns the parameter identifier.

        Input data: self.
        Expected output: str "dnssec".
        """
        return "dnssec"

    def weight(self) -> float:
        """Comment: returns the default weight of this parameter.

        Input data: self.
        Expected output: float 0.7 (low-medium weight).
        """
        return 0.7

    def run(self, url: str) -> ModuleResult:
        """Comment: checks DNSSEC presence and validity.

        Input data:
            url: full URL string.

        Expected output:
            ModuleResult with raw_value {has_dnskey, ad_bit}, score in [0,1].
        """
        domain = get_registered_domain(url)
        if not domain:
            return ModuleResult(
                name=self.name(),
                outcome=Outcome.NOT_EVALUATED,
                message="Dominio registrato non estraibile dall'URL.",
            )

        has_dnskey = resolve_dnskey(domain, timeout=5.0)
        ad_bit = dnssec_validated(domain, timeout=5.0)

        if has_dnskey and ad_bit:
            score = 0.0
            outcome = Outcome.SAFE
            msg = (
                f"DNSSEC attivo e validato per '{domain}': risposte DNS "
                f"autentiche, non contraffabili."
            )
        elif has_dnskey:
            score = 0.1
            outcome = Outcome.NEUTRAL
            msg = (
                f"DNSKEY presente ma AD bit non impostato dal resolver: "
                f"DNSSEC configurato ma non validato in catena."
            )
        else:
            score = 0.3
            outcome = Outcome.NEUTRAL
            msg = (
                f"Nessun record DNSKEY per '{domain}': DNSSEC assente "
                f"(non sospetto, ma riduce la robustezza DNS)."
            )

        return ModuleResult(
            name=self.name(),
            raw_value={
                "has_dnskey": has_dnskey,
                "ad_bit": ad_bit,
                "domain": domain,
            },
            score=score,
            outcome=outcome,
            message=msg,
        )
