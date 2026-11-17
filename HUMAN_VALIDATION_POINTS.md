# Punti di validazione umana / autorizzazione aggiuntiva

Elenco dei punti in cui il sistema richiede validazione umana o
un'autorizzazione scritta aggiuntiva **prima di passare alla fase di test
sul campo**. È organizzato per categoria.

---

## 1. Autorizzazioni legali e di scenario

| # | Punto | Azione richiesta |
|---|---|---|
| 1.1 | Conformità al GDPR e alle normative locali sulla raccolta di dati personali anche in forma passiva (IP, header, log di rete). | Validazione del DPO / legale interno. |
| 1.2 | Scenario B (test autorizzato): autorizzazione scritta del titolare dell'infrastruttura target, anche quando di proprietà aziendale, con scope temporale e perimetrale definito. | Firmare un Rules of Engagement (ROE). |
| 1.3 | Notifica al CERT / CSIRT interno prima di eseguire campagne simulate, per evitare allerte di incident response false positive. | Comunicazione formale pre-campagna. |
| 1.4 | Verifica che i domini analizzati siano effettivamente di proprietà o coperti da autorizzazione scritta (nessun "test amichevole" su domini terzi). | Checklist firmata dal richiedente. |

## 2. Sandbox dinamica (sezione 5)

| # | Punto | Azione richiesta |
|---|---|---|
| 2.1 | La sandbox descritta in `modules/dynamic/SANDBOX_ARCHITECTURE.md` deve essere effettivamente implementata e isolata (rete DMZ dedicata, no accesso alla LAN interna). | Validazione infrastrutturale del team network/security. |
| 2.2 | Review del profilo del browser headless: devono essere disattivati i plugin, il salvataggio credenziali, la sincronizzazione profili. | Code review della configurazione Playwright/Chromium. |
| 2.3 | Conservazione dei PCAP/HAR: definire retention (es. 30 giorni) e criteri di cancellazione in linea con policy aziendali. | Approvazione del data owner. |
| 2.4 | Il parametro `exploit` (modulo 32) è uno stub intenzionale: l'attivazione richiede sandbox dedicata esterna (Cuckoo, ANY.RUN) e autorizzazione separata. | Mai attivare senza autorizzazione scritta del CISO. |

## 3. API e servizi esterni (sezione 6)

| # | Punto | Azione richiesta |
|---|---|---|
| 3.1 | PhishTank, Google Safe Browsing, VirusTotal, AbuseIPDB: leggere i Terms of Service di ciascun servizio prima dell'uso in produzione (alcuni limitano il volume o vietano usi commerciali). | Review legale dei ToS. |
| 3.2 | Rotazione e protezione delle API key: devono essere memorizzate in un secrets manager (non nel file `.env` in chiaro in produzione). | Verifica DevSecOps. |
| 3.3 | Tasso di richieste: configurare rate-limiting per evitare ban dell'IP aziendale sui servizi gratuiti. | Tuning post-pilota. |
| 3.4 | Inoltro di URL sospetti a servizi di TI: inoltrare URL contenenti dati personali (es. query string con token) può violare il GDPR. | Anonimizzazione query string prima dell'invio. |

## 4. Calibrazione dei pesi e delle soglie

| # | Punto | Azione richiesta |
|---|---|---|
| 4.1 | I pesi in `config/weights.yaml` sono ragionati ma non calibrati su un dataset reale. | Tuning su dataset annotato (es. PhishTank + OpenPhish + whitelist aziendale) con metriche di precision/recall. |
| 4.2 | Le soglie quantitative (es. `entropia > 4.0`) sono valori di letteratura; ricalibrarle sulla distribuzione dei domini aziendali. | Analisi statistica post-pilota. |
| 4.3 | Definire una soglia di rischio operativo (es. `risk_pct >= 50%` = blocco automatico, `>= 25%` = review manuale). | Decisione del SOC. |

## 5. Moduli da completare prima della produzione

| # | Modulo | Note |
|---|---|---|
| 5.1 | Tutti gli 8 moduli `dns_whois` (15–22). | Implementare con `python-whois` e `dnspython`. |
| 5.2 | Tutti i 6 moduli `content` (23–28). | Richiedono fetch HTTP e parsing HTML; il 28 richiede un DB di pHash di loghi noti. |
| 5.3 | Tutti i 7 moduli `dynamic` (29–35). | Richiedono sandbox; vedere sezione 2. |
| 5.4 | Tutti i 4 moduli `reputation` (36–39). | Richiedono API key esterne (sezione 3). |

## 6. Operativi

| # | Punto | Azione richiesta |
|---|---|---|
| 6.1 | Logging degli accessi al tool (chi lancia, contro quali URL): utile per audit interno. | Integrazione con SIEM aziendale. |
| 6.2 | Output JSON deve essere inviato a SIEM/SOAR solo dopo dedup e normalizzazione. | Definire schema di esport. |
| 6.3 | Review periodica (mensile) delle blacklist di TLD e shortener (`modules/lexical/_urlutils.py`) per allinearsi alle campagne correnti. | Procedura di maintenance. |

## 7. Etica e responsabilità

| # | Punto | Azione richiesta |
|---|---|---|
| 7.1 | Lo strumento non deve MAI essere usato per profilare o tracciare utenti finali (è uno strumento difensivo, non di sorveglianza). | Clausola nel ROE. |
| 7.2 | I risultati delle analisi contengono dati potenzialmente sensibili (URL, contenuti HTML). Applicare cifratura at-rest ai report salvati. | Policy di cifratura. |
| 7.3 | Nessun risultato deve essere condiviso all'esterno dell'organizzazione senza autorizzazione (anche i report di phishing simulato possono contenere informazioni infrastrutturali). | NDA con stakeholder. |
