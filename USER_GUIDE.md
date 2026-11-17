# Guida rapida — phishing_analyzer

Questa guida spiega come **installare**, **usare** e **scaricare** il progetto
`phishing_analyzer`. Il codice è già pronto: i commenti e le docstring sono
in inglese (con il formato *comment / input data / expected output*), mentre
i messaggi utente (etichette di esito, testo del report) restano in italiano.

---

## 1. Requisiti

- **Python 3.11+** (verifica con `python3 --version`)
- Connessione a internet per i moduli TLS (test reali contro i server)
- (Opzionale) `pip` per installare le dipendenze

---

## 2. Installazione

Entra nella cartella del progetto e installa le dipendenze:

```bash
cd phishing_analyzer
pip install -r requirements.txt
```

Per le funzionalità opzionali (NLP, visione, UI ricca):

```bash
pip install -r requirements-extra.txt
```

> **Dipendenze minime e fallback**: il progetto è progettato per degradare
> in modo grazioso quando manca una libreria.
>
> | Se manca... | Cosa succede |
> |---|---|
> | `pyyaml` | i pesi vengono letti con un parser YAML minimale interno (stessi 39 pesi del file `weights.yaml`) |
> | `tldextract` | il dominio registrato viene estratto con un parser manuale che gestisce i TLD più comuni (.com, .it, .co.uk, ecc.) |
> | `cryptography` | i certificati X.509 vengono parseati con il modulo `ssl` della libreria standard (subject/issuer/date/SAN disponibili) |
> | `python-whois` | i moduli `eta_dominio` / `durata_registrazione` / `anonimato_whois` si marcano `NOT_EVALUATED` con un messaggio chiaro |
> | `dnspython` | i moduli DNS (`fast_flux_dns`, `ttl_dns`, `spf_dkim_dmarc`, `dnssec`, `reputazione_ip_asn`) si marcano `NOT_EVALUATED` |
> | `requests` | i moduli content/dynamic/reputation che richiedono fetch HTTP si marcano `NOT_EVALUATED` |
> | `beautifulsoup4` | l'HTML viene parseato con un parser regex minimale interno (supporta script/form/iframe/a/img) |
>
> Per avere tutte le funzionalità installa **tutto** il `requirements.txt`:
> `pyyaml`, `tldextract`, `cryptography`, `python-whois`, `dnspython`,
> `requests`, `beautifulsoup4`, `lxml`.

---

## 3. Come si usa

Tutti i comandi vanno eseguiti dalla cartella `phishing_analyzer/`.

### 3.1 Menu interattivo (più semplice)

```bash
python3 main.py
```

Apparirà un menu testuale che chiede:
1. quali categorie di parametri attivare (`lexical`, `tls`, `dns_whois`,
   `content`, `dynamic`, `reputation`);
2. quali URL analizzare (uno per riga, riga vuota per terminare).

### 3.2 Da riga di comando (script / CI/CD)

Analizza uno o più URL:

```bash
python3 main.py -u https://google.com http://example.tk/login
```

Seleziona solo alcune categorie:

```bash
python3 main.py -u https://example.com -m lexical,tls
```

Attiva tutte le categorie:

```bash
python3 main.py -u https://example.com --all
```

Modalità silenziosa (nessun progress per modulo, utile in CI):

```bash
python3 main.py -u https://example.com -m lexical -q --no-interactive
```

### 3.3 Da file CSV

Crea un file `urls.csv` con una colonna `url`:

```csv
url
https://google.com
http://example.tk/login
http://192.168.0.1/admin
```

Poi lancia:

```bash
python3 main.py -f urls.csv -m lexical,tls
```

### 3.4 Da pipe (stdin)

```bash
echo "https://example.com" | python3 main.py -m lexical
```

oppure:

```bash
cat urls.txt | python3 main.py -m lexical
```

### 3.5 Salvare i report su file

```bash
python3 main.py -u https://example.com -m lexical,tls \
  -o ./reports --json --markdown
```

- `-o ./reports` — salva i report nella cartella `reports/`
- `--json` — salva un file `<url_sanificato>.json` per URL
- `--markdown` — salva un file `<url_sanificato>.md` per URL

---

## 4. Esempio di output

Per `python3 main.py -u "http://192.168.0.1/admin" -m lexical,tls --no-interactive -q`
l'output su stdout è simile a:

```
==============================================================================
REPORT DI ANALISI PHISHING
==============================================================================
URL              : http://192.168.0.1/admin
Timestamp (UTC)  : 2026-11-17T10:43:49+00:00
------------------------------------------------------------------------------
Parametro                        Esito           Score  Dettagli
------------------------------------------------------------------------------
ip_in_url                        [!] sospetto     1.00  host=192.168.0.1
presenza_https                   [!] sospetto     1.00  scheme=http
caratteri_speciali_numeri        [!] sospetto     1.00  digit_ratio=0.73
...
------------------------------------------------------------------------------
RISCHIO FINALE: 38.74%  [MEDIO]
Moduli valutati: 10 | Non valutati: 4
==============================================================================
```

Legenda degli esiti:
- `[!] sospetto` — segnale di phishing rilevato (contribuisce al punteggio)
- `[ ] neutro` — nessun segnale rilevante
- `[+] sicuro` — segnale positivo di sicurezza
- `[?] non valutato` — modulo non eseguito (timeout, API mancante, ecc.)

---

## 5. Parametri disponibili

| # | Categoria | Parametro | Stato |
|---|---|---|---|
| 1 | lexical | lunghezza_url_dominio | ✅ implementato |
| 2 | lexical | entropia_caratteri | ✅ implementato |
| 3 | lexical | sottodomini | ✅ implementato |
| 4 | lexical | parole_chiave_sensibili | ✅ implementato |
| 5 | lexical | typosquatting_omografi | ✅ implementato |
| 6 | lexical | caratteri_speciali_numeri | ✅ implementato |
| 7 | lexical | tld_sospetti | ✅ implementato |
| 8 | lexical | ip_in_url | ✅ implementato |
| 9 | lexical | url_shortener | ✅ implementato |
| 10 | tls | presenza_https | ✅ implementato |
| 11 | tls | tipo_certificato | ✅ implementato |
| 12 | tls | eta_durata_certificato | ✅ implementato |
| 13 | tls | ca_catena_fiducia | ✅ implementato |
| 14 | tls | protocolli_cifrari | ✅ implementato |
| 15 | dns_whois | eta_dominio | ✅ implementato (python-whois) |
| 16 | dns_whois | durata_registrazione | ✅ implementato (python-whois) |
| 17 | dns_whois | anonimato_whois | ✅ implementato (python-whois) |
| 18 | dns_whois | reputazione_ip_asn | ✅ implementato (Spamhaus DBL via DNS) |
| 19 | dns_whois | fast_flux_dns | ✅ implementato (dnspython) |
| 20 | dns_whois | ttl_dns | ✅ implementato (dnspython) |
| 21 | dns_whois | spf_dkim_dmarc | ✅ implementato (dnspython) |
| 22 | dns_whois | dnssec | ✅ implementato (dnspython, DNSKEY + AD bit) |
| 23 | content | offuscamento_js | ✅ implementato (requests + bs4) |
| 24 | content | form_action_esterno | ✅ implementato (requests + bs4 + tldextract) |
| 25 | content | iframe_nascosti | ✅ implementato (requests + bs4) |
| 26 | content | link_esterni_hotlink | ✅ implementato (requests + bs4) |
| 27 | content | nlp_semantica | ✅ implementato (keyword matching IT/EN) |
| 28 | content | clonazione_visiva | ✅ implementato (match brand noti vs dominio) |
| 29 | dynamic | redirect_chain | ✅ implementato (requests) |
| 30 | dynamic | cloaking | ✅ implementato (confronto 2 fetch con UA diverso) |
| 31 | dynamic | drive_by_download | ✅ implementato (Content-Type/Disposition) |
| 32 | dynamic | exploit | 🚧 stub (richiede sandbox esterna Cuckoo/ANY.RUN) |
| 33 | dynamic | richieste_c2 | 🚧 stub (richiede Playwright + HAR logging) |
| 34 | dynamic | browser_manipolation | ✅ implementato (scareware patterns IT/EN) |
| 35 | dynamic | cryptojacking | ✅ implementato (script src match) |
| 36 | reputation | blacklist_threat_intel | ✅ implementato (Spamhaus ZEN + PhishTank pub + opz. GSB/VT) |
| 37 | reputation | popolarita_traffico | ✅ implementato (Tranco top-1M con cache giornaliera) |
| 38 | reputation | segnalazioni_utenti | 🚧 stub (richiede DB SIRT interno aziendale) |
| 39 | reputation | correlazione_email | 🚧 stub (richiede API SEG Proofpoint/Mimecast) |

**Totale: 35 moduli implementati su 39** (90%). I 4 stub rimanenti richiedono
infrastrutture esterne (sandbox di malware o servizi aziendali interni)
non disponibili in uno strumento pubblico, e lo dicono esplicitamente nel
report con un messaggio chiaro.

---

## 6. Test

Esegui la suite di test (24 test, ~0.1s):

```bash
python3 -m unittest discover tests -v
```

oppure, se hai `pytest`:

```bash
python3 -m pytest tests/ -v
```

---

## 7. Configurazione pesi (opzionale)

I pesi dei parametri si possono personalizzare in `config/weights.yaml`:

```yaml
weights:
  lunghezza_url_dominio: 0.5
  entropia_caratteri: 0.7
  ip_in_url: 2.0
  presenza_https: 1.8
  # ...

thresholds:
  basso: 25
  medio: 50
  alto: 75
```

Se il file manca o è malformato, vengono usati i pesi di default definiti
nel metodo `weight()` di ciascun modulo.

---

## 8. API esterne (opzionali)

I moduli della categoria `reputation` usano variabili d'ambiente. Copia
`.env.example` in `.env` e inserisci le chiavi:

```bash
cp .env.example .env
# poi edita .env con le tue API key
```

Per disattivare un servizio senza rimuovere la chiave:

```bash
export PA_PHISHTANK_ENABLED=0
```

---

## 9. Vincoli di sicurezza

⚠️ **Uso autorizzato solo su domini di proprietà aziendale o con
autorizzazione scritta.**

Il software:
- **non** invia payload reali
- **non** genera malware
- **non** esegue codice ricevuto dagli URL analizzati
- L'analisi dinamica avviene solo in sandbox isolata (il codice implementa
  solo la raccolta di metadati osservabili, non exploit)

---

## 10. Scaricare il progetto

Il progetto è distribuito come archivio ZIP pronto da scaricare:

```
phishing_analyzer.zip
```

Contiene tutta la struttura del progetto, esclusa la cache `__pycache__/`.
Vedi la sezione "Come scaricare" nel messaggio del assistente per il link
al file.
