# Phishing Analyzer

Sistema modulare di analisi URL per il rilevamento di phishing, scritto in
Python 3.11+ con tipizzazione statica e docstring in italiano.

## Scenario d'uso

Il sistema è progettato per supportare due scenari complementari:

- **Scenario A (difensivo):** verificare se è in corso una campagna di
  phishing contro i propri utenti, analizzando URL sospetti segnalati.
- **Scenario B (test autorizzato):** avviare una campagna di phishing
  simulata come test interno, per individuare falle e punti deboli.

### Vincoli di sicurezza (non derogabili)

1. Uso autorizzato **solo** su domini di proprietà aziendale o su
   infrastrutture per cui esiste un'autorizzazione scritta.
2. Il software **non** invia payload reali, **non** genera malware e
   **non** esegue codice ricevuto dagli URL analizzati.
3. L'analisi dinamica avviene solo in una **sandbox isolata** (vedi
   [`modules/dynamic/SANDBOX_ARCHITECTURE.md`](modules/dynamic/SANDBOX_ARCHITECTURE.md)).
   Il codice implementa solo la raccolta di metadati osservabili (catena di
   redirect, header, richieste di rete registrate); non implementa exploit
   né meccanismi per eseguire contenuti scaricati.

---

## Struttura del progetto

```
phishing_analyzer/
├── main.py                  # orchestratore + CLI interattiva
├── requirements.txt         # dipendenze base
├── requirements-extra.txt   # dipendenze opzionali (NLP, visione, sandbox)
├── .env.example             # esempio di variabili d'ambiente per API esterne
├── core/
│   ├── base_module.py        # BaseModule + ModuleResult + Outcome
│   ├── scoring.py            # aggregazione punteggi e percentuale finale
│   └── report.py             # report testuale/JSON/Markdown
├── modules/
│   ├── __init__.py           # registry delle categorie
│   ├── lexical/              # 9 moduli COMPLETI (parametri 1-9)
│   ├── dns_whois/            # 8 moduli SCHELETRO (parametri 15-22)
│   ├── tls/                  # 5 moduli COMPLETI (parametri 10-14)
│   ├── content/              # 6 moduli SCHELETRO (parametri 23-28)
│   ├── dynamic/              # 7 moduli SCHELETRO (parametri 29-35)
│   │   └── SANDBOX_ARCHITECTURE.md
│   └── reputation/           # 4 moduli SCHELETRO (parametri 36-39)
├── config/
│   └── weights.yaml          # pesi e soglie modificabili
└── tests/
    ├── test_basic.py
    └── urls_sample.csv
```

Totale: **39 parametri** suddivisi in 6 categorie. Di questi, 14 sono
completamente implementati (9 lexical + 5 tls) e 25 sono forniti come
scheletri con firme dei metodi, docstring e TODO espliciti.

---

## Architettura

### Interfaccia comune

Ogni modulo espone una classe che eredita da `BaseModule` e implementa:

```python
class MioModulo(BaseModule):
    def name(self) -> str: ...       # identificativo snake_case
    def weight(self) -> float: ...   # peso di default (>= 0)
    def run(self, url: str) -> ModuleResult: ...
```

`ModuleResult` contiene: nome, valore grezzo, punteggio (0–1), esito
(`sospetto` / `neutro` / `sicuro` / `non valutato`), soglia e messaggio.

### Robustezza

Un parametro che fallisce (timeout, API non disponibile, errore interno)
**non** blocca l'analisi: il metodo statico `BaseModule.safe_run()` cattura
ogni eccezione e restituisce un `ModuleResult` con
`outcome=NOT_EVALUATED`. Il modulo viene segnalato nel report ed escluso
dal calcolo della percentuale finale.

### Scoring

La percentuale di rischio finale è una **media pesata** normalizzata in
`[0%, 100%]`:

```
risk_pct = 100 * Σ(score_i × weight_i) / Σ(weight_i)
```

calcolata solo sui moduli effettivamente valutati. I moduli `SAFE`
contribuiscono con score 0, quelli `SUSPICIOUS` con score fino a 1.
I pesi sono definiti in
[`config/weights.yaml`](config/weights.yaml); se assenti, viene usato il
peso di default del modulo stesso (metodo `weight()`).

Etichette qualitative della percentuale finale:

| Range    | Etichetta |
|----------|-----------|
| 0 – 24%  | basso     |
| 25 – 49% | medio     |
| 50 – 74% | alto     |
| 75 – 100%| critico   |

### Import mirato

L'orchestratore importa dinamicamente **solo** i moduli delle categorie
selezionate dall'utente (vedi `main.py::load_category_modules`). Questo
rispetta il vincolo di non caricare tutto insieme e riduce la
superficie di dipendenze quando un'analisi non richiede, ad esempio, il
fetch di pagine remote o la sandbox dinamica.

### Moduli con servizi esterni

I moduli che richiedono API esterne (PhishTank, Spamhaus, Google Safe
Browsing, VirusTotal) leggono le API key da variabili d'ambiente (vedi
[`.env.example`](.env.example)) e possono essere disattivati impostando
`PA_<SERVIZIO>_ENABLED=0`. Se tutti i servizi di una categoria sono
disattivati, il modulo ritorna `NOT_EVALUATED` con un messaggio che elenca
i servizi esclusi.

### NLP (parametro 27) e visione (parametro 28)

- **NLP**: implementazione raccomandata con `spacy` + modello
  `it_core_news_sm` (POC e keyword extraction); in alternativa TF-IDF su
  un dictionary di frasi di phishing noto. Fallback su keyword matching se
  `spacy` non è installato.
- **Visione**: implementazione raccomandata con `Pillow` + `imagehash`
  (pHash) e un database di hash di loghi noti, confrontando per distanza
  di Hamming. Lo stub è fornito in `modules/content/content_modules.py` con
  un TODO esplicito perché la complessità richiede un DB di loghi.

---

## Installazione

### Requisiti

- Python 3.11 o superiore
- Connessione a Internet (per i moduli che contattano servizi esterni)

### Passi

```bash
cd phishing_analyzer

# 1) Crea un virtualenv (raccomandato)
python3.11 -m venv .venv
source .venv/bin/activate

# 2) Installa le dipendenze base
pip install -r requirements.txt

# 3) (Opzionale) Dipendenze avanzate: NLP, visione, sandbox
pip install -r requirements-extra.txt
python -m spacy download it_core_news_sm
python -m playwright install chromium

# 4) (Opzionale) Configura le API key esterne
cp .env.example .env
# modifica .env con le tue chiavi
```

---

## Esecuzione

### Menu interattivo

```bash
python main.py
```

Output atteso:

```
==============================================================================
PHISHING ANALYZER - sistema di analisi URL
==============================================================================
Scenario attivo: difensivo
------------------------------------------------------------------------------
VINCOLI DI SICUREZZA:
  - Uso autorizzato solo su domini di proprietà aziendale o
    infrastrutture con autorizzazione scritta.
  - Nessun invio di payload, nessun malware, nessuna esecuzione
    di codice ricevuto dagli URL analizzati.
  - Analisi dinamica in sandbox isolata (vedi
    modules/dynamic/SANDBOX_ARCHITECTURE.md).
==============================================================================

=== Selezione categorie di parametri ===
Seleziona i numeri delle categorie da attivare, separati da virgola.
Esempio: 1,3   (lexical + tls)   |   'all' per attivarle tutte

  1. 1. Lessicali e strutturali dell'URL   [lexical]
  2. 2. Registrazione e storico (WHOIS/DNS)   [dns_whois]
  3. 3. Cifratura e certificati (SSL/TLS)   [tls]
  4. 4. Codice sorgente e contenuti   [content]
  5. 5. Comportamentali (sandbox)   [dynamic]
  6. 6. Rete, traffico e reputazione   [reputation]

Categorie: 1,3

=== Inserimento URL ===
Inserisci un URL per riga. Termina con una riga vuota.
URL #1 (vuoto per terminare): http://example.tk/login-verify-account
URL #2 (vuoto per terminare):
```

### Da riga di comando

```bash
# Analizza un singolo URL con tutte le categorie
python main.py -u http://example.tk/login-verify-account --all

# Analizza più URL con categorie specifiche, salva in JSON
python main.py -u https://google.com https://bit.ly/abc -m lexical,tls \
    -o ./reports --json

# Analizza da CSV
python main.py -f tests/urls_sample.csv -m lexical --all -o ./reports --json

# Scenario test autorizzato, silenzioso, output Markdown
python main.py -u http://example.tk/login -s test_autorizzato \
    -m lexical,tls --markdown -q -o ./reports

# Pipeline da stdin
cat urls.txt | python main.py --all -o ./reports --json --no-interactive
```

### Help completo

```bash
python main.py --help
```

---

## Esempio di report finale

```
==============================================================================
REPORT DI ANALISI PHISHING
==============================================================================
URL              : http://example.tk/login-verify-account
Timestamp (UTC)  : 2026-11-17T09:30:00+00:00
------------------------------------------------------------------------------
Parametro                        Esito         Score  Dettagli
------------------------------------------------------------------------------
lunghezza_url_dominio            [!] sospetto     0.81  url_length=45, domain_length=7
                                 → URL lungo 45 caratteri, dominio 7 caratteri: lunghezze elevate...
                                 soglia: {'url_neutro_max': 75, ...}
entropia_caratteri               [ ] neutro       0.35  3.85
                                 → Entropia 3.85 bit/car: nella fascia di guardia.
sottodomini                      [+] sicuro       0.00  depth=0, count=0
parole_chiave_sensibili          [!] sospetto     0.80  keywords=['login', 'verify', 'account']
                                 → Trovate 3 parole chiave sensibili su dominio non ufficiale...
typosquatting_omografi           [+] sicuro       0.00  domain=example.tk
caratteri_speciali_numeri        [+] sicuro       0.00  dash_count=0, digit_ratio=0.000
tld_sospetti                     [!] sospetto     0.80  tld=tk
                                 → TLD .tk presente in lista TLD ad alto rischio...
ip_in_url                        [+] sicuro       0.00  is_ip=False
url_shortener                   [+] sicuro       0.00  is_shortener=False
presenza_https                   [!] sospetto     1.00  scheme=http
                                 → URL in HTTP chiaro: nessuna cifratura...
tipo_certificato                [?] non valutato  n/a
                                 → Certificato non valutato: errore di rete...
------------------------------------------------------------------------------
RISCHIO FINALE: 58.40%  [ALTO]
Moduli valutati: 9 | Non valutati: 1
Non valutati: tipo_certificato
==============================================================================
```

In JSON (estratto):

```json
{
  "url": "http://example.tk/login-verify-account",
  "timestamp_utc": "2026-11-17T09:30:00+00:00",
  "risk_pct": 58.40,
  "label": "alto",
  "weighted_sum": 4.66,
  "weight_sum": 8.0,
  "evaluated": ["lunghezza_url_dominio", "entropia_caratteri", ...],
  "not_evaluated": ["tipo_certificato"],
  "modules": [ ... ]
}
```

---

## Configurazione dei pesi

I pesi e le soglie sono in [`config/weights.yaml`](config/weights.yaml):

```yaml
weights:
  eta_dominio:           2.0   # dominio giovane = segnale forte
  blacklist_threat_intel: 2.5   # ground truth esterna
  lunghezza_url_dominio: 0.5   # da solo non significa nulla
  ...

thresholds:
  eta_dominio:
    sicuro_min_giorni: 365
    sospetto_max_giorni: 30
  ...

risk_labels:
  basso:   0
  medio:   25
  alto:    50
  critico: 75
```

Per modificare un peso senza toccare il codice, basta editare il valore in
`weights.yaml`: il cambio ha effetto al riavvio del programma.

---

## Test

```bash
cd phishing_analyzer
python -m pytest tests/            # con pytest
# oppure
python -m unittest discover tests  # con unittest stdlib
```

I test coprono:

- clamping dello score in `[0, 1]` e gestione NaN;
- `safe_run` che cattura le eccezioni;
- moduli lexical su URL sicuri e sospetti (IP, TLD, shortener, lunghezza);
- aggregazione dei punteggi con pesi ed esclusione dei `NOT_EVALUATED`;
- etichette qualitative (basso/medio/alto/critico).

---

## Estensione: aggiungere un nuovo modulo

1. Crea `modules/<categoria>/mio_modulo.py` con una classe che eredita da
   `BaseModule` e implementa `name`, `weight`, `run`.
2. Aggiungi la classe al registro `MODULES` di
   `modules/<categoria>/__init__.py`.
3. (Opzionale) aggiungi il peso e le soglie in `config/weights.yaml`.
4. Aggiungi un test in `tests/test_basic.py`.

Esempio minimo:

```python
from core.base_module import BaseModule, ModuleResult, Outcome

class MioModulo(BaseModule):
    description = "Esempio di nuovo modulo."
    def name(self) -> str: return "mio_modulo"
    def weight(self) -> float: return 1.0
    def run(self, url: str) -> ModuleResult:
        return ModuleResult(
            name=self.name(),
            raw_value=None,
            score=0.0,
            outcome=Outcome.NEUTRAL,
            message="Modulo implementato.",
        )
```

---

## Punti che richiedono validazione umana o autorizzazione aggiuntiva

Vedi la sezione "Punti di validazione umana" nel report finale del
deliverable: sono elencati i punti in cui serve un controllo manuale o
un'autorizzazione scritta prima di passare alla fase di test sul campo.

---

## Licenza e responsabilità d'uso

Questo software è fornito come strumento difensivo e di testing
autorizzato. L'utente è il solo responsabile dell'uso che ne fa e del
rispetto delle leggi locali (GDPR, normative di sicurezza, Computer Fraud
and Abuse Act, ecc.). Gli autori non si assumono responsabilità per usi
illeciti o non autorizzati.
