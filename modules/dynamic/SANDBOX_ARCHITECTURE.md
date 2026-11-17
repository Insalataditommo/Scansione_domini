"""
modules/dynamic/SANDBOX_ARCHITECTURE.md

# Architettura della sandbox per l'analisi dinamica

## Scopo

Permettere l'osservazione del comportamento di un URL sospetto in un ambiente
isolato, senza mai esporre l'infrastruttura aziendale e senza mai eseguire
codice ricevuto dall'URL al di fuori del browser headless confinato.

## Vincoli di sicurezza (NON derogabili)

1. Nessuna esecuzione di codice nativo ricevuto dall'URL analizzato al di
   fuori del processo browser headless.
2. Nessuna implementazione o integrazione di exploit.
3. Nessuna scrittura su filesystem del sistema host: tutto il filesystem
   della sandbox è ephemeral (tmpfs / overlay).
4. Nessun accesso alla rete interna aziendale: il container ha una sola
   interfaccia connessa a una rete dedicata (DMZ di analisi) che instrada
   solo verso Internet attraverso un proxy di logging.
5. Nessun invio di payload reali o credenziali ai siti analizzati.
6. Timeout rigidi per ogni fase.

## Componenti

```
                +-----------------------------------------+
                |           Host di analisi                |
                |  (machine fisica, NON rete aziendale)   |
                |                                          |
                |  +-----------------------------+          |
                |  |   Container Docker isolato  |          |
                |  |   rete: dmz-analisi (only)  |          |
                |  |   filesystem: overlay/tmpfs |          |
                |  |   no capabilities extra     |          |
                |  |   read_only filesystem      |          |
                |  |                             |          |
                |  |  +------------------------+ |          |
                |  |  | Browser headless        | |          |
                |  |  | (Chromium, profilo      | |          |
                |  |  |  usa-e-getta)            | |          |
                |  |  |  --no-sandbox limitato   | |          |
                |  |  |  CPU/mem limiti cgroups  | |          |
                |  |  +------------------------+ |          |
                |  |           |                  |          |
                |  |  +------------------------+ |          |
                |  |  | Proxy MITM (mitmproxy)  | |          |
                |  |  | logging HAR + PCAP      | |          |
                |  |  | NO modifica traffico    | |          |
                |  |  +------------------------+ |          |
                |  +-----------------------------+          |
                |            |                              |
                |  +-----------------------------+          |
                |  |  DNS resolver di analisi    |          |
                |  |  (risolve solo host Internet)|         |
                |  +-----------------------------+          |
                +-----------------------------------------+
                                |
                                v
                          Internet (DMZ)
```

## Flusso di un'analisi

1. L'orchestratore avvia un container Docker con immagine `pa-sandbox:latest`
   usando i flag di isolamento:
   ```
   --network dmz-analisi
   --memory 512m --cpus 1
   --read-only
   --tmpfs /tmp:rw,size=64m
   --security-opt no-new-privileges
   --cap-drop ALL
   ```
2. All'interno del container, il browser headless (Chromium via Playwright)
   viene avviato con un profilo pulito:
   ```
   chromium --headless --disable-gpu --no-first-run \
            --user-data-dir=/tmp/profile \
            --proxy-server=http://mitmproxy:8080
   ```
3. Il proxy MITM registra HAR + PCAP di tutte le richieste. Nessuna
   intercettazione TLS attiva: il browser usa una CA di analisi installata
   solo nel profilo usa-e-getta.
4. La pagina viene caricata con timeout 15 s. Eventuali dialoghi JavaScript
   (alert/confirm/prompt) vengono automaticamente chiusi.
5. Vengono raccolti:
   - URL finali di tutte le richieste (catena di redirect, XHR, fetch);
   - header di risposta (Content-Type, Content-Disposition);
   - elenco di host/IP contattati;
   - hash SHA-256 del body HTML e delle risorse principali.
6. Al termine, il container viene distrutto e i log vengono salvati in
   `download/sandbox_logs/<url_hash>/`.

## Cosa NON fa la sandbox

- Non esegue binari scaricati dalla pagina.
- Non implementa exploit né test di penetrazione.
- Non invia credenziali o dati sensibili ai siti analizzati.
- Non accede alla rete interna aziendale.
- Non implementa rilevamento di exploit in-browser (richiede strumentazione
  addizionale come Cuckoo Sandbox, esterna a questo progetto).

## Estensioni future (fuori scope)

- Integrazione con Cuckoo Sandbox per analisi comportamentale di processi
  (richiede VM dedicate, fuori dai vincoli di questo progetto).
- Analisi di memoria post-esecuzione (Volatility) - solo dopo esplicita
  autorizzazione scritta.
"""
