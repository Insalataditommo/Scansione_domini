#!/usr/bin/env python3
"""
phishing_analyzer/main.py

Comment:
    Orchestrator of the URL analysis system for phishing detection.

    It supports two scenarios (defensive and authorized testing) with an
    interactive CLI interface that lets the user select which parameters
    to activate. The orchestrator imports only the modules needed for the
    chosen parameters (targeted import) and runs the analysis on one or
    more URLs (from command line, from a CSV file, or manual input).

    For each URL it produces:
      - a per-URL report (outcome of each parameter);
      - a final risk percentage normalized 0-100%.

    Weights are defined in config/weights.yaml; when the file is missing,
    the default weights defined in each module (method weight()) are used.

Usage:
    python main.py                         # interactive menu
    python main.py -u URL1 URL2 ...       # analyze URLs from CLI
    python main.py -f urls.csv            # analyze URLs from CSV (column 'url')
    python main.py -u URL -m lexical,tls  # select categories
    python main.py -u URL --all           # activate all categories
    python main.py -u URL -o report.json  # JSON output

Security constraints:
  - Authorized use only on company-owned domains or infrastructures with
    written authorization.
  - No payload sending, no malware generation, no execution of code
    received from the analyzed URLs.
  - Dynamic analysis happens only in an isolated sandbox (see
    modules/dynamic/SANDBOX_ARCHITECTURE.md); the code implements only
    observable metadata collection, not exploits.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import sys
import traceback
from pathlib import Path
from typing import Iterable

# Ensure the project root is in sys.path for absolute imports (core.,
# modules.) both when running `python main.py` from the project root and
# when running from another directory.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.base_module import BaseModule, ModuleResult, Outcome  # noqa: E402
from core.scoring import aggregate, load_weights, effective_weight  # noqa: E402
from core.report import render_text, render_json, render_markdown_table  # noqa: E402


# Category -> label of the Python subpackage (for targeted import).
CATEGORIES: dict[str, str] = {
    "lexical":   "1. Lessicali e strutturali dell'URL",
    "dns_whois": "2. Registrazione e storico (WHOIS/DNS)",
    "tls":       "3. Cifratura e certificati (SSL/TLS)",
    "content":   "4. Codice sorgente e contenuti",
    "dynamic":   "5. Comportamentali (sandbox)",
    "reputation":"6. Rete, traffico e reputazione",
}

DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "config" / "weights.yaml"


# ----------------------------------------------------------------------
# Targeted import of the selected categories
# ----------------------------------------------------------------------
def load_category_modules(categories: Iterable[str]) -> dict[str, type]:
    """Comment: dynamically imports ONLY the modules of the selected categories.

        Respects the constraint of not importing everything together: it
        loads the `modules.<cat>` subpackage only when requested, and
        returns the resulting {parameter_name: class} map.

    Input data:
        categories: iterable of category names (e.g. ["lexical", "tls"]).

    Expected output:
        dict[str, type] mapping parameter name -> module class for all the
        selected categories; unknown or failing categories are skipped
        with a warning printed to stderr.
    """
    selected: dict[str, type] = {}
    for cat in categories:
        if cat not in CATEGORIES:
            print(f"[WARN] categoria sconosciuta '{cat}', ignorata.", file=sys.stderr)
            continue
        try:
            mod = importlib.import_module(f"modules.{cat}")
        except Exception as exc:  # noqa: BLE001
            print(
                f"[ERROR] impossibile importare modules.{cat}: {exc}",
                file=sys.stderr,
            )
            continue
        cat_modules = getattr(mod, "MODULES", {})
        if not cat_modules:
            print(f"[WARN] categoria '{cat}' non espone moduli.", file=sys.stderr)
        selected.update(cat_modules)
    return selected


# ----------------------------------------------------------------------
# Analysis execution on a single URL
# ----------------------------------------------------------------------
def analyze_url(
    url: str,
    module_classes: dict[str, type],
    weights: dict[str, float],
    verbose: bool = True,
) -> tuple[list[ModuleResult], dict]:
    """Comment: runs the analysis of a single URL with the selected modules.

    Input data:
        url:            URL to analyze.
        module_classes: map parameter_name -> module class.
        weights:        weights loaded from config/weights.yaml.
        verbose:        when True, prints progress to stderr.

    Expected output:
        tuple (list of ModuleResult, aggregate result dict). Each module
        that fails to instantiate or run is captured as a NOT_EVALUATED
        ModuleResult and never raises.
    """
    results: list[ModuleResult] = []
    for name, cls in module_classes.items():
        try:
            module: BaseModule = cls()
        except Exception as exc:  # noqa: BLE001
            results.append(ModuleResult(
                name=name,
                outcome=Outcome.NOT_EVALUATED,
                message=f"Istanza non creata: {exc.__class__.__name__}: {exc}",
            ))
            continue
        if verbose:
            print(f"  → {name}...", file=sys.stderr, end="", flush=True)
        result = BaseModule.safe_run(module, url)
        results.append(result)
        if verbose:
            print(f" {result.outcome.value} (score={result.score:.2f})", file=sys.stderr)

    # Build the effective weights dict (module.name -> weight).
    effective_weights = {
        cls().name(): effective_weight(cls(), weights)
        for cls in module_classes.values()
    }

    aggregate_result = aggregate(results, weights=effective_weights)
    return results, aggregate_result


# ----------------------------------------------------------------------
# URL input: CLI, CSV, manual
# ----------------------------------------------------------------------
def collect_urls(args: argparse.Namespace) -> list[str]:
    """Comment: collects the URLs to analyze combining CLI, CSV and stdin.

    Input data:
        args: parsed argparse Namespace with attributes `url`, `file`,
              `interactive`.

    Expected output:
        list[str] of non-empty URLs deduplicated from the CLI list, the
        CSV file, the piped stdin and the interactive prompt.
    """
    urls: list[str] = []
    if args.url:
        urls.extend(args.url)
    if args.file:
        urls.extend(_read_csv_urls(args.file))
    if not urls and sys.stdin.isatty() is False:
        # Read from piped stdin (one URL per line).
        urls.extend([line.strip() for line in sys.stdin if line.strip()])
    if not urls and args.interactive:
        urls.extend(_interactive_url_input())
    return [u for u in urls if u]


def _read_csv_urls(path: str) -> list[str]:
    """Comment: reads URLs from a CSV looking for an 'url' column (case-insensitive).

    Input data:
        path: filesystem path of the CSV file with a header row.

    Expected output:
        list[str] of URLs found in the 'url' column; empty list on file
        not found, missing header, missing column or parse error (a
        warning is printed to stderr).
    """
    urls: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                print(f"[ERROR] CSV '{path}' senza header.", file=sys.stderr)
                return urls
            url_col = next(
                (c for c in reader.fieldnames if c.strip().lower() == "url"),
                None,
            )
            if url_col is None:
                print(
                    f"[ERROR] CSV '{path}' non contiene colonna 'url'. "
                    f"Trovate: {reader.fieldnames}",
                    file=sys.stderr,
                )
                return urls
            for row in reader:
                v = (row.get(url_col) or "").strip()
                if v:
                    urls.append(v)
    except FileNotFoundError:
        print(f"[ERROR] file '{path}' non trovato.", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] lettura CSV '{path}': {exc}", file=sys.stderr)
    return urls


def _interactive_url_input() -> list[str]:
    """Comment: prompts for URLs interactively, one per line, until an empty line.

    Input data: user input from stdin (one URL per line).

    Expected output:
        list[str] of URLs entered by the user; the loop ends on an empty
        line or EOF.
    """
    print("\n=== Inserimento URL ===")
    print("Inserisci un URL per riga. Termina con una riga vuota.")
    urls: list[str] = []
    while True:
        try:
            line = input(f"URL #{len(urls) + 1} (vuoto per terminare): ").strip()
        except EOFError:
            break
        if not line:
            break
        urls.append(line)
    return urls


# ----------------------------------------------------------------------
# Category selection (interactive menu)
# ----------------------------------------------------------------------
def select_categories_interactive() -> list[str]:
    """Comment: shows a text menu for category selection.

        Uses only the standard library (no dependency on rich/questionary)
        for maximum portability. If `questionary` or `rich` are installed
        the user can replace this function for a richer UX.

    Input data: user input from stdin (comma-separated numbers or 'all').

    Expected output:
        list[str] of selected category names; empty list on EOF.
    """
    print("\n=== Selezione categorie di parametri ===")
    print("Seleziona i numeri delle categorie da attivare, separati da virgola.")
    print("Esempio: 1,3   (lexical + tls)   |   'all' per attivarle tutte\n")
    for idx, (cat, label) in enumerate(CATEGORIES.items(), start=1):
        print(f"  {idx}. {label}   [{cat}]")
    print()

    while True:
        try:
            choice = input("Categorie: ").strip().lower()
        except EOFError:
            return []
        if not choice:
            print("[ERROR] selezione vuota.", file=sys.stderr)
            continue
        if choice == "all":
            return list(CATEGORIES.keys())
        try:
            indices = [int(x.strip()) for x in choice.split(",") if x.strip()]
        except ValueError:
            print("[ERROR] input non valido: usa numeri separati da virgola.", file=sys.stderr)
            continue
        cats = []
        valid = True
        for i in indices:
            if i < 1 or i > len(CATEGORIES):
                print(f"[ERROR] numero {i} fuori range.", file=sys.stderr)
                valid = False
                break
            cats.append(list(CATEGORIES.keys())[i - 1])
        if valid and cats:
            return cats


def resolve_categories(args: argparse.Namespace) -> list[str]:
    """Comment: determines the categories to activate based on CLI args.

    Input data:
        args: parsed argparse Namespace with `all`, `modules`,
              `interactive`, `url`, `file`.

    Expected output:
        list[str] of category names; defaults to ["lexical", "tls"] (the
        two fully-implemented categories) when nothing else is specified.
    """
    if args.all:
        return list(CATEGORIES.keys())
    if args.modules:
        cats = [c.strip().lower() for c in args.modules.split(",") if c.strip()]
        unknown = [c for c in cats if c not in CATEGORIES]
        if unknown:
            print(f"[WARN] categorie sconosciute ignorate: {unknown}", file=sys.stderr)
        return [c for c in cats if c in CATEGORIES]
    if args.interactive or (not args.url and not args.file):
        return select_categories_interactive()
    # default: only lexical + tls (the two fully implemented categories).
    return ["lexical", "tls"]


# ----------------------------------------------------------------------
# Report output
# ----------------------------------------------------------------------
def write_reports(
    url: str,
    results: list[ModuleResult],
    aggregate_result: dict,
    out_dir: Path | None,
    json_out: bool,
    markdown_out: bool,
) -> None:
    """Comment: prints the text report to stdout and optionally writes files.

    Input data:
        url:              the analyzed URL.
        results:          list of ModuleResult for the URL.
        aggregate_result: dict returned by scoring.aggregate().
        out_dir:          output directory (None = no file output).
        json_out:         when True, write a JSON report file.
        markdown_out:     when True, write a Markdown report file.

    Expected output:
        None; the text report is always printed to stdout; JSON and
        Markdown files are written to out_dir when requested.
    """
    print(render_text(url, results, aggregate_result))

    if out_dir is None:
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_filename(url)

    if json_out:
        path = out_dir / f"{base}.json"
        path.write_text(
            render_json(url, results, aggregate_result),
            encoding="utf-8",
        )
        print(f"[INFO] report JSON salvato in: {path}", file=sys.stderr)
    if markdown_out:
        path = out_dir / f"{base}.md"
        path.write_text(
            render_markdown_table(url, results, aggregate_result),
            encoding="utf-8",
        )
        print(f"[INFO] report Markdown salvato in: {path}", file=sys.stderr)


def _sanitize_filename(url: str) -> str:
    """Comment: converts a URL into a safe filename (no slash, no colon).

    Input data:
        url: input URL string.

    Expected output:
        str of length <= 120, with non-alphanumeric characters (except
        -_. ) replaced by '_'.
    """
    keep = [c if c.isalnum() or c in "-_." else "_" for c in url]
    name = "".join(keep)
    return name[:120] if len(name) > 120 else name


# ----------------------------------------------------------------------
# Safety banner (shown at startup)
# ----------------------------------------------------------------------
def print_safety_banner(scenario: str) -> None:
    """Comment: prints a banner with the security constraints and the active scenario.

    Input data:
        scenario: name of the active scenario ("difensivo" or
                  "test_autorizzato").

    Expected output:
        None; a multi-line banner is printed to stderr.
    """
    print("=" * 78, file=sys.stderr)
    print("PHISHING ANALYZER - sistema di analisi URL", file=sys.stderr)
    print("=" * 78, file=sys.stderr)
    print(f"Scenario attivo: {scenario}", file=sys.stderr)
    print("-" * 78, file=sys.stderr)
    print("VINCOLI DI SICUREZZA:", file=sys.stderr)
    print("  - Uso autorizzato solo su domini di proprietà aziendale o", file=sys.stderr)
    print("    infrastrutture con autorizzazione scritta.", file=sys.stderr)
    print("  - Nessun invio di payload, nessun malware, nessuna esecuzione", file=sys.stderr)
    print("    di codice ricevuto dagli URL analizzati.", file=sys.stderr)
    print("  - Analisi dinamica in sandbox isolata (vedi", file=sys.stderr)
    print("    modules/dynamic/SANDBOX_ARCHITECTURE.md).", file=sys.stderr)
    print("=" * 78, file=sys.stderr)


# ----------------------------------------------------------------------
# CLI parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Comment: builds the argparse CLI parser with all supported options.

    Input data: none.

    Expected output:
        argparse.ArgumentParser ready to be parsed; options include -u,
        -f, -m, --all, -o, --json, --markdown, -c, -s, --no-interactive, -q.
    """
    p = argparse.ArgumentParser(
        prog="phishing_analyzer",
        description="Sistema modulare di analisi URL per il rilevamento di phishing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Esempi:\n"
            "  python main.py -u https://example.com/login --all\n"
            "  python main.py -f urls.csv -m lexical,tls -o ./reports --json\n"
            "  python main.py   # menu interattivo\n"
        ),
    )
    p.add_argument("-u", "--url", nargs="+", help="URL da analizzare.")
    p.add_argument("-f", "--file", help="File CSV con una colonna 'url'.")
    p.add_argument(
        "-m", "--modules",
        help="Categorie da attivare, separate da virgola (lexical,tls,...).",
    )
    p.add_argument("--all", action="store_true", help="Attiva tutte le categorie.")
    p.add_argument(
        "-o", "--out-dir",
        help="Directory in cui salvare i report (se omesso, stampa solo a video).",
    )
    p.add_argument("--json", action="store_true", help="Salva anche report JSON.")
    p.add_argument("--markdown", action="store_true", help="Salva anche report Markdown.")
    p.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Percorso del file di configurazione (default: {DEFAULT_CONFIG_PATH}).",
    )
    p.add_argument(
        "-s", "--scenario",
        choices=["difensivo", "test_autorizzato"],
        default="difensivo",
        help="Scenario d'uso (solo informativo, non cambia la logica).",
    )
    p.add_argument(
        "--no-interactive", action="store_true",
        help="Disabilita i prompt interattivi (per CI).",
    )
    p.add_argument(
        "-q", "--quiet", action="store_true",
        help="Silenzioso: non stampa il progress dei singoli moduli.",
    )
    return p


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Comment: orchestrator entry point.

    Input data:
        argv: optional list of CLI arguments (defaults to sys.argv).

    Expected output:
        int exit code: 0 on success, 2/3/4 when no categories or URLs are
        selected, 130 on KeyboardInterrupt, 1 on per-URL analysis failure.
    """
    args = build_parser().parse_args(argv)
    args.interactive = not args.no_interactive

    print_safety_banner(args.scenario)

    # 1) Resolve the categories to activate.
    categories = resolve_categories(args)
    if not categories:
        print("[ERROR] nessuna categoria selezionata. Uscita.", file=sys.stderr)
        return 2
    print(f"\nCategorie attive: {', '.join(categories)}", file=sys.stderr)

    # 2) Targeted import of the selected categories' modules.
    module_classes = load_category_modules(categories)
    if not module_classes:
        print("[ERROR] nessun modulo caricato. Uscita.", file=sys.stderr)
        return 3
    print(f"Moduli caricati: {len(module_classes)}", file=sys.stderr)

    # 3) Load weights from the configuration file.
    weights = load_weights(args.config)
    if weights:
        print(f"Pesi caricati da {args.config} ({len(weights)} voci).", file=sys.stderr)
    else:
        print(
            f"[WARN] nessun peso caricato da {args.config}: uso pesi di default "
            f"(definiti nel metodo weight() di ogni modulo). "
            f"Per usare il file YAML installa 'pyyaml' (pip install pyyaml).",
            file=sys.stderr,
        )

    # 4) Collect the URLs.
    urls = collect_urls(args)
    if not urls:
        print("[ERROR] nessun URL da analizzare. Uscita.", file=sys.stderr)
        return 4
    print(f"\nURL da analizzare: {len(urls)}", file=sys.stderr)

    # 5) Run the analysis for each URL.
    out_dir = Path(args.out_dir) if args.out_dir else None
    overall_exit = 0
    for url in urls:
        print(f"\n>>> Analisi: {url}", file=sys.stderr)
        try:
            results, agg = analyze_url(
                url, module_classes, weights, verbose=not args.quiet
            )
        except KeyboardInterrupt:
            print("\n[INTERRUPT] analisi interrotta dall'utente.", file=sys.stderr)
            return 130
        except Exception as exc:  # noqa: BLE001
            print(
                f"[ERROR] analisi fallita per {url}: {exc}",
                file=sys.stderr,
            )
            traceback.print_exc(file=sys.stderr)
            overall_exit = max(overall_exit, 1)
            continue
        write_reports(url, results, agg, out_dir, args.json, args.markdown)

    return overall_exit


if __name__ == "__main__":
    sys.exit(main())
