"""Comment: minimal tests for phishing_analyzer.

    Runnable with:
        cd phishing_analyzer
        python -m pytest tests/
    or:
        python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

# Add the project root to sys.path for absolute imports.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.base_module import BaseModule, ModuleResult, Outcome  # noqa: E402
from core.scoring import aggregate  # noqa: E402
from modules.lexical.lunghezza import LunghezzaUrlDominio  # noqa: E402
from modules.lexical.entropia import EntropiaCaratteri  # noqa: E402
from modules.lexical.ip_in_url import IpInUrl  # noqa: E402
from modules.lexical.tld_sospetti import TldSospetti  # noqa: E402
from modules.lexical.url_shortener import UrlShortener  # noqa: E402


class TestModuleResult(unittest.TestCase):
    """Comment: tests for the ModuleResult dataclass normalization."""

    def test_score_clamping(self):
        """Comment: verifies that scores above 1 and below 0 are clamped.

        Input data: ModuleResult with score=5.0 then score=-1.0.
        Expected output: r.score within [0.0, 1.0] in both cases.
        """
        r = ModuleResult(name="t", score=5.0, outcome=Outcome.SUSPICIOUS)
        self.assertLessEqual(r.score, 1.0)
        r = ModuleResult(name="t", score=-1.0, outcome=Outcome.SUSPICIOUS)
        self.assertGreaterEqual(r.score, 0.0)

    def test_score_nan_is_zero(self):
        """Comment: verifies that NaN scores are forced to 0.

        Input data: ModuleResult with score=NaN.
        Expected output: r.score == 0.0.
        """
        r = ModuleResult(name="t", score=float("nan"), outcome=Outcome.SUSPICIOUS)
        self.assertEqual(r.score, 0.0)

    def test_not_evaluated_zero(self):
        """Comment: verifies that NOT_EVALUATED results have score 0.

        Input data: ModuleResult with score=0.9 and outcome=NOT_EVALUATED.
        Expected output: r.score == 0.0.
        """
        r = ModuleResult(name="t", score=0.9, outcome=Outcome.NOT_EVALUATED)
        self.assertEqual(r.score, 0.0)


class TestSafeRun(unittest.TestCase):
    """Comment: tests for the BaseModule.safe_run exception-catcher."""

    def test_safe_run_catches_exception(self):
        """Comment: verifies that safe_run captures exceptions.

        Input data: a BaseModule whose run() raises RuntimeError("boom").
        Expected output: ModuleResult with outcome=NOT_EVALUATED and the
        string "boom" in the message.
        """
        class BadModule(BaseModule):
            def name(self): return "bad"
            def weight(self): return 1.0
            def run(self, url): raise RuntimeError("boom")

        result = BaseModule.safe_run(BadModule(), "http://x")
        self.assertEqual(result.outcome, Outcome.NOT_EVALUATED)
        self.assertIn("boom", result.message)


class TestLexicalModules(unittest.TestCase):
    """Comment: tests for the lexical modules on safe and suspicious URLs."""

    def test_lunghezza_short_safe(self):
        """Comment: verifies a short URL is rated SAFE.

        Input data: URL "https://google.com".
        Expected output: outcome == SAFE.
        """
        r = LunghezzaUrlDominio().run("https://google.com")
        self.assertEqual(r.outcome, Outcome.SAFE)

    def test_lunghezza_long_suspicious(self):
        """Comment: verifies a very long URL is rated SUSPICIOUS.

        Input data: URL with 200 'a' chars in the path.
        Expected output: outcome == SUSPICIOUS.
        """
        long_url = "https://example.com/" + ("a" * 200)
        r = LunghezzaUrlDominio().run(long_url)
        self.assertEqual(r.outcome, Outcome.SUSPICIOUS)

    def test_ip_in_url(self):
        """Comment: verifies an IP literal URL is rated SUSPICIOUS with score 1.

        Input data: URL "http://192.168.0.1/login".
        Expected output: outcome == SUSPICIOUS and score == 1.0.
        """
        r = IpInUrl().run("http://192.168.0.1/login")
        self.assertEqual(r.outcome, Outcome.SUSPICIOUS)
        self.assertEqual(r.score, 1.0)

    def test_ip_not_in_url(self):
        """Comment: verifies a domain URL is rated SAFE.

        Input data: URL "https://google.com".
        Expected output: outcome == SAFE.
        """
        r = IpInUrl().run("https://google.com")
        self.assertEqual(r.outcome, Outcome.SAFE)

    def test_tld_sospetto(self):
        """Comment: verifies a suspicious TLD (.tk) is rated SUSPICIOUS.

        Input data: URL "http://example.tk/login".
        Expected output: outcome == SUSPICIOUS.
        """
        r = TldSospetti().run("http://example.tk/login")
        self.assertEqual(r.outcome, Outcome.SUSPICIOUS)

    def test_tld_normale(self):
        """Comment: verifies a normal TLD (.com) is rated SAFE.

        Input data: URL "https://example.com".
        Expected output: outcome == SAFE.
        """
        r = TldSospetti().run("https://example.com")
        self.assertEqual(r.outcome, Outcome.SAFE)

    def test_url_shortener(self):
        """Comment: verifies a shortener URL is rated SUSPICIOUS.

        Input data: URL "http://bit.ly/abc".
        Expected output: outcome == SUSPICIOUS.
        """
        r = UrlShortener().run("http://bit.ly/abc")
        self.assertEqual(r.outcome, Outcome.SUSPICIOUS)

    def test_entropia_high(self):
        """Comment: verifies entropy module returns a valid outcome.

        Input data: URL with high-entropy host.
        Expected output: outcome is one of SUSPICIOUS/NEUTRAL/SAFE.
        """
        # High-entropy random string.
        r = EntropiaCaratteri().run("https://xq9k2z8m4j7p1.example.com")
        self.assertIn(r.outcome, (Outcome.SUSPICIOUS, Outcome.NEUTRAL, Outcome.SAFE))

    def test_url_invalido(self):
        """Comment: verifies an empty URL returns NOT_EVALUATED.

        Input data: empty string URL.
        Expected output: outcome == NOT_EVALUATED.
        """
        r = LunghezzaUrlDominio().run("")
        self.assertEqual(r.outcome, Outcome.NOT_EVALUATED)


class TestScoring(unittest.TestCase):
    """Comment: tests for the scoring.aggregate function."""

    def test_aggregate_empty(self):
        """Comment: verifies aggregate on empty input returns 0 risk.

        Input data: empty list of ModuleResult.
        Expected output: risk_pct == 0.0 and label == "indeterminato".
        """
        agg = aggregate([])
        self.assertEqual(agg["risk_pct"], 0.0)
        self.assertEqual(agg["label"], "indeterminato")

    def test_aggregate_weights(self):
        """Comment: verifies weighted average with equal weights yields 50%.

        Input data: two ModuleResults (score 1.0 and 0.0) with weights 2.0
        and 2.0.
        Expected output: risk_pct ~= 50.0.
        """
        r1 = ModuleResult(name="a", score=1.0, outcome=Outcome.SUSPICIOUS)
        r2 = ModuleResult(name="b", score=0.0, outcome=Outcome.SAFE)
        agg = aggregate([r1, r2], weights={"a": 2.0, "b": 2.0})
        self.assertAlmostEqual(agg["risk_pct"], 50.0, places=1)

    def test_aggregate_excludes_not_evaluated(self):
        """Comment: verifies NOT_EVALUATED modules are excluded from the score.

        Input data: one SUSPICIOUS (w=1.0) and one NOT_EVALUATED (w=100.0)
        ModuleResult.
        Expected output: risk_pct == 100.0 and "b" in not_evaluated.
        """
        r1 = ModuleResult(name="a", score=1.0, outcome=Outcome.SUSPICIOUS)
        r2 = ModuleResult(name="b", score=1.0, outcome=Outcome.NOT_EVALUATED)
        agg = aggregate([r1, r2], weights={"a": 1.0, "b": 100.0})
        self.assertEqual(agg["risk_pct"], 100.0)
        self.assertIn("b", agg["not_evaluated"])

    def test_aggregate_label_basso(self):
        """Comment: verifies a low score yields the "basso" label.

        Input data: one NEUTRAL ModuleResult with score 0.1.
        Expected output: label == "basso".
        """
        r1 = ModuleResult(name="a", score=0.1, outcome=Outcome.NEUTRAL)
        agg = aggregate([r1], weights={"a": 1.0})
        self.assertEqual(agg["label"], "basso")

    def test_aggregate_label_critico(self):
        """Comment: verifies a max score yields the "critico" label.

        Input data: one SUSPICIOUS ModuleResult with score 1.0.
        Expected output: label == "critico".
        """
        r1 = ModuleResult(name="a", score=1.0, outcome=Outcome.SUSPICIOUS)
        agg = aggregate([r1], weights={"a": 1.0})
        self.assertEqual(agg["label"], "critico")


class TestDnsWhoisHelpers(unittest.TestCase):
    """Comment: tests for the dns_whois utility helpers (offline, no network)."""

    def test_get_registered_domain_simple(self):
        """Comment: verifies that a simple URL returns sld.tld.

        Input data: "https://www.google.com/path".
        Expected output: "google.com".
        """
        from modules.dns_whois._dnsutils import get_registered_domain
        self.assertEqual(get_registered_domain("https://www.google.com/path"), "google.com")

    def test_get_registered_domain_subdomain(self):
        """Comment: verifies that subdomains are stripped.

        Input data: "https://login.accounts.example.co.uk/".
        Expected output: "example.co.uk".
        """
        from modules.dns_whois._dnsutils import get_registered_domain
        self.assertEqual(
            get_registered_domain("https://login.accounts.example.co.uk/"),
            "example.co.uk",
        )

    def test_get_registered_domain_ip_returns_none(self):
        """Comment: verifies that an IP literal returns None.

        Input data: "http://192.168.0.1/admin".
        Expected output: None (an IP is not a registered domain).
        """
        from modules.dns_whois._dnsutils import get_registered_domain
        self.assertIsNone(get_registered_domain("http://192.168.0.1/admin"))

    def test_get_registered_domain_invalid_returns_none(self):
        """Comment: verifies that an empty/invalid URL returns None.

        Input data: "" and "   ".
        Expected output: None for both inputs.
        """
        from modules.dns_whois._dnsutils import get_registered_domain
        self.assertIsNone(get_registered_domain(""))
        self.assertIsNone(get_registered_domain("   "))


class TestScoringWeightsFallback(unittest.TestCase):
    """Comment: tests for the minimal YAML fallback parser in scoring.py."""

    def test_load_weights_with_pyyaml(self):
        """Comment: verifies that the real weights.yaml loads with pyyaml.

        Input data: the project's config/weights.yaml path.
        Expected output: dict with >= 30 entries (one per parameter).
        """
        from core.scoring import load_weights
        path = str(ROOT / "config" / "weights.yaml")
        weights = load_weights(path)
        self.assertGreaterEqual(len(weights), 30)
        self.assertAlmostEqual(weights.get("ip_in_url", 0.0), 2.0)
        self.assertAlmostEqual(weights.get("eta_dominio", 0.0), 2.0)

    def test_load_weights_minimal_fallback(self):
        """Comment: verifies that the minimal fallback parser works.

        Input data: a temporary YAML file with only a `weights:` block.
        Expected output: dict with the two entries, even without pyyaml.
        """
        import os
        import sys
        import tempfile

        # Simulate pyyaml NOT installed by hiding the module.
        original_yaml = sys.modules.get("yaml")
        sys.modules["yaml"] = None  # type: ignore
        try:
            # Reload scoring to reset the cached `import yaml` failure.
            if "core.scoring" in sys.modules:
                del sys.modules["core.scoring"]
            from core.scoring import load_weights  # noqa: E402

            with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False, encoding="utf-8"
            ) as fh:
                fh.write(
                    "# test config\n"
                    "weights:\n"
                    "  ip_in_url: 2.0   # high weight\n"
                    "  eta_dominio: 1.5\n"
                    "\n"
                    "thresholds:\n"
                    "  ip_in_url:\n"
                    "    is_ip_expected: false\n"
                )
                path = fh.name
            try:
                weights = load_weights(path)
            finally:
                os.unlink(path)
            self.assertEqual(weights.get("ip_in_url"), 2.0)
            self.assertEqual(weights.get("eta_dominio"), 1.5)
            self.assertNotIn("thresholds", weights)
        finally:
            if original_yaml is None:
                sys.modules.pop("yaml", None)
            else:
                sys.modules["yaml"] = original_yaml
            # Reload scoring with the real yaml availability.
            if "core.scoring" in sys.modules:
                del sys.modules["core.scoring"]


if __name__ == "__main__":
    unittest.main()