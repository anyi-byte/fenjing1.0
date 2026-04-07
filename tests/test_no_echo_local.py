import sys
import unittest

sys.path.append("..")

from fenjing import const
from fenjing.full_payload_gen import FullPayloadGen
from fenjing.job import build_no_echo_full_payload_gen
from fenjing.no_echo import NoEchoExecutor, NoEchoOptions, ParsedNoEchoCommand, NoEchoCommandKind
from fenjing.options import Options
from fenjing.submitter import Submitter, HTTPResponse
from flask import Flask, render_template_string


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


class DummySubmitter(Submitter):
    def submit_raw(self, raw_payload):
        return HTTPResponse(200, raw_payload)


class SemiReflectiveSubmitter(Submitter):
    def __init__(self):
        super().__init__()
        self.app = Flask(__name__)

    def submit_raw(self, raw_payload):
        with self.app.app_context():
            try:
                rendered = render_template_string(raw_payload)
            except Exception as exc:
                return HTTPResponse(500, f"{type(exc).__name__}:{exc}")
        if raw_payload.isalpha():
            return HTTPResponse(200, f"<h3>{raw_payload}</h3>")
        return HTTPResponse(200, f"<h3>{rendered}</h3>")


class NoEchoLocalTests(unittest.TestCase):
    def test_cache_priming_expression_is_generatable_under_web370_blacklist(self):
        waf = lambda s: all(word not in s for word in WEB370_BLACKLIST)
        full_payload_gen = FullPayloadGen(
            waf,
            options=Options(
                python_version=const.PythonVersion.PYTHON3,
                python_subversion=sys.version_info.minor,
            ),
        )
        executor = NoEchoExecutor(
            DummySubmitter(),
            full_payload_gen,
            NoEchoOptions(outbound_enabled=False),
        )
        parsed_command = ParsedNoEchoCommand(NoEchoCommandKind.SHELL, "ls")
        expression = executor._build_cache_priming_expression(
            parsed_command,
            "fenjing_cache_key",
        )

        payload, will_print = full_payload_gen.generate(const.EVAL, (const.STRING, expression))

        self.assertTrue(will_print)
        self.assertIsNotNone(payload)

    def test_build_no_echo_full_payload_gen_handles_semi_reflective_pages(self):
        options = Options(
            detect_mode=const.DetectMode.ACCURATE,
            python_version=const.PythonVersion.PYTHON3,
            python_subversion=sys.version_info.minor,
        )
        options.no_echo.enabled = True
        payload_gen = build_no_echo_full_payload_gen(SemiReflectiveSubmitter(), options)
        self.assertIsNotNone(payload_gen)

    def test_shell_timeout_is_reported_in_generated_code(self):
        full_payload_gen = FullPayloadGen(
            lambda _: True,
            options=Options(
                python_version=const.PythonVersion.PYTHON3,
                python_subversion=sys.version_info.minor,
            ),
        )
        executor = NoEchoExecutor(
            DummySubmitter(),
            full_payload_gen,
            NoEchoOptions(command_timeout=0.05),
        )
        parsed_command = ParsedNoEchoCommand(
            NoEchoCommandKind.SHELL,
            f'"{sys.executable}" -c "import time; time.sleep(0.5)"',
        )
        namespace = {}

        exec(executor._build_result_code(parsed_command), namespace, namespace)

        self.assertEqual(namespace["_error"], "1")
        self.assertIn("COMMAND_TIMEOUT", namespace["_raw"].decode())


if __name__ == "__main__":
    unittest.main()
