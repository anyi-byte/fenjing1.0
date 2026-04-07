import sys  # noqa

sys.path.append("..")  # noqa

import unittest
import logging
import os

import requests

import fenjing
from fenjing.context_vars import const_exprs, const_exprs_py3, prepare_context_vars
from fenjing.options import Options

from jinja2 import Template

VULUNSERVER_ADDR = os.environ.get("VULUNSERVER_ADDR", "http://127.0.0.1:5000")

fenjing.payload_gen.logger.setLevel(logging.ERROR)


class ContextVarsTests(unittest.TestCase):
    def test_const_exprs(self):
        exprs = {**const_exprs, **const_exprs_py3}
        for k, (v, _) in exprs.items():
            payload = "{%if (EXPR)==(VALUE)%}yes{%endif%}".replace("EXPR", k).replace(
                "VALUE", repr(v)
            )
            result = Template(payload).render()
            assert "yes" in result, f"Test Failed for {k!r}"

    def test_get_payload_deduplicates_same_context_block(self):
        manager = prepare_context_vars(lambda _: True, Options())
        context = manager.get_context()
        payloads = manager.get_payload(
            {
                "oa": context["oa"],
                "la": context["la"],
                "lla": context["lla"],
                "ob": context["ob"],
                "lb": context["lb"],
            }
        )
        self.assertEqual(len(payloads), 2)
        self.assertEqual(sum("oa**oa" in payload for payload in payloads), 1)
        self.assertEqual(sum("ob**ob" in payload for payload in payloads), 1)

    def test_web370_context_contains_short_underline_helpers(self):
        blacklist = ["'", '"', "args", "[", "]", "_", "os", "{{", "request"] + list("0123456789")
        manager = prepare_context_vars(
            lambda s: all(word not in s for word in blacklist),
            Options(),
        )
        context = manager.get_context()
        self.assertIn("ul", context)
        self.assertIn("ud", context)
        self.assertEqual(context["ul"][0], "_")
        self.assertEqual(context["ud"][0], "__")
