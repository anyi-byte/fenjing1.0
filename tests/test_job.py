import sys
import unittest

sys.path.append("..")

from fenjing import const
from fenjing.full_payload_gen import FullPayloadGen
from fenjing.job import do_submit_cmdexec
from fenjing.options import Options
from fenjing.rules_utils import precedence
from fenjing.submitter import HTTPResponse, Submitter


class DummyCache:
    def clear(self):
        return None


class DummyPayloadGen:
    def __init__(self):
        self.waf_func = lambda payload: True
        self.cache_by_repr = DummyCache()


class DummyContextVars:
    def get_payload(self, _used_context):
        return []

    def get_context(self):
        return {}


class AutofixSubmitter(Submitter):
    def submit_raw(self, raw_payload):
        if "BAD" in raw_payload:
            return HTTPResponse(500, "Internal Server Error")
        return HTTPResponse(200, "command output")


class AutofixFullPayloadGen(FullPayloadGen):
    def __init__(self):
        self.options = Options(autofix_500=const.AutoFix500Code.ENABLED)
        self.waf_func = lambda payload: True
        self.waf_expr_func = None
        self.payload_gen = DummyPayloadGen()
        self._callback = lambda *_: None
        self.outer_pattern = "{{PAYLOAD}}"
        self.context_vars = DummyContextVars()
        self.prepared = True
        self.will_print = True

    def generate_with_tree(self, gen_type, *args):
        del gen_type, args
        if self.payload_gen.waf_func("BAD"):
            tree = [
                (
                    (const.EXPRESSION, precedence["literal"], [(const.LITERAL, "BAD")]),
                    [((const.LITERAL, "BAD"), [])],
                )
            ]
            return "BAD", True, tree
        tree = [
            (
                (const.EXPRESSION, precedence["literal"], [(const.LITERAL, "GOOD")]),
                [((const.LITERAL, "GOOD"), [])],
            )
        ]
        return "GOOD", True, tree


class JobTests(unittest.TestCase):
    def test_do_submit_cmdexec_autofixes_500(self):
        submitter = AutofixSubmitter()
        payload_gen = AutofixFullPayloadGen()

        result = do_submit_cmdexec("id", submitter, payload_gen)

        self.assertEqual(result, "command output")
        self.assertFalse(payload_gen.payload_gen.waf_func("BAD"))
        self.assertTrue(payload_gen.payload_gen.waf_func("GOOD"))


if __name__ == "__main__":
    unittest.main()
