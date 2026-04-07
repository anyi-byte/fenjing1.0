# pylint: skip-file
# flake8: noqa

import sys

sys.path.append("..")

import time
import threading
import unittest
import os
from unittest import mock
import requests
from fenjing import webui, const
from fenjing.options import Options

WEBUI_URL = "http://127.0.0.1:11451"
VULUNSERVER_URL = os.environ.get("VULUNSERVER_ADDR", "http://127.0.0.1:5000")

t = threading.Thread(target=webui.main, kwargs={"open_browser": False})
t.daemon = True
t.start()
time.sleep(0.5)


class TestWebui(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_index(self):
        resp = requests.get(WEBUI_URL)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("<!DOCTYPE html>", resp.text)

    def wait_for_task(self, task_id, task_type, max_time=60):
        start_time = time.perf_counter()
        while True:
            time.sleep(0.2)
            resp = requests.post(
                WEBUI_URL + "/watchTask",
                data={
                    "taskid": task_id,
                },
            )
            resp_data = resp.json()
            self.assertEqual(resp_data["code"], const.APICODE_OK)
            if resp_data["done"]:
                if task_type == "crack":
                    self.assertTrue(resp_data["success"])
                break
            self.assertLessEqual(time.perf_counter() - start_time, max_time)

    def general_task_test(
        self,
        request_data,
        cmd="echo test  webui",
        expected="test webui",
        max_time=60,
    ):
        resp = requests.post(WEBUI_URL + "/createTask", data=request_data)
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        task_id = resp_data["taskid"]
        self.wait_for_task(task_id, "crack", max_time=max_time)

        resp = requests.post(
            WEBUI_URL + "/createTask",
            data={
                "type": "interactive",
                "last_task_id": task_id,
                "cmd": cmd,
            },
        )
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        task_id = resp_data["taskid"]
        self.wait_for_task(task_id, "interact", max_time=max_time)

        resp = requests.post(
            WEBUI_URL + "/watchTask",
            data={
                "taskid": task_id,
            },
        )
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        messages = resp_data["messages"]

        is_cmd_executed = any(expected in msg for msg in messages)
        self.assertTrue(is_cmd_executed)

    def test_crack(self):
        self.general_task_test(
            {
                "type": "crack",
                "url": VULUNSERVER_URL,
                "inputs": "name",
                "method": "GET",
                "action": "/",
                "interval": "0.02",
            }
        )

    def test_scan(self):
        self.general_task_test(
            {
                "type": "scan",
                "url": VULUNSERVER_URL,
                "interval": "0.02",
            }
        )

    def test_crack_path(self):
        self.general_task_test(
            {
                "type": "crack-path",
                "url": VULUNSERVER_URL + "/crackpath/",
                "interval": "0.02",
            }
        )

    def test_crack_json(self):
        self.general_task_test(
            {
                "type": "crack-json",
                "url": VULUNSERVER_URL + "/crackjson",
                "json_data": '{"name": "admin", "age": 24, "msg": "test"}',
                "key": "msg",
                "method": "POST",
                "interval": "0.02",
            }
        )

    def test_parse_options_no_echo(self):
        parsed = webui.parse_options(
            {
                "detect-mode": "fast",
                "environment": "flask",
                "replaced_keyword_strategy": "ignore",
                "detect_waf_keywords": "full",
                "no_echo": "on",
                "outbound_enabled": "false",
                "no_echo_callback_url": "http://127.0.0.1:18080/callback",
                "no_echo_receiver_api": "http://127.0.0.1:18080/records",
                "no_echo_listen_host": "0.0.0.0",
                "no_echo_listen_port": "18080",
                "no_echo_probe_timeout": "2.5",
                "no_echo_poll_interval": "0.3",
                "no_echo_chunk_size": "72",
                "no_echo_blind_delay": "0.4",
                "no_echo_blind_threshold": "0.75",
                "no_echo_blind_max_length": "48",
                "no_echo_command_timeout": "9.5",
                "no_echo_dns_domain": "dnslog.example.com",
                "no_echo_dnslog_command": "python poll.py",
            }
        )
        self.assertEqual(parsed.detect_mode.value, "fast")
        self.assertEqual(parsed.environment.value, "flask")
        self.assertEqual(parsed.replaced_keyword_strategy.value, "ignore")
        self.assertEqual(parsed.detect_waf_keywords.value, "full")
        self.assertTrue(parsed.no_echo.enabled)
        self.assertFalse(parsed.no_echo.outbound_enabled)
        self.assertEqual(parsed.no_echo.callback_url, "http://127.0.0.1:18080/callback")
        self.assertEqual(parsed.no_echo.receiver_api, "http://127.0.0.1:18080/records")
        self.assertEqual(parsed.no_echo.listen_host, "0.0.0.0")
        self.assertEqual(parsed.no_echo.listen_port, 18080)
        self.assertEqual(parsed.no_echo.probe_timeout, 2.5)
        self.assertEqual(parsed.no_echo.poll_interval, 0.3)
        self.assertEqual(parsed.no_echo.chunk_size, 72)
        self.assertEqual(parsed.no_echo.blind_delay, 0.4)
        self.assertEqual(parsed.no_echo.blind_threshold, 0.75)
        self.assertEqual(parsed.no_echo.blind_max_length, 48)
        self.assertEqual(parsed.no_echo.command_timeout, 9.5)
        self.assertEqual(parsed.no_echo.dns_domain, "dnslog.example.com")
        self.assertEqual(parsed.no_echo.dnslog_command, "python poll.py")

    def test_resolve_webui_options_guesses_runtime(self):
        requester = mock.Mock()
        submitter = mock.Mock()
        options = Options(environment=const.TemplateEnvironment.JINJA2)

        with mock.patch(
            "fenjing.webui.guess_python_version",
            return_value=(const.PythonVersion.PYTHON3, 11),
        ) as mocked_guess_python, mock.patch(
            "fenjing.webui.guess_is_flask", return_value=True
        ) as mocked_guess_flask:
            resolved = webui.resolve_webui_options(
                url=VULUNSERVER_URL,
                requester=requester,
                submitter=submitter,
                options=options,
            )

        mocked_guess_python.assert_called_once_with(VULUNSERVER_URL, requester)
        mocked_guess_flask.assert_called_once_with(submitter)
        self.assertEqual(resolved.python_version, const.PythonVersion.PYTHON3)
        self.assertEqual(resolved.python_subversion, 11)
        self.assertEqual(resolved.environment, const.TemplateEnvironment.FLASK)

    def test_callback_submit_keeps_only_latest_submit_message(self):
        flash_messages = []
        messages = []
        callback = webui.CallBackLogger(flash_messages, messages)

        callback.callback_submit(
            {
                "type": "form",
                "form": {"action": "/", "method": "GET", "inputs": {"name"}},
                "inputs": {"name": "first"},
                "response": None,
            }
        )
        callback.callback_submit(
            {
                "type": "form",
                "form": {"action": "/", "method": "GET", "inputs": {"name"}},
                "inputs": {"name": "second"},
                "response": None,
            }
        )

        self.assertEqual(len(flash_messages), 1)
        self.assertIn("second", flash_messages[0])

    def test_callback_generate_payload_is_hidden_in_webui(self):
        flash_messages = []
        messages = []
        callback = webui.CallBackLogger(flash_messages, messages)

        callback.callback_generate_payload(
            {
                "gen_type": "string",
                "args": ("__",),
                "payload": "ud",
            }
        )

        self.assertEqual(flash_messages, [])
        self.assertEqual(messages, [])

    def test_crack_submitter_forces_no_echo_path(self):
        task = webui.BaseCrackTaskThread()
        task.options = Options()
        requester = mock.Mock()
        submitter = mock.Mock()
        resolved_options = Options(
            environment=const.TemplateEnvironment.FLASK,
            python_version=const.PythonVersion.PYTHON3,
        )
        resolved_options.no_echo.enabled = True
        fake_cracker = mock.Mock()
        fake_full_payload_gen = mock.Mock(options=resolved_options)

        with mock.patch(
            "fenjing.webui.resolve_webui_options", return_value=resolved_options
        ), mock.patch(
            "fenjing.webui.Cracker", return_value=fake_cracker
        ), mock.patch(
            "fenjing.webui.build_no_echo_full_payload_gen",
            return_value=fake_full_payload_gen,
        ) as mocked_build_no_echo:
            result = task.crack_submitter(
                url=VULUNSERVER_URL,
                requester=requester,
                submitter=submitter,
            )

        self.assertIs(result, fake_full_payload_gen)
        mocked_build_no_echo.assert_called_once_with(
            submitter,
            resolved_options,
            task.callback,
        )
        fake_cracker.has_respond.assert_not_called()
        fake_cracker.crack.assert_not_called()

    def test_crack_no_echo_http(self):
        self.general_task_test(
            {
                "type": "crack",
                "url": VULUNSERVER_URL + "/noecho",
                "inputs": "name",
                "method": "GET",
                "action": "/noecho",
                "interval": "0.02",
                "no_echo": "on",
                "outbound_enabled": "true",
                "no_echo_listen_host": "127.0.0.1",
                "no_echo_listen_port": "0",
                "no_echo_probe_timeout": "2.0",
            },
            cmd="echo test-webui-noecho-http",
            expected="test-webui-noecho-http",
            max_time=90,
        )
