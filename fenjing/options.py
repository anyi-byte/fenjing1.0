from typing import Sequence, Union, Optional
from dataclasses import dataclass, field
from .const import (
    DetectMode,
    TemplateEnvironment,
    PythonVersion,
    ReplacedKeywordStrategy,
    AutoFix500Code,
    DetectWafKeywords,
)


@dataclass
class NoEchoOptions:
    """无回显利用相关选项"""

    enabled: bool = False
    outbound_enabled: bool = True
    callback_url: Optional[str] = None
    receiver_api: Optional[str] = None
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    probe_timeout: float = 4.0
    poll_interval: float = 0.2
    chunk_size: int = 96
    blind_delay: float = 1.2
    blind_threshold: float = 0.65
    blind_max_length: int = 256
    command_timeout: float = 15.0
    dns_domain: Optional[str] = None
    dnslog_command: Optional[str] = None
    waf_keyword: Optional[str] = None
    ok_keyword: Optional[str] = None


@dataclass
class Options:
    """影响到攻击逻辑的选项"""

    detect_mode: DetectMode = DetectMode.ACCURATE
    environment: TemplateEnvironment = TemplateEnvironment.FLASK
    replaced_keyword_strategy: ReplacedKeywordStrategy = ReplacedKeywordStrategy.AVOID
    python_version: PythonVersion = PythonVersion.UNKNOWN
    python_subversion: Union[int, None] = None
    autofix_500: AutoFix500Code = AutoFix500Code.ENABLED
    detect_waf_keywords: DetectWafKeywords = DetectWafKeywords.NONE
    waf_keywords: Sequence[str] = tuple()
    no_echo: NoEchoOptions = field(default_factory=NoEchoOptions)
