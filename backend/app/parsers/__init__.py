"""Log parsers for converting raw log data to normalized events."""

# Import parsers to register them
from app.parsers import (
    adguard_parser,  # noqa: F401
    authentik_parser,  # noqa: F401
    custom_parser,  # noqa: F401
    endpoint_parser,  # noqa: F401
    json_parser,  # noqa: F401
    loki_parser,  # noqa: F401
    netflow_parser,  # noqa: F401
    nginx_parser,  # noqa: F401
    ollama_parser,  # noqa: F401
    sflow_parser,  # noqa: F401
    syslog_parser,  # noqa: F401
)
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import ParserRegistry, get_parser

__all__ = ["BaseParser", "ParseResult", "ParserRegistry", "get_parser"]
