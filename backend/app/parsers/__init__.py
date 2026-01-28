"""Log parsers for converting raw log data to normalized events."""

from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import ParserRegistry, get_parser

# Import parsers to register them
from app.parsers import json_parser  # noqa: F401
from app.parsers import syslog_parser  # noqa: F401
from app.parsers import adguard_parser  # noqa: F401
from app.parsers import authentik_parser  # noqa: F401
from app.parsers import custom_parser  # noqa: F401
from app.parsers import ollama_parser  # noqa: F401
from app.parsers import endpoint_parser  # noqa: F401
from app.parsers import netflow_parser  # noqa: F401
from app.parsers import sflow_parser  # noqa: F401
from app.parsers import loki_parser  # noqa: F401
from app.parsers import nginx_parser  # noqa: F401

__all__ = ["BaseParser", "ParseResult", "ParserRegistry", "get_parser"]
