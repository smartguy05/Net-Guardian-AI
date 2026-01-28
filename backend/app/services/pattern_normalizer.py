"""Pattern normalizer for converting log messages into normalized templates."""

import hashlib
import re


class PatternNormalizer:
    """Normalizes log messages by replacing dynamic values with placeholders.

    This allows us to identify similar log messages that differ only in specific
    values like IP addresses, timestamps, or UUIDs.
    """

    # Regex patterns for normalization (order matters - more specific first)
    _patterns = [
        # UUIDs (with or without hyphens)
        (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "<UUID>",
        ),
        (r"[0-9a-fA-F]{32}", "<UUID>"),
        # ISO 8601 timestamps
        (
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
            "<TIMESTAMP>",
        ),
        # Common timestamp formats
        (
            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?",
            "<TIMESTAMP>",
        ),
        (
            r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",
            "<TIMESTAMP>",
        ),
        # Syslog timestamps
        (
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
            "<TIMESTAMP>",
        ),
        # Unix timestamps (10 or 13 digits)
        (r"\b\d{13}\b", "<TIMESTAMP_MS>"),
        (r"\b\d{10}\b", "<TIMESTAMP_SEC>"),
        # Email addresses (before URLs to avoid partial matching)
        (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "<EMAIL>",
        ),
        # URLs with protocol
        (
            r"https?://[^\s\"'<>]+",
            "<URL>",
        ),
        # IPv6 addresses
        (
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
            "<IPV6>",
        ),
        (
            r"(?:[0-9a-fA-F]{1,4}:){1,7}:",
            "<IPV6>",
        ),
        (
            r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}",
            "<IPV6>",
        ),
        # IPv4 addresses
        (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "<IP>",
        ),
        # MAC addresses
        (
            r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
            "<MAC>",
        ),
        (
            r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}",
            "<MAC>",
        ),
        # File paths (Unix and Windows)
        (
            r"(?:/[a-zA-Z0-9._-]+)+(?:/)?",
            "<PATH>",
        ),
        (
            r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
            "<PATH>",
        ),
        # Hex strings (8+ characters, standalone)
        (
            r"\b[0-9a-fA-F]{8,}\b",
            "<HEX>",
        ),
        # Port numbers (standalone, 1-65535)
        (
            r"(?<=:)\d{1,5}\b",
            "<PORT>",
        ),
        # Duration/time values
        (
            r"\b\d+(?:\.\d+)?(?:ms|s|sec|min|h|hr|d)\b",
            "<DURATION>",
        ),
        # Byte sizes
        (
            r"\b\d+(?:\.\d+)?(?:B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)\b",
            "<SIZE>",
        ),
        # Percentage values
        (
            r"\b\d+(?:\.\d+)?%\b",
            "<PERCENT>",
        ),
        # Floating point numbers (before integers)
        (
            r"\b\d+\.\d+\b",
            "<FLOAT>",
        ),
        # Integer numbers (standalone, not part of words)
        (
            r"(?<![a-zA-Z0-9_])\d+(?![a-zA-Z0-9_])",
            "<NUM>",
        ),
    ]

    # Compiled patterns for efficiency
    _compiled_patterns = [(re.compile(p), r) for p, r in _patterns]

    @classmethod
    def normalize(cls, message: str) -> tuple[str, str]:
        """Normalize a log message by replacing dynamic values with placeholders.

        Args:
            message: The raw log message to normalize.

        Returns:
            A tuple of (normalized_pattern, pattern_hash).
            - normalized_pattern: The message with dynamic values replaced.
            - pattern_hash: SHA-256 hash of the normalized pattern.
        """
        normalized = message

        # Apply each pattern replacement
        for pattern, replacement in cls._compiled_patterns:
            normalized = pattern.sub(replacement, normalized)

        # Collapse multiple consecutive placeholders of the same type
        # e.g., "<NUM> <NUM> <NUM>" -> "<NUM>..."
        for placeholder in [
            "<NUM>",
            "<IP>",
            "<HEX>",
            "<UUID>",
            "<TIMESTAMP>",
            "<FLOAT>",
        ]:
            repeated = f"({re.escape(placeholder)}\\s*){{2,}}"
            normalized = re.sub(repeated, f"{placeholder}... ", normalized)

        # Clean up whitespace
        normalized = re.sub(r"\s+", " ", normalized).strip()

        # Generate hash
        pattern_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        return normalized, pattern_hash

    @classmethod
    def extract_variables(cls, message: str) -> dict:
        """Extract the dynamic values from a log message.

        This is useful for debugging and analysis to see what values
        were replaced with placeholders.

        Args:
            message: The raw log message.

        Returns:
            A dictionary mapping placeholder types to lists of extracted values.
        """
        variables = {}

        for pattern, replacement in cls._compiled_patterns:
            placeholder_name = replacement.strip("<>")
            matches = pattern.findall(message)
            if matches:
                if placeholder_name not in variables:
                    variables[placeholder_name] = []
                variables[placeholder_name].extend(matches)

        return variables

    @classmethod
    def is_similar(cls, message1: str, message2: str) -> bool:
        """Check if two messages normalize to the same pattern.

        Args:
            message1: First message.
            message2: Second message.

        Returns:
            True if both messages normalize to the same pattern.
        """
        _, hash1 = cls.normalize(message1)
        _, hash2 = cls.normalize(message2)
        return hash1 == hash2
