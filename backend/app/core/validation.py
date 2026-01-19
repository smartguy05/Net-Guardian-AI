"""Input validation and sanitization utilities.

This module provides security-focused validation for user inputs,
passwords, and other potentially dangerous data.
"""

import re
import ipaddress
from typing import List, Optional, Tuple

import structlog

logger = structlog.get_logger()


# Password requirements
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Patterns for validation
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
)

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")

# Common weak passwords to reject
COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "password1",
    "password123", "123456789", "12345678", "1234567890",
}


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """Validate password meets security requirements.

    Args:
        password: The password to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit")

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character")

    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common")

    # Check for sequential characters
    if re.search(r"(.)\1{2,}", password):
        errors.append("Password cannot contain 3+ consecutive identical characters")

    return len(errors) == 0, errors


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """Validate username format.

    Args:
        username: The username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"

    if not USERNAME_PATTERN.match(username):
        return False, "Username must be 3-32 characters, alphanumeric, underscores, or hyphens"

    # Check for common reserved names
    reserved = {"admin", "root", "system", "api", "null", "undefined"}
    if username.lower() in reserved:
        return False, "Username is reserved"

    return True, None


def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate an IP address.

    Args:
        ip: The IP address string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address is required"

    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError:
        return False, "Invalid IP address format"


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """Validate a domain name.

    Args:
        domain: The domain name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not domain:
        return False, "Domain is required"

    if len(domain) > 253:
        return False, "Domain name too long"

    if not DOMAIN_PATTERN.match(domain):
        return False, "Invalid domain format"

    return True, None


def validate_mac_address(mac: str) -> Tuple[bool, Optional[str]]:
    """Validate a MAC address.

    Args:
        mac: The MAC address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not mac:
        return False, "MAC address is required"

    # Normalize and validate
    mac = mac.upper().replace("-", ":").replace(".", ":")

    # Check format (XX:XX:XX:XX:XX:XX)
    if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
        return False, "Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)"

    return True, None


def sanitize_string(value: str, max_length: int = 255) -> str:
    """Sanitize a string input.

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not value:
        return ""

    # Strip whitespace
    value = value.strip()

    # Remove null bytes
    value = value.replace("\x00", "")

    # Truncate to max length
    if len(value) > max_length:
        value = value[:max_length]

    return value


def sanitize_log_message(message: str, max_length: int = 10000) -> str:
    """Sanitize a log message to prevent log injection.

    Args:
        message: The log message to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized log message
    """
    if not message:
        return ""

    # Strip whitespace
    message = message.strip()

    # Remove/escape newlines to prevent log injection
    message = message.replace("\n", "\\n").replace("\r", "\\r")

    # Remove null bytes
    message = message.replace("\x00", "")

    # Truncate
    if len(message) > max_length:
        message = message[:max_length] + "...[truncated]"

    return message
