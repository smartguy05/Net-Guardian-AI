"""Default honeypot template definitions."""

from app.models.honeypot import HoneypotType

# Default honeypot templates
DEFAULT_TEMPLATES = [
    {
        "id": "ssh-cowrie",
        "name": "SSH Honeypot (Cowrie)",
        "honeypot_type": HoneypotType.SSH,
        "description": "Medium-interaction SSH honeypot that logs brute force attacks and shell interaction. "
        "Records commands, downloads, and session data.",
        "container_image": "cowrie/cowrie:latest",
        "container_config": {
            "env": {
                "COWRIE_TELNET_ENABLED": "no",
            },
            "volumes": {},
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [2222],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "ssh-simple",
        "name": "Simple SSH Honeypot",
        "honeypot_type": HoneypotType.SSH,
        "description": "Lightweight SSH honeypot that captures login attempts. "
        "Lower resource usage than Cowrie.",
        "container_image": "linuxserver/openssh-server:latest",
        "container_config": {
            "env": {
                "PUID": "1000",
                "PGID": "1000",
            },
            "memory_limit": "128m",
            "cpu_limit": 0.25,
        },
        "exposed_ports": [2222],
        "default_timeout_minutes": 120,
        "enabled": True,
    },
    {
        "id": "http-admin-fake",
        "name": "Fake Admin Panel",
        "honeypot_type": HoneypotType.HTTP,
        "description": "HTTP honeypot mimicking common admin panels (WordPress, phpMyAdmin). "
        "Captures login attempts and SQL injection attacks.",
        "container_image": "mushorg/snare:latest",
        "container_config": {
            "env": {},
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [8080],
        "default_timeout_minutes": 120,
        "enabled": True,
    },
    {
        "id": "http-webserver",
        "name": "Vulnerable Web Server",
        "honeypot_type": HoneypotType.HTTP,
        "description": "HTTP honeypot that appears as a vulnerable web server. "
        "Logs path traversal, XSS, and other web attacks.",
        "container_image": "owasp/webgoat:latest",
        "container_config": {
            "env": {},
            "memory_limit": "512m",
            "cpu_limit": 1.0,
        },
        "exposed_ports": [8080, 8443],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "ftp-dionaea",
        "name": "FTP Honeypot",
        "honeypot_type": HoneypotType.FTP,
        "description": "FTP honeypot that captures connection attempts and file upload attempts. "
        "Part of the Dionaea malware capture system.",
        "container_image": "dinotools/dionaea:latest",
        "container_config": {
            "env": {
                "DIONAEA_SERVICES": "ftp",
            },
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [21],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "telnet-cowrie",
        "name": "Telnet Honeypot",
        "honeypot_type": HoneypotType.TELNET,
        "description": "Telnet honeypot that captures Mirai-style botnet attacks. "
        "Records commands and download attempts.",
        "container_image": "cowrie/cowrie:latest",
        "container_config": {
            "env": {
                "COWRIE_TELNET_ENABLED": "yes",
                "COWRIE_SSH_ENABLED": "no",
            },
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [2323],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "mysql-dionaea",
        "name": "MySQL Honeypot",
        "honeypot_type": HoneypotType.MYSQL,
        "description": "MySQL honeypot that captures SQL injection and authentication attacks. "
        "Logs queries and connection attempts.",
        "container_image": "dinotools/dionaea:latest",
        "container_config": {
            "env": {
                "DIONAEA_SERVICES": "mysql",
            },
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [3306],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "smb-dionaea",
        "name": "SMB Honeypot",
        "honeypot_type": HoneypotType.SMB,
        "description": "SMB honeypot that captures EternalBlue and other SMB exploits. "
        "Logs connection attempts and malware uploads.",
        "container_image": "dinotools/dionaea:latest",
        "container_config": {
            "env": {
                "DIONAEA_SERVICES": "smb",
            },
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [445],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "redis-honeypot",
        "name": "Redis Honeypot",
        "honeypot_type": HoneypotType.REDIS,
        "description": "Redis honeypot that captures unauthorized access attempts. "
        "Logs commands including crypto mining and config attacks.",
        "container_image": "redis:7-alpine",
        "container_config": {
            "env": {},
            "memory_limit": "128m",
            "cpu_limit": 0.25,
            "command": ["redis-server", "--protected-mode", "no"],
        },
        "exposed_ports": [6379],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
    {
        "id": "rdp-honeypot",
        "name": "RDP Honeypot",
        "honeypot_type": HoneypotType.RDP,
        "description": "RDP honeypot that captures brute force and credential attacks. "
        "Logs connection attempts and authentication data.",
        "container_image": "cytopia/rdp-honeypot:latest",
        "container_config": {
            "env": {},
            "memory_limit": "256m",
            "cpu_limit": 0.5,
        },
        "exposed_ports": [3389],
        "default_timeout_minutes": 60,
        "enabled": True,
    },
]

# Interaction types by honeypot type for parsing
INTERACTION_TYPES = {
    HoneypotType.SSH: [
        "login_attempt",
        "login_success",
        "login_failed",
        "command",
        "download",
        "session_start",
        "session_end",
        "key_fingerprint",
    ],
    HoneypotType.HTTP: [
        "request",
        "login_attempt",
        "sql_injection",
        "xss_attempt",
        "path_traversal",
        "file_upload",
        "scan",
    ],
    HoneypotType.HTTPS: [
        "request",
        "login_attempt",
        "sql_injection",
        "xss_attempt",
        "path_traversal",
        "file_upload",
        "scan",
        "ssl_error",
    ],
    HoneypotType.FTP: [
        "login_attempt",
        "login_success",
        "login_failed",
        "file_upload",
        "file_download",
        "directory_listing",
        "command",
    ],
    HoneypotType.TELNET: [
        "login_attempt",
        "login_success",
        "login_failed",
        "command",
        "download",
        "session_start",
        "session_end",
    ],
    HoneypotType.MYSQL: [
        "connection",
        "login_attempt",
        "login_success",
        "login_failed",
        "query",
        "sql_injection",
    ],
    HoneypotType.POSTGRESQL: [
        "connection",
        "login_attempt",
        "login_success",
        "login_failed",
        "query",
        "sql_injection",
    ],
    HoneypotType.SMB: [
        "connection",
        "share_access",
        "file_access",
        "exploit_attempt",
        "malware_upload",
    ],
    HoneypotType.REDIS: [
        "connection",
        "command",
        "config_get",
        "config_set",
        "slaveof",
        "module_load",
    ],
    HoneypotType.RDP: [
        "connection",
        "login_attempt",
        "login_success",
        "login_failed",
        "session_start",
        "session_end",
    ],
}

# Common attack signatures to look for
ATTACK_SIGNATURES = {
    "ssh_bruteforce": {
        "description": "SSH brute force attack",
        "indicators": ["multiple login attempts", "common passwords", "root login"],
    },
    "mirai_botnet": {
        "description": "Mirai-style IoT botnet activity",
        "indicators": ["busybox", "/bin/sh", "wget", "tftp", "chmod 777"],
    },
    "cryptominer": {
        "description": "Cryptocurrency mining activity",
        "indicators": ["xmrig", "minerd", "stratum+tcp", "pool."],
    },
    "ransomware": {
        "description": "Potential ransomware activity",
        "indicators": ["vssadmin delete", "wmic shadowcopy", "bcdedit /set"],
    },
    "webshell": {
        "description": "Web shell upload attempt",
        "indicators": ["<?php", "eval(", "base64_decode", "system("],
    },
    "sql_injection": {
        "description": "SQL injection attack",
        "indicators": ["UNION SELECT", "OR 1=1", "'; DROP", "SLEEP("],
    },
    "command_injection": {
        "description": "Command injection attack",
        "indicators": ["; cat /etc/passwd", "| nc", "&& wget", "$(curl"],
    },
}


def get_template_by_id(template_id: str) -> dict | None:
    """Get a template by its ID.

    Args:
        template_id: Template identifier.

    Returns:
        Template dict or None if not found.
    """
    for template in DEFAULT_TEMPLATES:
        if template["id"] == template_id:
            return template
    return None


def get_templates_by_type(honeypot_type: HoneypotType) -> list[dict]:
    """Get all templates for a given honeypot type.

    Args:
        honeypot_type: Type of honeypot.

    Returns:
        List of matching templates.
    """
    return [t for t in DEFAULT_TEMPLATES if t["honeypot_type"] == honeypot_type]


def get_enabled_templates() -> list[dict]:
    """Get all enabled templates.

    Returns:
        List of enabled templates.
    """
    return [t for t in DEFAULT_TEMPLATES if t.get("enabled", True)]
