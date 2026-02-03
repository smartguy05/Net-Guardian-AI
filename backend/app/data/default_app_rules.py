"""Default built-in detection rules for application log analysis.

These rules are loaded into the database on first startup if they don't exist.
Users can disable them but cannot delete them.
"""

from typing import Any

from app.models.alert import AlertSeverity

# Default application detection rules
DEFAULT_APP_RULES: list[dict[str, Any]] = [
    # ============================================
    # Security Pattern Rules
    # ============================================
    {
        "id": "security_pattern_sql_injection",
        "name": "SQL Injection Attack Detected",
        "description": "Triggers when SQL injection patterns are detected in application logs. "
        "This indicates an active attack attempting to manipulate database queries.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "security_pattern"},
                {"field": "details.category", "operator": "eq", "value": "sql_injection"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
        ],
        "cooldown_minutes": 5,
    },
    {
        "id": "security_pattern_command_injection",
        "name": "Command Injection Attack Detected",
        "description": "Triggers when command injection patterns are detected in application logs. "
        "This indicates an attempt to execute arbitrary system commands.",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "security_pattern"},
                {"field": "details.category", "operator": "eq", "value": "command_injection"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True, "priority": "critical"}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
        ],
        "cooldown_minutes": 1,
    },
    {
        "id": "security_pattern_path_traversal",
        "name": "Path Traversal Attack Detected",
        "description": "Triggers when path traversal patterns (../) are detected in application logs. "
        "This indicates an attempt to access files outside the intended directory.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "security_pattern"},
                {"field": "details.category", "operator": "eq", "value": "path_traversal"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["ntfy"]}},
        ],
        "cooldown_minutes": 5,
    },
    {
        "id": "security_pattern_xss",
        "name": "XSS Attack Detected",
        "description": "Triggers when cross-site scripting (XSS) patterns are detected in application logs. "
        "This indicates an attempt to inject malicious scripts.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "security_pattern"},
                {"field": "details.category", "operator": "eq", "value": "xss"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
        ],
        "cooldown_minutes": 5,
    },
    {
        "id": "security_pattern_deserialization",
        "name": "Deserialization Attack Detected",
        "description": "Triggers when Java deserialization gadget classes are detected in logs. "
        "This indicates a potential remote code execution attempt via unsafe deserialization.",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "security_pattern"},
                {"field": "details.category", "operator": "eq", "value": "deserialization"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True, "priority": "critical"}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
        ],
        "cooldown_minutes": 1,
    },
    # ============================================
    # Container Rules
    # ============================================
    {
        "id": "container_restart_loop",
        "name": "Container Restart Loop Detected",
        "description": "Triggers when a container restarts 3 or more times within 30 minutes. "
        "This indicates a crash loop or configuration issue.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "container_restart"},
                {"field": "score", "operator": "gte", "value": 3.0},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "tag_device", "config": {"tag": "unstable-container"}},
        ],
        "cooldown_minutes": 30,
    },
    {
        "id": "container_oom_killed",
        "name": "Container OOM Killed",
        "description": "Triggers when a container is killed due to out-of-memory conditions. "
        "Consider increasing memory limits or investigating memory leaks.",
        "severity": AlertSeverity.MEDIUM,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "container"},
                {"field": "parsed_fields.oom_killed", "operator": "eq", "value": True},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
        ],
        "cooldown_minutes": 15,
    },
    {
        "id": "container_exit_error",
        "name": "Container Exited with Error",
        "description": "Triggers when a container exits with a non-zero exit code. "
        "This indicates the application encountered a fatal error.",
        "severity": AlertSeverity.MEDIUM,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "container"},
                {"field": "parsed_fields.exit_code", "operator": "gt", "value": 0},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": False}},
        ],
        "cooldown_minutes": 15,
    },
    # ============================================
    # Error Rate Rules
    # ============================================
    {
        "id": "error_rate_spike",
        "name": "Error Rate Spike Detected",
        "description": "Triggers when the application error rate exceeds 10% of log volume "
        "in a 5-minute window. This indicates a significant application issue.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "error_spike"},
                {"field": "score", "operator": "gte", "value": 2.5},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["ntfy"]}},
        ],
        "cooldown_minutes": 10,
    },
    {
        "id": "critical_error_rate_spike",
        "name": "Critical Error Rate Spike",
        "description": "Triggers when the critical/error log rate exceeds 25% of log volume. "
        "This indicates a severe application problem requiring immediate attention.",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "error_spike"},
                {"field": "score", "operator": "gte", "value": 4.0},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True, "priority": "critical"}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
        ],
        "cooldown_minutes": 5,
    },
    # ============================================
    # New Error Pattern Rules
    # ============================================
    {
        "id": "new_error_pattern",
        "name": "New Error Pattern Detected",
        "description": "Triggers when a previously unseen exception or error type appears "
        "in application logs. This may indicate a new bug or regression.",
        "severity": AlertSeverity.MEDIUM,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "new_error_pattern"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": False}},
        ],
        "cooldown_minutes": 60,
    },
    {
        "id": "new_security_exception",
        "name": "New Security Exception Detected",
        "description": "Triggers when a new security-related exception appears, such as "
        "authentication failures, authorization errors, or cryptographic exceptions.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "anomaly_type", "operator": "eq", "value": "new_error_pattern"},
                {
                    "field": "details.exception_type",
                    "operator": "regex",
                    "value": "(?i)(security|auth|permission|access|credential|crypto)",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["ntfy"]}},
        ],
        "cooldown_minutes": 15,
    },
    # ============================================
    # Service Health Rules
    # ============================================
    {
        "id": "service_failure",
        "name": "Systemd Service Failure",
        "description": "Triggers when a monitored systemd service enters failed state. "
        "This indicates the service has stopped unexpectedly.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "journal"},
                {"field": "parsed_fields.service_state", "operator": "eq", "value": "failed"},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["ntfy"]}},
        ],
        "cooldown_minutes": 15,
    },
    {
        "id": "service_repeated_restart",
        "name": "Service Repeated Restarts",
        "description": "Triggers when a systemd service restarts multiple times. "
        "This indicates instability requiring investigation.",
        "severity": AlertSeverity.MEDIUM,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "journal"},
                {
                    "field": "parsed_fields.service_state",
                    "operator": "in",
                    "value": ["starting", "reloading"],
                },
                {"field": "parsed_fields.restart_count", "operator": "gte", "value": 3},
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
        ],
        "cooldown_minutes": 30,
    },
    # ============================================
    # Java-specific Rules
    # ============================================
    {
        "id": "java_oom_error",
        "name": "Java OutOfMemoryError",
        "description": "Triggers when a Java OutOfMemoryError is detected. "
        "The JVM has exhausted heap space and requires attention.",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "application"},
                {
                    "field": "parsed_fields.exception_type",
                    "operator": "contains",
                    "value": "OutOfMemoryError",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True, "priority": "critical"}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
        ],
        "cooldown_minutes": 5,
    },
    {
        "id": "java_stack_overflow",
        "name": "Java StackOverflowError",
        "description": "Triggers when a Java StackOverflowError is detected. "
        "This typically indicates infinite recursion or very deep call stacks.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "application"},
                {
                    "field": "parsed_fields.exception_type",
                    "operator": "contains",
                    "value": "StackOverflowError",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
        ],
        "cooldown_minutes": 15,
    },
    {
        "id": "java_deserialization_attack",
        "name": "Java Deserialization Attack",
        "description": "Triggers when known ysoserial gadget classes appear in Java stack traces. "
        "This is a strong indicator of a remote code execution attack.",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "application"},
                {"field": "parsed_fields.is_security_exception", "operator": "eq", "value": True},
                {
                    "field": "raw_message",
                    "operator": "regex",
                    "value": "(?i)(ysoserial|CommonsCollections|Jdk7u21|MozillaRhino)",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True, "priority": "critical"}},
            {"type": "send_notification", "config": {"channels": ["email", "ntfy"]}},
            {
                "type": "quarantine_device",
                "config": {"reason": "Java deserialization attack detected"},
            },
        ],
        "cooldown_minutes": 1,
    },
    # ============================================
    # Python-specific Rules
    # ============================================
    {
        "id": "python_memory_error",
        "name": "Python MemoryError",
        "description": "Triggers when a Python MemoryError is detected. "
        "The process has exhausted available memory.",
        "severity": AlertSeverity.HIGH,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "application"},
                {
                    "field": "parsed_fields.exception_type",
                    "operator": "eq",
                    "value": "MemoryError",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": True}},
            {"type": "send_notification", "config": {"channels": ["ntfy"]}},
        ],
        "cooldown_minutes": 15,
    },
    {
        "id": "python_recursion_error",
        "name": "Python RecursionError",
        "description": "Triggers when a Python RecursionError is detected. "
        "This indicates infinite recursion exceeding the recursion limit.",
        "severity": AlertSeverity.MEDIUM,
        "conditions": {
            "logic": "and",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "application"},
                {
                    "field": "parsed_fields.exception_type",
                    "operator": "eq",
                    "value": "RecursionError",
                },
            ],
        },
        "response_actions": [
            {"type": "create_alert", "config": {"notify": False}},
        ],
        "cooldown_minutes": 30,
    },
]


async def load_default_app_rules(session) -> int:
    """Load default application rules into the database.

    Only loads rules that don't already exist (by ID).
    Built-in rules have their ID as the identifier and cannot be deleted.

    Args:
        session: AsyncSession database session.

    Returns:
        Number of rules loaded.
    """
    from sqlalchemy import select

    from app.models.detection_rule import DetectionRule

    loaded_count = 0

    for rule_data in DEFAULT_APP_RULES:
        # Check if rule already exists
        result = await session.execute(
            select(DetectionRule).where(DetectionRule.id == rule_data["id"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            continue

        # Create new rule
        rule = DetectionRule(
            id=rule_data["id"],
            name=rule_data["name"],
            description=rule_data.get("description"),
            severity=rule_data["severity"],
            enabled=True,
            conditions=rule_data["conditions"],
            response_actions=rule_data.get("response_actions", []),
            cooldown_minutes=rule_data.get("cooldown_minutes", 60),
        )
        session.add(rule)
        loaded_count += 1

    if loaded_count > 0:
        await session.commit()

    return loaded_count
