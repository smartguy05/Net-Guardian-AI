# Security Pattern Feeds

NetGuardian AI supports importing security patterns from external feeds, allowing you to keep your attack detection rules updated with the latest threats.

## Feed Format

Security pattern feeds should return JSON in the following format:

```json
{
  "version": "1.0",
  "name": "My Security Patterns",
  "description": "Custom security patterns for application logs",
  "patterns": [
    {
      "id": "sql-union-001",
      "name": "SQL UNION Attack",
      "description": "Detects UNION-based SQL injection attempts",
      "category": "sql_injection",
      "pattern_type": "regex",
      "pattern": "(?i)union\\s+(all\\s+)?select",
      "severity": "high",
      "tags": ["owasp-top-10", "injection", "database"],
      "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
      "examples": ["' UNION SELECT * FROM users--"]
    },
    {
      "id": "cmd-injection-001",
      "name": "Shell Command Injection",
      "description": "Detects shell metacharacters in input",
      "category": "command_injection",
      "pattern_type": "regex",
      "pattern": "[;&|`$]\\s*(cat|ls|whoami|id)\\b",
      "severity": "critical",
      "tags": ["owasp-top-10", "rce"],
      "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
      "examples": ["; cat /etc/passwd"]
    }
  ]
}
```

## Field Reference

### Pattern Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | No | Unique identifier from the source feed |
| `name` | string | Yes | Human-readable pattern name |
| `description` | string | No | Description of what the pattern detects |
| `category` | string | Yes | Attack category (see below) |
| `pattern_type` | string | Yes | Type of pattern matching (see below) |
| `pattern` | string | Yes | The actual pattern/regex |
| `severity` | string | No | Severity level (default: medium) |
| `tags` | array | No | Tags for categorization |
| `references` | array | No | URLs to documentation |
| `examples` | array | No | Example strings that should match |

### Categories

- `sql_injection` - SQL injection attacks
- `command_injection` - OS command injection
- `path_traversal` - Directory traversal / LFI
- `xss` - Cross-site scripting
- `deserialization` - Insecure deserialization
- `ssrf` - Server-side request forgery
- `auth_bypass` - Authentication bypass
- `log_injection` - Log injection / Log4Shell
- `ldap_injection` - LDAP injection
- `xxe` - XML external entity injection
- `custom` - Custom patterns

### Pattern Types

- `regex` - Regular expression pattern (PCRE compatible)
- `literal` - Exact string match (case-insensitive)
- `keyword` - Comma-separated keywords to match

### Severity Levels

- `info` - Informational
- `low` - Low severity
- `medium` - Medium severity (default)
- `high` - High severity
- `critical` - Critical severity

## Field Mapping

If your feed uses different field names, you can configure field mapping when adding the feed:

```json
{
  "field_mapping": {
    "patterns_path": "rules",
    "id": "rule_id",
    "name": "title",
    "description": "description",
    "category": "attack_type",
    "pattern_type": "match_type",
    "pattern": "regex",
    "severity": "risk_level",
    "tags": "labels",
    "references": "urls",
    "examples": "test_cases"
  }
}
```

### Field Mapping Options

| Mapping Field | Description | Default |
|---------------|-------------|---------|
| `patterns_path` | JSONPath to the patterns array | `patterns` |
| `id` | Field name for pattern ID | `id` |
| `name` | Field name for pattern name | `name` |
| `description` | Field name for description | `description` |
| `category` | Field name for category | `category` |
| `pattern_type` | Field name for pattern type | `pattern_type` |
| `pattern` | Field name for the pattern | `pattern` |
| `severity` | Field name for severity | `severity` |
| `tags` | Field name for tags array | `tags` |
| `references` | Field name for reference URLs | `references` |
| `examples` | Field name for examples | `examples` |

## Authentication

Feeds can be protected with various authentication methods:

### No Authentication

```json
{
  "auth_type": "none"
}
```

### Basic Authentication

```json
{
  "auth_type": "basic",
  "auth_config": {
    "username": "user",
    "password": "secret"
  }
}
```

### Bearer Token

```json
{
  "auth_type": "bearer",
  "auth_config": {
    "token": "your-api-token"
  }
}
```

### API Key

```json
{
  "auth_type": "api_key",
  "auth_config": {
    "header": "X-API-Key",
    "key": "your-api-key"
  }
}
```

## API Endpoints

### List Feeds

```bash
GET /api/v1/security-patterns/feeds
```

### Create Feed

```bash
POST /api/v1/security-patterns/feeds
Content-Type: application/json

{
  "name": "OWASP Security Patterns",
  "description": "Patterns from OWASP",
  "url": "https://example.com/patterns.json",
  "enabled": true,
  "update_interval_hours": 24,
  "auth_type": "none",
  "field_mapping": {}
}
```

### Trigger Manual Fetch

```bash
POST /api/v1/security-patterns/feeds/{feed_id}/fetch
```

### Test a Pattern

```bash
POST /api/v1/security-patterns/test
Content-Type: application/json

{
  "pattern_type": "regex",
  "pattern": "(?i)union\\s+select",
  "test_text": "' UNION SELECT * FROM users--"
}
```

### Match Text Against All Patterns

```bash
POST /api/v1/security-patterns/match
Content-Type: application/json

{
  "text": "User input: ' OR 1=1--",
  "categories": ["sql_injection"]
}
```

## Example: Creating a Custom Feed

1. Create a JSON file with your patterns:

```json
{
  "version": "1.0",
  "name": "Custom App Patterns",
  "patterns": [
    {
      "name": "App-Specific SQL Attack",
      "description": "Detects attacks specific to our application",
      "category": "sql_injection",
      "pattern_type": "regex",
      "pattern": "(?i)select.*from\\s+users\\s+where\\s+deleted\\s*=\\s*false",
      "severity": "high",
      "tags": ["custom", "app-specific"]
    }
  ]
}
```

2. Host it on a web server or use a static file hosting service.

3. Add the feed via the API or GUI:

```bash
curl -X POST http://localhost:8000/api/v1/security-patterns/feeds \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom App Patterns",
    "url": "https://your-server.com/patterns.json",
    "update_interval_hours": 12
  }'
```

4. Trigger an initial fetch:

```bash
curl -X POST http://localhost:8000/api/v1/security-patterns/feeds/{feed_id}/fetch \
  -H "Authorization: Bearer $TOKEN"
```

## Built-in Patterns

NetGuardian AI ships with built-in patterns for common attack types:

- SQL Injection (UNION, OR-based, comments, time-based, stacked queries)
- Command Injection (shell metacharacters, reverse shells)
- Path Traversal (basic, URL-encoded, double-encoded)
- XSS (script tags, event handlers, javascript: URIs)
- Deserialization (Java ysoserial, Python pickle)
- SSRF (internal IPs, cloud metadata)
- Authentication Bypass (JWT none algorithm, default credentials)
- Log Injection (newlines, Log4Shell)
- LDAP Injection
- XXE (DOCTYPE, SYSTEM entities)

Built-in patterns can be disabled but not deleted. They are automatically loaded on first startup.
