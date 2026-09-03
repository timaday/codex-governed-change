"""Shared fail-closed recognizers for machine-shaped retained stream values."""

from __future__ import annotations

import re


_VALUE_TAIL = rb"[^\s\"'<>|,;)}\]]+"
_OPTIONAL_VALUE_TAIL = rb"[^\s\"'<>|,;)}\]]*"
_SCHEME_QUALIFIED_AUTHORITY_GUARDS = (
    rb"(?<!(?i:\bhttp:))"
    rb"(?<!(?i:\bhttps:))"
    rb"(?<!(?i:\bws:))"
    rb"(?<!(?i:\bwss:))"
    rb"(?<!(?i:\bssh:))"
    rb"(?<!(?i:\btcp:))"
    rb"(?<!(?i:\btls:))"
    rb"(?<!(?i:\bpostgres:))"
    rb"(?<!(?i:\bpostgresql:))"
    rb"(?<!(?i:\bmysql:))"
    rb"(?<!(?i:\bredis:))"
    rb"(?<!(?i:\bamqp:))"
)

SHAPED_VALUE_PATTERNS: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (
        re.compile(
            rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
            rb"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "credential",
    ),
    (
        re.compile(
            rb"(?i)\b(?:api[_-]?key|token|secret|password|passwd|authorization)"
            rb"\b[\"']?\s*[:=]\s*[^\r\n,;)}\]]+"
        ),
        "credential",
    ),
    (re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "credential"),
    (re.compile(rb"\bsk-[A-Za-z0-9_-]{16,}\b"), "credential"),
    (re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "credential"),
    (
        re.compile(
            rb"(?<![A-Za-z0-9._~/-])(?:/(?!/)|"
            + _SCHEME_QUALIFIED_AUTHORITY_GUARDS
            + rb"//+)"
            + _VALUE_TAIL
        ),
        "generic_host_path",
    ),
    (
        re.compile(
            rb"[A-Za-z]:\\(?:Users|Documents and Settings|ProgramData|Windows|Temp)\\"
            + _VALUE_TAIL
        ),
        "generic_host_path",
    ),
    (
        re.compile(
            rb"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+(?:\\"
            + _OPTIONAL_VALUE_TAIL
            + rb")?"
        ),
        "generic_host_path",
    ),
    (
        re.compile(
            rb"(?i)(?<![0-9a-f:])"
            rb"(?=(?:(?:[0-9a-f]{0,4}:){7}|[0-9a-f:]*::))"
            rb"(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}"
            rb"(?:%[A-Za-z0-9_.-]+)?"
            rb"(?![0-9a-f:])"
        ),
        "endpoint",
    ),
    (
        re.compile(
            rb"(?i)\b(?:https?|wss?|ssh|tcp|tls|postgres(?:ql)?|mysql|redis|amqp)://"
            rb"(?:[^\s/@]+@)?(?:\[[0-9a-f:]+\]|[A-Za-z0-9]"
            rb"[A-Za-z0-9.-]{0,252})(?::[0-9]{1,5})?"
            rb"(?:/" + _OPTIONAL_VALUE_TAIL + rb")?"
        ),
        "endpoint",
    ),
    (
        re.compile(
            rb"(?i)\b(?:local" rb"host|127(?:\.[0-9]{1,3}){3}|"
            rb"10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|"
            rb"172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}|\[?::1\]?)"
            rb"(?::[0-9]{1,5})?\b"
        ),
        "endpoint",
    ),
    (
        re.compile(
            rb"(?i)\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            rb"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            rb":[0-9]{1,5}\b"
        ),
        "endpoint",
    ),
    (
        re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b"),
        "endpoint",
    ),
)


def stream_contains_shaped_value(data: bytes) -> bool:
    """Return whether bytes contain a recognized credential or host value."""
    return any(pattern.search(data) for pattern, _ in SHAPED_VALUE_PATTERNS)
