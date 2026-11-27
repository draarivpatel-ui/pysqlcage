from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .constants import CODE, DEFAULT_MAX_SQL_LENGTH, MAX_AUDIT_FINDINGS, MAX_AUDIT_INPUT_LENGTH
from .errors import fail
from .identifiers import normalize_dialect

_DANGEROUS_SINGLE_KEYWORDS = frozenset((
    "DROP",
    "TRUNCATE",
    "ALTER",
    "GRANT",
    "REVOKE",
    "XP_CMDSHELL",
    "LOAD_FILE",
))
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


@dataclass(frozen=True)
class AuditFinding:
    code: str
    message: str
    index: int
    token: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        if key == "code":
            return self.code
        if key == "message":
            return self.message
        if key == "index":
            return self.index
        if key == "token":
            return self.token
        raise KeyError(key)

    def to_dict(self) -> Dict[str, Any]:
        result = {"code": self.code, "message": self.message, "index": self.index}
        if self.token is not None:
            result["token"] = self.token
        return result


@dataclass(frozen=True)
class AuditStats:
    length: int
    bytes: int
    semicolons: int
    statements: int
    comments: int
    dangerous_keywords: int
    nul_bytes: int
    truncated_findings: int

    def __getitem__(self, key: str) -> int:
        if key in ("length", "bytes", "semicolons", "statements", "comments", "dangerous_keywords", "nul_bytes", "truncated_findings"):
            return getattr(self, key)
        raise KeyError(key)

    def to_dict(self) -> Dict[str, int]:
        return {
            "length": self.length,
            "bytes": self.bytes,
            "semicolons": self.semicolons,
            "statements": self.statements,
            "comments": self.comments,
            "dangerous_keywords": self.dangerous_keywords,
            "nul_bytes": self.nul_bytes,
            "truncated_findings": self.truncated_findings,
        }


@dataclass(frozen=True)
class AuditResult:
    safe: bool
    findings: Tuple[AuditFinding, ...]
    stats: AuditStats

    def __getitem__(self, key: str) -> Any:
        if key == "safe":
            return self.safe
        if key == "findings":
            return self.findings
        if key == "stats":
            return self.stats
        raise KeyError(key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats.to_dict(),
        }


def _is_ascii_whitespace(character: str) -> bool:
    return character in " \t\n\r\f\v"


def _is_mysql_dash_comment_start(character: Optional[str]) -> bool:
    if character is None:
        return True
    return _is_ascii_whitespace(character) or ord(character) < 32 or ord(character) == 127


def _is_word_character(character: str) -> bool:
    return character.isascii() and (character.isalpha() or character.isdigit() or character == "_")


def _dollar_quote_delimiter(query: str, index: int) -> Optional[str]:
    if query[index] != "$":
        return None
    cursor = index + 1
    if cursor < len(query) and query[cursor] == "$":
        return "$$"
    if cursor >= len(query) or not _is_word_character(query[cursor]) or query[cursor].isdigit():
        return None
    while cursor < len(query) and _is_word_character(query[cursor]):
        cursor += 1
    if cursor < len(query) and query[cursor] == "$":
        return query[index:cursor + 1]
    return None


def _utf8_length(text: str) -> int:
    return len(text.encode("utf-8", errors="surrogatepass"))


def audit_sql_query(query: Any, *, dialect: Any = None, max_sql_length: Any = DEFAULT_MAX_SQL_LENGTH) -> AuditResult:
    """Lexically audit SQL for injection-oriented risk markers.

    The auditor is dialect-aware and understands quoted strings, PostgreSQL
    escape and dollar-quoted strings, nested PostgreSQL block comments, and
    MySQL executable comments. It is a defense-in-depth reviewer for SQL text,
    not a substitute for parameter binding.
    """

    if type(query) is not str:
        fail(CODE["INVALID_INPUT"], "audit_sql_query input must be a string")
    selected = normalize_dialect(dialect)
    if type(max_sql_length) is not int or max_sql_length < 1 or max_sql_length > MAX_AUDIT_INPUT_LENGTH:
        fail(CODE["INVALID_OPTIONS"], "max_sql_length must be an integer between 1 and " + str(MAX_AUDIT_INPUT_LENGTH))

    stats = {
        "length": len(query),
        "bytes": _utf8_length(query),
        "semicolons": 0,
        "statements": 0,
        "comments": 0,
        "dangerous_keywords": 0,
        "nul_bytes": 0,
        "truncated_findings": 0,
    }
    findings: List[AuditFinding] = []

    def add_finding(code: str, message: str, index: int, token: Optional[str] = None) -> None:
        if len(findings) >= MAX_AUDIT_FINDINGS:
            stats["truncated_findings"] += 1
            return
        findings.append(AuditFinding(code, message, index, token))

    if len(query) > max_sql_length:
        add_finding(CODE["MAX_SQL_LENGTH"], "SQL length exceeds max_sql_length (" + str(max_sql_length) + ")", max_sql_length)

    nul_indexes = [index for index, character in enumerate(query) if character == "\x00"]
    if nul_indexes:
        stats["nul_bytes"] = len(nul_indexes)
        add_finding(CODE["NUL_BYTE"], "SQL contains a NUL byte", nul_indexes[0])

    index = 0
    state = "normal"
    quote_start = -1
    quote_kind = ""
    quote_backslash_escapes = False
    dollar_delimiter = ""
    block_comment_depth = 0
    block_comment_start = -1
    line_comment_start = -1
    statement_index = 0
    statement_has_content = False
    statement_segment_count = 0
    semicolon_seen = False
    content_after_semicolon_index = -1
    tokens: List[Tuple[str, str, int, int]] = []
    removable_comment_spans: List[Tuple[int, int]] = []

    def has_adjacent_postgres_escape_prefix(position: int) -> bool:
        if not tokens:
            return False
        word, upper, token_index, _statement = tokens[-1]
        return token_index == position - 1 and word in ("E", "e") and upper == "E"

    def mark_statement_content(position: int) -> None:
        nonlocal statement_has_content, content_after_semicolon_index
        if not statement_has_content:
            statement_has_content = True
        if semicolon_seen and content_after_semicolon_index == -1:
            content_after_semicolon_index = position

    def finish_statement_segment() -> None:
        nonlocal statement_has_content, statement_index, statement_segment_count
        if statement_has_content:
            statement_segment_count += 1
        statement_has_content = False
        statement_index += 1

    while index < len(query):
        character = query[index]
        if state in ("single", "double", "backtick"):
            quote = "'" if state == "single" else ('"' if state == "double" else "`")
            if quote_backslash_escapes and character == "\\":
                index += 2
                continue
            if character == quote:
                if index + 1 < len(query) and query[index + 1] == quote:
                    index += 2
                    continue
                state = "normal"
                quote_backslash_escapes = False
                index += 1
                continue
            index += 1
            continue

        if state == "dollar":
            end = query.find(dollar_delimiter, index)
            if end == -1:
                index = len(query)
            else:
                index = end + len(dollar_delimiter)
                state = "normal"
            continue

        if state == "line-comment":
            if character in ("\n", "\r"):
                removable_comment_spans.append((line_comment_start, index))
                state = "normal"
            index += 1
            continue

        if state == "block-comment":
            if character == "/" and index + 1 < len(query) and query[index + 1] == "*":
                if selected == "postgres":
                    block_comment_depth += 1
                index += 2
                continue
            if character == "*" and index + 1 < len(query) and query[index + 1] == "/":
                block_comment_depth -= 1
                index += 2
                if block_comment_depth == 0:
                    removable_comment_spans.append((block_comment_start, index))
                    state = "normal"
                continue
            index += 1
            continue

        if _is_ascii_whitespace(character):
            index += 1
            continue

        if (
            character == "-"
            and index + 1 < len(query)
            and query[index + 1] == "-"
            and (selected != "mysql" or _is_mysql_dash_comment_start(query[index + 2] if index + 2 < len(query) else None))
        ):
            stats["comments"] += 1
            add_finding(CODE["COMMENT_TOKEN"], "SQL comment marker -- appears outside a string literal", index, "--")
            state = "line-comment"
            line_comment_start = index
            index += 2
            continue

        if character == "/" and index + 1 < len(query) and query[index + 1] == "*":
            stats["comments"] += 1
            if selected == "mysql" and index + 2 < len(query) and query[index + 2] == "!":
                add_finding(CODE["COMMENT_TOKEN"], "MySQL executable comment marker /*! appears outside a string literal", index, "/*!")
                index += 3
                continue
            add_finding(CODE["COMMENT_TOKEN"], "SQL block comment marker /* appears outside a string literal", index, "/*")
            state = "block-comment"
            block_comment_depth = 1
            block_comment_start = index
            index += 2
            continue

        if character == "#":
            stats["comments"] += 1
            add_finding(CODE["COMMENT_TOKEN"], "SQL comment marker # appears outside a string literal", index, "#")
            state = "line-comment"
            line_comment_start = index
            index += 1
            continue

        if character == ";":
            stats["semicolons"] += 1
            semicolon_seen = True
            finish_statement_segment()
            index += 1
            continue

        mark_statement_content(index)

        if character in ("'", '"', "`"):
            state = "single" if character == "'" else ("double" if character == '"' else "backtick")
            quote_start = index
            quote_kind = character
            quote_backslash_escapes = selected == "mysql" or (
                selected == "postgres" and character == "'" and has_adjacent_postgres_escape_prefix(index)
            )
            index += 1
            continue

        if selected == "postgres" and character == "$":
            delimiter = _dollar_quote_delimiter(query, index)
            if delimiter is not None:
                state = "dollar"
                dollar_delimiter = delimiter
                quote_start = index
                quote_kind = delimiter
                index += len(delimiter)
                continue

        if _is_word_character(character):
            start = index
            while index < len(query) and _is_word_character(query[index]):
                index += 1
            word = query[start:index]
            tokens.append((word, word.upper(), start, statement_index))
            continue

        index += 1

    if state == "line-comment":
        removable_comment_spans.append((line_comment_start, len(query)))
    if state == "block-comment":
        removable_comment_spans.append((block_comment_start, len(query)))
    if statement_has_content:
        finish_statement_segment()
    stats["statements"] = statement_segment_count

    if state in ("single", "double", "backtick", "dollar"):
        add_finding(CODE["UNBALANCED_QUOTE"], "SQL contains an unterminated quoted string or identifier", quote_start, quote_kind)
    if state == "block-comment":
        add_finding(CODE["UNBALANCED_QUOTE"], "SQL contains an unterminated block comment", block_comment_start, "/*")

    if content_after_semicolon_index != -1:
        add_finding(CODE["MULTI_STATEMENT"], "SQL contains executable content after a statement terminator", content_after_semicolon_index)

    for token_index, token in enumerate(tokens):
        word, upper, token_start, token_statement = token
        if upper in _DANGEROUS_SINGLE_KEYWORDS:
            stats["dangerous_keywords"] += 1
            add_finding(CODE["DANGEROUS_KEYWORD"], "SQL contains dangerous keyword " + upper, token_start, upper)
        next_token = tokens[token_index + 1] if token_index + 1 < len(tokens) else None
        if next_token is not None and next_token[3] == token_statement:
            next_upper = next_token[1]
            if upper == "INTO" and next_upper == "OUTFILE":
                stats["dangerous_keywords"] += 1
                add_finding(CODE["DANGEROUS_KEYWORD"], "SQL contains INTO OUTFILE file export syntax", token_start, "INTO OUTFILE")
            if upper == "ATTACH" and next_upper == "DATABASE":
                stats["dangerous_keywords"] += 1
                add_finding(CODE["DANGEROUS_KEYWORD"], "SQL contains ATTACH DATABASE syntax", token_start, "ATTACH DATABASE")
            if upper == "BULK" and next_upper == "INSERT":
                stats["dangerous_keywords"] += 1
                add_finding(CODE["DANGEROUS_KEYWORD"], "SQL contains BULK INSERT syntax", token_start, "BULK INSERT")
        if upper == "COPY":
            for lookahead in range(token_index + 1, len(tokens)):
                if tokens[lookahead][3] != token_statement:
                    break
                if tokens[lookahead][1] == "PROGRAM":
                    stats["dangerous_keywords"] += 1
                    add_finding(CODE["DANGEROUS_KEYWORD"], "SQL contains COPY ... PROGRAM command execution syntax", token_start, "COPY PROGRAM")
                    break

    removed = [False] * len(query)
    for start, end in removable_comment_spans:
        for position in range(max(0, start), min(len(query), end)):
            removed[position] = True
    compact_characters = []
    compact_map = []
    for position, character in enumerate(query):
        if not removed[position]:
            compact_characters.append(character)
            compact_map.append(position)
    compact = "".join(compact_characters)
    for match in _WORD_RE.finditer(compact):
        upper = match.group(0).upper()
        if upper not in _DANGEROUS_SINGLE_KEYWORDS:
            continue
        original_start = compact_map[match.start()]
        original_end = compact_map[match.end() - 1]
        if any(removed[position] for position in range(original_start, original_end + 1)):
            stats["dangerous_keywords"] += 1
            add_finding(
                CODE["DANGEROUS_KEYWORD"],
                "SQL contains comment-split dangerous keyword " + upper,
                original_start,
                upper,
            )

    frozen_stats = AuditStats(
        length=stats["length"],
        bytes=stats["bytes"],
        semicolons=stats["semicolons"],
        statements=stats["statements"],
        comments=stats["comments"],
        dangerous_keywords=stats["dangerous_keywords"],
        nul_bytes=stats["nul_bytes"],
        truncated_findings=stats["truncated_findings"],
    )
    return AuditResult(len(findings) == 0, tuple(findings), frozen_stats)
