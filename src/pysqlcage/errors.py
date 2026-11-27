from __future__ import annotations

from typing import Any, Optional


class SqlCageError(ValueError):
    """Structured failure raised for every pysqlcage validation error."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.name = "SqlCageError"
        self.code = code
        if details is not None:
            self.details = details

    def __repr__(self) -> str:
        return "SqlCageError(code={!r}, message={!r})".format(self.code, str(self))


def fail(code: str, message: str, details: Optional[Any] = None) -> None:
    raise SqlCageError(code, message, details)
