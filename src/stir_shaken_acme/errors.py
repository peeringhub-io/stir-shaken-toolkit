"""Exceptions raised by STIR/SHAKEN ACME helpers."""

from __future__ import annotations


class StirShakenError(RuntimeError):
    """Raised when STIR/SHAKEN ACME processing fails."""


class StipaError(StirShakenError):
    """Raised when STI-PA token processing fails."""


class ShakenValidationError(StirShakenError):
    """Raised when SHAKEN certificate validation fails."""
