"""Exceptions raised by ACME client operations."""

from __future__ import annotations


class AcmeClientError(RuntimeError):
    """Raised when ACME processing fails."""


class AcmeProtocolError(AcmeClientError):
    """Raised when an ACME response violates expected protocol shape."""


class AcmeBadNonceError(AcmeClientError):
    """Raised when an ACME server rejects a nonce."""
