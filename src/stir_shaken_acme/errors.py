"""Exceptions raised by STIR/SHAKEN ACME helpers."""

from __future__ import annotations


class StirShakenError(RuntimeError):
    """Raised when STIR/SHAKEN ACME processing fails."""


class StipaError(StirShakenError):
    """Raised when STI-PA token processing fails."""


class StipaRemoteDisconnectedError(StipaError):
    """Raised when STI-PA closes the connection without a response."""

    def __init__(
        self,
        context: str = "STI-PA request",
        url: str | None = None,
    ) -> None:
        """Build an Iconectiv STI-PA whitelist guidance error.

        :param context: STI-PA operation that failed.
        :type context: str
        :param url: Optional URL that disconnected.
        :type url: str | None
        """

        message = (
            f"{context} failed: the remote server closed "
            + "the connection without a response. Iconectiv STI-PA API "
            + "access is restricted by "
            + "source IP address; this usually means your current public IP "
            + "is not whitelisted for the selected STI-PA environment. "
            + "Confirm your current public egress IP, VPN/NAT path, "
            + "and Iconectiv whitelist configuration."
        )
        if url is not None:
            message = f"{message} url={url}"
        super().__init__(message)


class ShakenValidationError(StirShakenError):
    """Raised when SHAKEN certificate validation fails."""
