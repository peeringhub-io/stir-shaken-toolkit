"""TNAuthList DER and text encoding helpers."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Literal

from .errors import ShakenValidationError

SPC_PATTERN = re.compile(r"^[A-Z0-9]{4}$")
TnAuthEncoding = Literal["base64", "base64url"]


@dataclass(frozen=True)
class TnAuthList:
    """TNAuthList value for one configured SPC."""

    spc: str

    def validate(self) -> None:
        """Validate SPC shape before ASN.1 encoding."""

        try:
            spc_bytes = self.spc.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ShakenValidationError("SPC must be ASCII") from exc
        if self.spc != self.spc.upper():
            raise ShakenValidationError("SPC must be uppercase")
        if not SPC_PATTERN.match(self.spc):
            raise ShakenValidationError(
                "SPC must match four uppercase alphanumeric characters"
            )
        if len(spc_bytes) > 127:
            raise ShakenValidationError(
                "SPC is too long for the short-form DER encoder"
            )

    def der(self) -> bytes:
        """Return TNAuthList DER bytes."""

        self.validate()
        spc_bytes = self.spc.encode("ascii")
        return (
            bytes(
                [
                    0x30,
                    len(spc_bytes) + 4,
                    0xA0,
                    len(spc_bytes) + 2,
                    0x16,
                    len(spc_bytes),
                ]
            )
            + spc_bytes
        )

    def base64(self) -> str:
        """Return padded standard base64 DER text."""

        return base64.b64encode(self.der()).decode("ascii")

    def base64url(self) -> str:
        """Return unpadded base64url DER text."""

        return base64.urlsafe_b64encode(self.der()).decode("ascii").rstrip("=")

    def encoded(self, encoding: str) -> str:
        """Return the requested text encoding."""

        if encoding == "base64":
            return self.base64()
        if encoding == "base64url":
            return self.base64url()
        raise ShakenValidationError(f"Unsupported TNAuthList encoding: {encoding}")
