"""Base64url helpers for ACME and JWS payloads."""

from __future__ import annotations

import base64


def encode(value: bytes) -> str:
    """Encode bytes as unpadded base64url text.

    :param value: Bytes to encode.
    :type value: bytes
    :return: Encoded text.
    :rtype: str
    """

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode(value: str) -> bytes:
    """Decode unpadded base64url text.

    :param value: Encoded text.
    :type value: str
    :return: Decoded bytes.
    :rtype: bytes
    """

    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))
