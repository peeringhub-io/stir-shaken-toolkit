"""Configuration and environment resolution for the toolkit CLI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from stir_shaken_acme.errors import StirShakenError


class CliValueResolver:
    """Resolve CLI values from args, YAML config, environment, and defaults."""

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path
        self.config = self.load_config(config_path)

    def value(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        default: object = None,
    ) -> object:
        """Resolve one value.

        :param cli_value: Parsed command-line value.
        :type cli_value: object
        :param config_key: YAML config key.
        :type config_key: str
        :param env_name: Environment variable name.
        :type env_name: str
        :param default: Built-in default value.
        :type default: object
        :return: Resolved value.
        :rtype: object
        """

        if not self.is_blank(cli_value):
            return cli_value
        if config_key in self.config and not self.is_blank(self.config[config_key]):
            return self.config[config_key]
        if env_name in os.environ and os.environ[env_name] != "":
            return os.environ[env_name]
        return default

    def string(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        default: str | None = None,
    ) -> str | None:
        """Resolve one optional string value."""

        value = self.value(cli_value, config_key, env_name, default)
        if value is None:
            return None
        return str(value)

    def required_string(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        display_name: str,
        default: str | None = None,
    ) -> str:
        """Resolve one required string value."""

        value = self.string(cli_value, config_key, env_name, default)
        if value is None or not value.strip():
            raise StirShakenError(f"Missing required value: {display_name}")
        return value.strip()

    def integer(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        default: int,
    ) -> int:
        """Resolve one integer value."""

        value = self.value(cli_value, config_key, env_name, default)
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise StirShakenError(f"Invalid integer for {config_key}: {value}") from exc

    def path(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        default: str | None = None,
    ) -> Path | None:
        """Resolve one optional path value."""

        value = self.string(cli_value, config_key, env_name, default)
        if value is None or not value.strip():
            return None
        return Path(value)

    def required_path(
        self,
        cli_value: object,
        config_key: str,
        env_name: str,
        display_name: str,
        default: str | None = None,
    ) -> Path:
        """Resolve one required path value."""

        path = self.path(cli_value, config_key, env_name, default)
        if path is None:
            raise StirShakenError(f"Missing required value: {display_name}")
        return path

    def mapped_url(
        self,
        config_key: str,
        environment: str,
        fallback: str | None = None,
    ) -> str | None:
        """Resolve an environment-keyed URL from YAML config."""

        value = self.config.get(config_key)
        if isinstance(value, dict) and environment in value:
            url = value[environment]
            return None if self.is_blank(url) else str(url)
        return fallback

    def load_config(self, config_path: Path | None) -> dict[str, Any]:
        """Load an optional YAML config file."""

        if config_path is None:
            return {}
        try:
            data = yaml.safe_load(config_path.read_text()) or {}
        except OSError as exc:
            raise StirShakenError(f"Failed to read config: {config_path}") from exc
        except yaml.YAMLError as exc:
            raise StirShakenError(
                f"Failed to parse YAML config: {config_path}"
            ) from exc
        if not isinstance(data, dict):
            raise StirShakenError("Config file root must be a mapping")
        return data

    def is_blank(self, value: object) -> bool:
        """Return whether a value should be treated as unset."""

        return value is None or value == ""
