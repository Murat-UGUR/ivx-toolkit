"""Connection settings, read from environment variables (never from command-line passwords)."""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    host: str
    username: str
    password: str
    api_version: str = "v2.0.0"
    verify_tls: bool | str = True
    client_token: str | None = None
    port: int = 443
    scheme: str = "https"  # http only for the local mock server

    @classmethod
    def from_env(cls, host: str | None = None, prompt_password: bool = True) -> Settings:
        """Build settings from IVX_* environment variables.

        IVX_HOST, IVX_USER, IVX_PASSWORD, IVX_API_VERSION, IVX_PORT,
        IVX_VERIFY_TLS (true/false), IVX_CA_BUNDLE (path), IVX_CLIENT_TOKEN,
        IVX_SCHEME (https by default; http is meant only for the bundled mock server).
        If IVX_PASSWORD is unset, the password is prompted interactively.
        """
        host = host or os.environ.get("IVX_HOST")
        if not host:
            raise ValueError(
                "IVX host is not set. Use --host or the IVX_HOST environment variable."
            )
        username = os.environ.get("IVX_USER")
        if not username:
            raise ValueError("IVX_USER environment variable is not set.")
        password = os.environ.get("IVX_PASSWORD")
        if not password:
            if not prompt_password:
                raise ValueError("IVX_PASSWORD environment variable is not set.")
            password = getpass.getpass(f"IVX password for {username}@{host}: ")

        verify: bool | str = _env_bool("IVX_VERIFY_TLS", True)
        ca_bundle = os.environ.get("IVX_CA_BUNDLE")
        if ca_bundle:
            verify = ca_bundle

        return cls(
            host=host,
            username=username,
            password=password,
            api_version=os.environ.get("IVX_API_VERSION", "v2.0.0"),
            verify_tls=verify,
            client_token=os.environ.get("IVX_CLIENT_TOKEN") or None,
            port=int(os.environ.get("IVX_PORT", "443")),
            scheme=os.environ.get("IVX_SCHEME", "https"),
        )
