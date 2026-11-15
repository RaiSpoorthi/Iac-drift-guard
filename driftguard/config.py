"""Runtime settings and the 'local emulator only' safety guard."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "moto"}

# Dummy credentials: Moto accepts anything, and real AWS would reject these.
DUMMY_CREDENTIALS = {
    "AWS_ACCESS_KEY_ID": "test",
    "AWS_SECRET_ACCESS_KEY": "test",
}


class UnsafeEndpointError(ValueError):
    """Raised when the endpoint does not look like a local emulator."""


@dataclass(frozen=True)
class Settings:
    endpoint: str = "http://127.0.0.1:5000"
    region: str = "us-east-1"

    def validate(self) -> None:
        host = urlparse(self.endpoint).hostname
        if host not in LOCAL_HOSTS:
            raise UnsafeEndpointError(
                f"Refusing to run against {self.endpoint!r}: DriftGuard only targets a local "
                f"AWS emulator ({', '.join(sorted(LOCAL_HOSTS))})."
            )

    def env(self) -> dict[str, str]:
        """Environment variables for Terraform and boto3."""
        return {
            **DUMMY_CREDENTIALS,
            "AWS_DEFAULT_REGION": self.region,
            "AWS_REGION": self.region,
            "TF_VAR_aws_endpoint": self.endpoint,
            "TF_VAR_aws_region": self.region,
        }
