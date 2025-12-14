"""
Configuration management for GlobalDetect.

Loads API keys from environment variables or config file.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

# Try to load from .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Check common locations for .env
    env_locations = [
        Path.home() / ".globaldetect" / ".env",
        Path.home() / ".config" / "globaldetect" / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_locations:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass


@dataclass
class APIConfig:
    """API configuration with keys and endpoints."""

    # Cloudflare
    cloudflare_api_token: str = ""
    cloudflare_account_id: str = ""

    # IPInfo.io
    ipinfo_token: str = ""

    # AbuseIPDB
    abuseipdb_api_key: str = ""

    # Shodan
    shodan_api_key: str = ""

    # DNS Science API
    dnsscience_api_key: str = ""
    dnsscience_api_url: str = "https://dnsscience.io/api/v1"

    # PeeringDB (no auth needed for basic queries)
    peeringdb_api_url: str = "https://www.peeringdb.com/api"

    # BGPView (no auth needed)
    bgpview_api_url: str = "https://api.bgpview.io"

    # RIPE Stat (no auth needed)
    ripestat_api_url: str = "https://stat.ripe.net/data"

    @classmethod
    def from_env(cls) -> "APIConfig":
        """Load configuration from environment variables."""
        return cls(
            cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN", ""),
            cloudflare_account_id=os.getenv("CLOUDFLARE_ACCOUNT_ID", ""),
            ipinfo_token=os.getenv("IPINFO_TOKEN", ""),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            dnsscience_api_key=os.getenv("DNSSCIENCE_API_KEY", ""),
            dnsscience_api_url=os.getenv("DNSSCIENCE_API_URL", "https://dnsscience.io/api/v1"),
        )


# Global config instance
_config: APIConfig | None = None


def get_config() -> APIConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = APIConfig.from_env()
    return _config


def set_config(config: APIConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
