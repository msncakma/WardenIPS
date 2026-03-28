"""CLI client layer - Direct and API access modes."""

from .base import BaseClient
from .direct import DirectClient
from .api import APIClient

__all__ = ["BaseClient", "DirectClient", "APIClient", "get_client"]


def get_client(args, config):
    """
    Factory function to return appropriate client (Direct or API).
    
    Args:
        args: Argument namespace from argparse
        config: CLI configuration dict
        
    Returns:
        DirectClient or APIClient instance
    """
    # Explicit --use-api flag forces API mode
    if hasattr(args, "use_api") and args.use_api:
        return APIClient(
            base_url=args.api_url or config.get("api", {}).get("base_url", "http://127.0.0.1:7680"),
            api_key=args.api_key or config.get("api", {}).get("api_key", ""),
            timeout=config.get("api", {}).get("timeout", 10),
        )
    
    # Auto-detect: try direct, fall back to API
    default_mode = config.get("default_mode", "direct")
    if default_mode == "api":
        return APIClient(
            base_url=args.api_url or config.get("api", {}).get("base_url", "http://127.0.0.1:7680"),
            api_key=args.api_key or config.get("api", {}).get("api_key", ""),
            timeout=config.get("api", {}).get("timeout", 10),
        )
    else:
        return DirectClient(
            config_path=args.config,
            verbose=getattr(args, "verbose", False),
        )
