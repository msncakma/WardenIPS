"""WardenIPS CLI - Professional command-line interface for operational control.

Usage:
    wardenips-cli --help
    wardenips-cli ban add 203.0.113.50 --reason "SSH brute-force"
    wardenips-cli config reload --components whitelist,firewall
    wardenips-cli database stats
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Any

from wardenips import __version__, __author__
from wardenips.cli.client import get_client
from wardenips.cli.client.exceptions import CLIError

# Import command handlers and registrations
from wardenips.cli.commands.ban import register_ban_commands, handle_ban_command
from wardenips.cli.commands.whitelist import register_whitelist_commands, handle_whitelist_command
from wardenips.cli.commands.config import register_config_commands, handle_config_command
from wardenips.cli.commands.firewall import register_firewall_commands, handle_firewall_command
from wardenips.cli.commands.database import register_database_commands, handle_database_command


def load_cli_config() -> Dict[str, Any]:
    """Load CLI configuration from ~/.wardenips/config.json."""
    config_dir = Path.home() / ".wardenips"
    config_file = config_dir / "config.json"
    
    default_config = {
        "api": {
            "base_url": "http://127.0.0.1:7680",
            "api_key": "",
            "timeout": 10,
        },
        "default_mode": "direct",  # "direct" or "api"
    }
    
    if config_file.exists():
        try:
            with open(config_file) as f:
                loaded = json.load(f)
                # Deep merge with defaults
                default_config["api"].update(loaded.get("api", {}))
                if "default_mode" in loaded:
                    default_config["default_mode"] = loaded["default_mode"]
                return default_config
        except Exception as e:
            print(f"Warning: Failed to load CLI config from {config_file}: {e}", file=sys.stderr)
    
    return default_config


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all supported commands."""
    parser = argparse.ArgumentParser(
        prog="wardenips-cli",
        description="WardenIPS - Professional command-line tool for IPS management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wardenips-cli ban add 203.0.113.50 --reason "SSH brute-force"
  wardenips-cli ban list --output json
  wardenips-cli whitelist add 192.168.0.0/16 --reason "Internal network"
  wardenips-cli firewall status
  wardenips-cli config reload --components whitelist,firewall
  wardenips-cli plugins list
  wardenips-cli database stats
  wardenips-cli status
  
For more help on a specific command:
  wardenips-cli <command> --help
        """,
    )
    
    # Global arguments
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"wardenips-cli v{__version__} by {__author__}",
    )
    
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to WardenIPS config.yaml (default: config.yaml)",
    )
    
    parser.add_argument(
        "--use-api",
        action="store_true",
        help="Use API mode instead of direct DB access (requires dashboard running)",
    )
    
    parser.add_argument(
        "--api-url",
        help="Override dashboard API URL (default: http://127.0.0.1:7680)",
    )
    
    parser.add_argument(
        "--api-key",
        help="API key for authentication (default: from ~/.wardenips/config.json)",
    )
    
    parser.add_argument(
        "--output", "-o",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True
    
    # Register commands from command modules
    ban_parser = subparsers.add_parser("ban", help="Ban IP addresses")
    ban_subparsers = ban_parser.add_subparsers(dest="ban_cmd", required=True)
    register_ban_commands(ban_subparsers)
    ban_parser.set_defaults(handler='ban')
    
    whitelist_parser = subparsers.add_parser("whitelist", help="Manage whitelist")
    whitelist_subparsers = whitelist_parser.add_subparsers(dest="whitelist_cmd", required=True)
    register_whitelist_commands(whitelist_subparsers)
    whitelist_parser.set_defaults(handler='whitelist')
    
    firewall_parser = subparsers.add_parser("firewall", help="Manage firewall")
    firewall_subparsers = firewall_parser.add_subparsers(dest="firewall_cmd", required=True)
    register_firewall_commands(firewall_subparsers)
    firewall_parser.set_defaults(handler='firewall')
    
    config_parser = subparsers.add_parser("config", help="Configure system")
    config_subparsers = config_parser.add_subparsers(dest="config_cmd", required=True)
    register_config_commands(config_subparsers)
    config_parser.set_defaults(handler='config')
    
    database_parser = subparsers.add_parser("database", help="Manage database")
    database_subparsers = database_parser.add_subparsers(dest="database_cmd", required=True)
    register_database_commands(database_subparsers)
    database_parser.set_defaults(handler='database')
    
    return parser


async def cmd_firewall_status(args, client):
    """Execute firewall status command."""
    result = await client.get_firewall_status()
    print_result(result, args.output)


async def cmd_firewall_sync(args, client):
    """Execute firewall sync command."""
    result = await client.sync_firewall(dry_run=args.dry_run)
    print_result(result, args.output)


async def cmd_config_get(args, client):
    """Execute config get command."""
    result = await client.get_config(key=args.key)
    print_result(result, args.output)


async def cmd_config_set(args, client):
    """Execute config set command."""
    # Try to parse value as JSON, fallback to string
    try:
        value = json.loads(args.value)
    except json.JSONDecodeError:
        value = args.value
    
    result = await client.set_config(args.key, value)
    print_result(result, args.output)


async def cmd_config_reload(args, client):
    """Execute config reload command."""
    components = None
    if args.components:
        components = [c.strip() for c in args.components.split(",")]
    
    result = await client.reload_config(components=components)
    print_result(result, args.output)


async def cmd_plugins_list(args, client):
    """Execute plugins list command."""
    result = await client.get_plugin_list()
    print_result(result, args.output)


async def cmd_plugins_status(args, client):
    """Execute plugins status command."""
    result = await client.get_plugin_status(args.name)
    print_result(result, args.output)


async def cmd_plugins_reload(args, client):
    """Execute plugins reload command."""
    result = await client.reload_plugin(args.name)
    print_result(result, args.output)


async def cmd_database_stats(args, client):
    """Execute database stats command."""
    result = await client.get_database_stats()
    print_result(result, args.output)


async def cmd_database_optimize(args, client):
    """Execute database optimize command."""
    result = await client.optimize_database()
    print_result(result, args.output)


async def cmd_auth_create_user(args, client):
    """Execute auth create-user command."""
    print("Note: User creation not yet implemented in DirectClient", file=sys.stderr)
    print("Use dashboard /setup endpoint instead", file=sys.stderr)


async def cmd_status(args, client):
    """Execute status command."""
    result = await client.get_system_status()
    print_result(result, args.output)


def print_result(result, format_type: str = "text"):
    """Print result in specified format."""
    if format_type == "json":
        print(json.dumps(result, indent=2, default=str))
    elif format_type == "csv":
        # Simple CSV for lists of dicts
        if isinstance(result, list) and result and isinstance(result[0], dict):
            keys = list(result[0].keys())
            print(",".join(keys))
            for item in result:
                print(",".join(str(item.get(k, "")) for k in keys))
        else:
            print(json.dumps(result, indent=2, default=str))
    else:
        # Text format
        if isinstance(result, dict):
            for key, value in result.items():
                if isinstance(value, (dict, list)):
                    print(f"{key}: {json.dumps(value, indent=2, default=str)}")
                else:
                    print(f"{key}: {value}")
        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    print(" | ".join(f"{k}={v}" for k, v in item.items()))
                else:
                    print(item)
        else:
            print(result)


async def main():
    """Main CLI entry point."""
    # Load config
    cli_config = load_cli_config()
    
    # Parse arguments
    parser = build_arg_parser()
    args = parser.parse_args()
    
    # Show help if no command
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        # Get the handler for this command
        handler = getattr(args, 'handler', None)
        
        if handler == 'ban':
            return await handle_ban_command(args)
        elif handler == 'whitelist':
            return await handle_whitelist_command(args)
        elif handler == 'config':
            return await handle_config_command(args)
        elif handler == 'firewall':
            return await handle_firewall_command(args)
        elif handler == 'database':
            return await handle_database_command(args)
        elif handler == 'plugins':
            print("Note: Plugins commands not yet implemented", file=sys.stderr)
            return 1
        elif handler == 'auth':
            print("Note: Auth commands not yet implemented", file=sys.stderr)
            return 1
        elif handler == 'status':
            print("Note: Status command not yet implemented", file=sys.stderr)
            return 1
        else:
            print(f"Error: Unknown handler '{handler}'", file=sys.stderr)
            return 1
    
    except CLIError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def cli_entry_point():
    """Entry point for console_scripts in setup.py."""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli_entry_point()
