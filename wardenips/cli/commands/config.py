"""Config management CLI commands."""
import asyncio
import json
from argparse import Namespace
from tabulate import tabulate
from ..client import get_client
from ..client.exceptions import CLIError


async def cmd_config_get(client, args: Namespace) -> int:
    """Get config value."""
    try:
        key = args.key
        
        # Call service
        result = await client.get_config(key=key)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                value = result.get('value')
                print(f"{key} = {json.dumps(value, indent=2)}")
            else:
                print(f"✗ Failed to get config")
                print(f"  {result.get('error', 'Unknown error')}")
        
        return 0 if result.get('ok') else 1
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def cmd_config_set(client, args: Namespace) -> int:
    """Set config value."""
    try:
        key = args.key
        value = args.value
        
        # Try to parse as JSON if it looks like JSON
        if value.startswith('{') or value.startswith('[') or value.lower() in ['true', 'false', 'null']:
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass  # Keep as string
        
        # Call service
        result = await client.set_config(key=key, value=value)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Config updated")
                print(f"  {key} = {json.dumps(value)}")
            else:
                print(f"✗ Failed to set config")
                print(f"  {result.get('error', 'Unknown error')}")
        
        return 0 if result.get('ok') else 1
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def cmd_config_list(client, args: Namespace) -> int:
    """List all config values."""
    try:
        # Call service
        result = await client.get_all_config()
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        config = result.get('config', {})
        if not config:
            print("No config found")
            return 0
        
        # Format for table display
        table_data = []
        for key, value in config.items():
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value)[:50]
            else:
                value_str = str(value)[:50]
            table_data.append([key, value_str])
        
        headers = ['Key', 'Value']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal: {len(config)} config entries")
        
        return 0
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def cmd_config_reload(client, args: Namespace) -> int:
    """Reload configuration."""
    try:
        components = getattr(args, 'components', None)
        
        if components:
            components_list = components.split(',')
        else:
            components_list = None
        
        # Call service
        result = await client.reload_config(components=components_list)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Config reloaded")
                if result.get('reloaded'):
                    print(f"  Reloaded components:")
                    for comp in result['reloaded']:
                        print(f"    - {comp}")
                if result.get('failed'):
                    print(f"  Failed to reload:")
                    for comp, err in result['failed'].items():
                        print(f"    - {comp}: {err}")
            else:
                print(f"✗ Failed to reload config")
                print(f"  {result.get('error', 'Unknown error')}")
        
        return 0 if result.get('ok') else 1
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def cmd_config_validate(client, args: Namespace) -> int:
    """Validate configuration."""
    try:
        # Call service
        result = await client.validate_config()
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok') or result.get('valid'):
                print(f"✓ Configuration is valid")
            else:
                print(f"✗ Configuration errors found")
                errors = result.get('errors', [])
                for error in errors:
                    print(f"  - {error}")
                warnings = result.get('warnings', [])
                if warnings:
                    print(f"Warnings:")
                    for warning in warnings:
                        print(f"  - {warning}")
        
        return 0 if (result.get('ok') or result.get('valid')) else 1
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def register_config_commands(subparsers):
    """Register config command parsers."""
    
    # Main config parser
    config_parser = subparsers.add_parser('config', help='Manage configuration')
    config_subparsers = config_parser.add_subparsers(dest='config_cmd', required=True)
    
    # config get
    get_parser = config_subparsers.add_parser('get', help='Get config value')
    get_parser.add_argument('key', help='Config key')
    get_parser.set_defaults(handler='config_get')
    
    # config set
    set_parser = config_subparsers.add_parser('set', help='Set config value')
    set_parser.add_argument('key', help='Config key')
    set_parser.add_argument('value', help='Config value (JSON for objects/arrays)')
    set_parser.set_defaults(handler='config_set')
    
    # config list
    list_parser = config_subparsers.add_parser('list', help='List all config values')
    list_parser.set_defaults(handler='config_list')
    
    # config reload
    reload_parser = config_subparsers.add_parser('reload', help='Reload configuration')
    reload_parser.add_argument('-c', '--components', help='Comma-separated component list')
    reload_parser.set_defaults(handler='config_reload')
    
    # config validate
    validate_parser = config_subparsers.add_parser('validate', help='Validate configuration')
    validate_parser.set_defaults(handler='config_validate')


async def handle_config_command(args: Namespace) -> int:
    """Main handler for config commands."""
    client = get_client(args)
    
    cmd_name = getattr(args, 'config_cmd', None)
    if not cmd_name:
        print("Usage: wardenips config {get|set|list|reload|validate}")
        return 1
    
    handler_map = {
        'get': cmd_config_get,
        'set': cmd_config_set,
        'list': cmd_config_list,
        'reload': cmd_config_reload,
        'validate': cmd_config_validate,
    }
    
    handler = handler_map.get(cmd_name)
    if not handler:
        print(f"Unknown config command: {cmd_name}")
        return 1
    
    return await handler(client, args)
