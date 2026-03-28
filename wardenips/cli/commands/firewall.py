"""Firewall management CLI commands."""
import asyncio
import json
from argparse import Namespace
from tabulate import tabulate
from ..client import get_client
from ..client.exceptions import CLIError


async def cmd_firewall_status(client, args: Namespace) -> int:
    """Show firewall status."""
    try:
        # Call service
        result = await client.get_firewall_status()
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        if result.get('ok'):
            status = result.get('status', {})
            print(f"Firewall Status:")
            print(f"  Backend: {status.get('backend', 'N/A')}")
            print(f"  Simulation Mode: {status.get('simulation_mode', False)}")
            print(f"  Active Rules: {status.get('active_rules', 0)}")
            print(f"  Active Bans: {status.get('active_bans', 0)}")
            
            details = status.get('details', {})
            if details:
                print(f"  Details:")
                for key, value in details.items():
                    print(f"    {key}: {value}")
        else:
            print(f"✗ Failed to get firewall status")
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


async def cmd_firewall_sync(client, args: Namespace) -> int:
    """Sync firewall rules with database."""
    try:
        dry_run = getattr(args, 'dry_run', False)
        
        # Call service
        result = await client.sync_firewall(dry_run=dry_run)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Firewall sync completed")
                print(f"  Added: {result.get('added', 0)} rules")
                print(f"  Removed: {result.get('removed', 0)} rules")
                print(f"  Synced: {result.get('synced', 0)} rules")
                if dry_run:
                    print(f"  [DRY RUN - No changes made]")
            else:
                print(f"✗ Firewall sync failed")
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


async def cmd_firewall_clear(client, args: Namespace) -> int:
    """Clear all firewall rules."""
    try:
        # Confirm
        if not getattr(args, 'force', False):
            response = input("Clear all firewall rules? This will unban all IPs. (yes/no): ")
            if response.lower() != 'yes':
                print("Cancelled")
                return 1
        
        # Call service
        result = await client.clear_firewall()
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Firewall cleared")
                print(f"  Removed: {result.get('removed', 0)} rules")
            else:
                print(f"✗ Failed to clear firewall")
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


async def cmd_firewall_rules(client, args: Namespace) -> int:
    """List active firewall rules."""
    try:
        # Get filters
        limit = getattr(args, 'limit', 50)
        offset = getattr(args, 'offset', 0)
        
        # Call service
        result = await client.get_firewall_rules(limit=limit, offset=offset)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        rules = result.get('rules', [])
        if not rules:
            print("No active firewall rules")
            return 0
        
        # Format for table display
        table_data = []
        for rule in rules:
            table_data.append([
                rule.get('ip', 'N/A'),
                rule.get('action', 'N/A'),
                rule.get('protocol', 'N/A'),
                rule.get('port', 'N/A'),
                rule.get('expires_at', 'Permanent')[:19],
            ])
        
        headers = ['IP', 'Action', 'Protocol', 'Port', 'Expires']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal: {result.get('total', len(rules))} active rules")
        
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


async def cmd_firewall_export(client, args: Namespace) -> int:
    """Export firewall rules to file."""
    try:
        file_path = args.file
        format_type = getattr(args, 'format', 'text')
        
        # Get rules
        result = await client.get_firewall_rules(limit=999999)
        rules = result.get('rules', [])
        
        if not rules:
            print("No active firewall rules to export")
            return 0
        
        # Format data
        if format_type == 'json':
            content = json.dumps(rules, indent=2)
        elif format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['ip', 'action', 'protocol', 'port', 'expires_at'])
            writer.writeheader()
            writer.writerows(rules)
            content = output.getvalue()
        else:  # text - just IPs
            content = '\n'.join([rule['ip'] for rule in rules])
        
        # Write to file
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✓ Exported {len(rules)} rules to {file_path}")
            return 0
        except IOError as e:
            raise CLIError(f"Cannot write to file: {e}")
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def register_firewall_commands(subparsers):
    """Register firewall command parsers."""
    
    # Main firewall parser
    firewall_parser = subparsers.add_parser('firewall', help='Manage firewall rules')
    firewall_subparsers = firewall_parser.add_subparsers(dest='firewall_cmd', required=True)
    
    # firewall status
    status_parser = firewall_subparsers.add_parser('status', help='Show firewall status')
    status_parser.set_defaults(handler='firewall_status')
    
    # firewall sync
    sync_parser = firewall_subparsers.add_parser('sync', help='Sync firewall with database')
    sync_parser.add_argument('--dry-run', action='store_true', help='Preview changes')
    sync_parser.set_defaults(handler='firewall_sync')
    
    # firewall clear
    clear_parser = firewall_subparsers.add_parser('clear', help='Clear all firewall rules')
    clear_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    clear_parser.set_defaults(handler='firewall_clear')
    
    # firewall rules
    rules_parser = firewall_subparsers.add_parser('rules', help='List active firewall rules')
    rules_parser.add_argument('-l', '--limit', type=int, default=50, help='Limit results')
    rules_parser.add_argument('-o', '--offset', type=int, default=0, help='Offset')
    rules_parser.set_defaults(handler='firewall_rules')
    
    # firewall export
    export_parser = firewall_subparsers.add_parser('export', help='Export rules to file')
    export_parser.add_argument('file', help='Output file')
    export_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    export_parser.set_defaults(handler='firewall_export')


async def handle_firewall_command(args: Namespace) -> int:
    """Main handler for firewall commands."""
    client = get_client(args)
    
    cmd_name = getattr(args, 'firewall_cmd', None)
    if not cmd_name:
        print("Usage: wardenips firewall {status|sync|clear|rules|export}")
        return 1
    
    handler_map = {
        'status': cmd_firewall_status,
        'sync': cmd_firewall_sync,
        'clear': cmd_firewall_clear,
        'rules': cmd_firewall_rules,
        'export': cmd_firewall_export,
    }
    
    handler = handler_map.get(cmd_name)
    if not handler:
        print(f"Unknown firewall command: {cmd_name}")
        return 1
    
    return await handler(client, args)
