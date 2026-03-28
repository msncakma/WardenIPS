"""Whitelist management CLI commands."""
import asyncio
import json
from typing import List
from argparse import Namespace
from tabulate import tabulate
from ..client import get_client
from ..client.exceptions import CLIError


async def cmd_whitelist_add(client, args: Namespace) -> int:
    """Add IP or CIDR to whitelist."""
    try:
        ip = args.ip
        reason = getattr(args, 'reason', 'CLI whitelist')
        
        # Call service
        result = await client.add_whitelist(ip=ip, reason=reason)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ {ip} added to whitelist")
            else:
                print(f"✗ Failed to add {ip} to whitelist")
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


async def cmd_whitelist_list(client, args: Namespace) -> int:
    """List whitelisted IPs."""
    try:
        # Get filters
        limit = getattr(args, 'limit', 100)
        offset = getattr(args, 'offset', 0)
        
        # Call service
        result = await client.get_whitelisted_ips(limit=limit, offset=offset)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        whitelist = result.get('whitelist', [])
        if not whitelist:
            print("Whitelist is empty")
            return 0
        
        # Format for table display
        table_data = []
        for entry in whitelist:
            table_data.append([
                entry.get('ip', 'N/A'),
                entry.get('reason', 'N/A')[:40],
                entry.get('added_by', 'N/A'),
                entry.get('added_at', 'N/A')[:19],
            ])
        
        headers = ['IP/CIDR', 'Reason', 'Added By', 'Added At']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal: {result.get('total', len(whitelist))} entries")
        
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


async def cmd_whitelist_remove(client, args: Namespace) -> int:
    """Remove IP or CIDR from whitelist."""
    try:
        ip = args.ip
        
        # Call service
        result = await client.remove_whitelist(ip=ip)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ {ip} removed from whitelist")
            else:
                print(f"✗ Failed to remove {ip}")
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


async def cmd_whitelist_import(client, args: Namespace) -> int:
    """Import whitelisted IPs from file."""
    try:
        file_path = args.file
        reason = getattr(args, 'reason', 'Imported via CLI')
        dry_run = getattr(args, 'dry_run', False)
        
        ips = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ips.append(line)
        except IOError as e:
            raise CLIError(f"Cannot read file: {e}")
        
        if not ips:
            raise CLIError("No IPs to import")
        
        # Show preview
        if args.verbose or dry_run:
            print(f"IPs to whitelist ({len(ips)}):")
            for ip in ips[:10]:
                print(f"  {ip}")
            if len(ips) > 10:
                print(f"  ... and {len(ips) - 10} more")
        
        if dry_run:
            print(f"\n[DRY RUN] Would whitelist {len(ips)} IPs")
            return 0
        
        # Confirm
        if not getattr(args, 'force', False):
            response = input(f"\nWhitelist {len(ips)} IPs? (yes/no): ")
            if response.lower() != 'yes':
                print("Cancelled")
                return 1
        
        # Import each IP
        passed = 0
        failed = 0
        for ip in ips:
            try:
                result = await client.add_whitelist(ip=ip, reason=reason)
                if result.get('ok'):
                    passed += 1
                else:
                    failed += 1
                    if args.verbose:
                        print(f"  Failed: {ip} - {result.get('error')}")
            except Exception as e:
                failed += 1
                if args.verbose:
                    print(f"  Failed: {ip} - {str(e)}")
        
        # Output result
        if args.output == 'json':
            print(json.dumps({
                'ok': True,
                'passed': passed,
                'failed': failed,
                'total': len(ips)
            }, indent=2))
        else:
            print(f"✓ Import completed")
            print(f"  Whitelisted: {passed}")
            print(f"  Failed: {failed}")
        
        return 0 if failed == 0 else 1
        
    except CLIError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def cmd_whitelist_export(client, args: Namespace) -> int:
    """Export whitelist to file."""
    try:
        file_path = args.output if hasattr(args, 'output_file') else args.file
        format_type = getattr(args, 'format', 'text')
        
        # Get whitelist
        result = await client.get_whitelisted_ips(limit=999999)
        whitelist = result.get('whitelist', [])
        
        if not whitelist:
            print("Whitelist is empty")
            return 0
        
        # Format data
        if format_type == 'json':
            content = json.dumps(whitelist, indent=2)
        elif format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['ip', 'reason', 'added_by', 'added_at'])
            writer.writeheader()
            writer.writerows(whitelist)
            content = output.getvalue()
        else:  # text
            content = '\n'.join([entry['ip'] for entry in whitelist])
        
        # Write to file
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✓ Exported {len(whitelist)} entries to {file_path}")
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


def register_whitelist_commands(subparsers):
    """Register whitelist command parsers."""
    
    # Main whitelist parser
    whitelist_parser = subparsers.add_parser('whitelist', help='Manage whitelisted IPs')
    whitelist_subparsers = whitelist_parser.add_subparsers(dest='whitelist_cmd', required=True)
    
    # whitelist add
    add_parser = whitelist_subparsers.add_parser('add', help='Add IP to whitelist')
    add_parser.add_argument('ip', help='IP or CIDR to whitelist')
    add_parser.add_argument('-r', '--reason', help='Reason for whitelisting')
    add_parser.set_defaults(handler='whitelist_add')
    
    # whitelist list
    list_parser = whitelist_subparsers.add_parser('list', help='List whitelisted IPs')
    list_parser.add_argument('-l', '--limit', type=int, default=100, help='Limit results')
    list_parser.add_argument('-o', '--offset', type=int, default=0, help='Offset')
    list_parser.set_defaults(handler='whitelist_list')
    
    # whitelist remove
    remove_parser = whitelist_subparsers.add_parser('remove', help='Remove IP from whitelist')
    remove_parser.add_argument('ip', help='IP or CIDR to remove')
    remove_parser.set_defaults(handler='whitelist_remove')
    
    # whitelist import
    import_parser = whitelist_subparsers.add_parser('import', help='Import IPs from file')
    import_parser.add_argument('file', help='File with IPs (one per line)')
    import_parser.add_argument('-r', '--reason', help='Reason for whitelisting')
    import_parser.add_argument('--dry-run', action='store_true', help='Preview without importing')
    import_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    import_parser.set_defaults(handler='whitelist_import')
    
    # whitelist export
    export_parser = whitelist_subparsers.add_parser('export', help='Export whitelist to file')
    export_parser.add_argument('file', help='Output file')
    export_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    export_parser.set_defaults(handler='whitelist_export')


async def handle_whitelist_command(args: Namespace) -> int:
    """Main handler for whitelist commands."""
    client = get_client(args)
    
    cmd_name = getattr(args, 'whitelist_cmd', None)
    if not cmd_name:
        print("Usage: wardenips whitelist {add|list|remove|import|export}")
        return 1
    
    handler_map = {
        'add': cmd_whitelist_add,
        'list': cmd_whitelist_list,
        'remove': cmd_whitelist_remove,
        'import': cmd_whitelist_import,
        'export': cmd_whitelist_export,
    }
    
    handler = handler_map.get(cmd_name)
    if not handler:
        print(f"Unknown whitelist command: {cmd_name}")
        return 1
    
    return await handler(client, args)
