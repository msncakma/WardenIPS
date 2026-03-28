"""Ban management CLI commands."""
import asyncio
import json
from typing import List
from argparse import Namespace
from tabulate import tabulate
from ..client import get_client
from ..client.exceptions import CLIError


async def cmd_ban_add(client, args: Namespace) -> int:
    """Add IP to ban list."""
    try:
        # Parse arguments
        ip = args.ip
        duration = getattr(args, 'duration', None)
        reason = getattr(args, 'reason', 'CLI ban')
        
        # Parse duration if provided (format: 1h, 24h, 7d, 30d)
        duration_seconds = None
        if duration:
            multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
            if duration[-1] in multipliers:
                try:
                    amount = int(duration[:-1])
                    duration_seconds = amount * multipliers[duration[-1]]
                except ValueError:
                    raise CLIError(f"Invalid duration format: {duration}. Use format like '24h', '7d', etc.")
            else:
                raise CLIError(f"Invalid duration format: {duration}. Use format like '24h', '7d', etc.")
        
        # Call service
        result = await client.ban_ip(ip=ip, duration_seconds=duration_seconds, reason=reason)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ IP {ip} banned successfully")
                if result.get('details'):
                    print(f"  Duration: {result['details'].get('duration_human', 'Permanent')}")
                    print(f"  Added to firewall: {result['details'].get('firewall_added', 'N/A')}")
            else:
                print(f"✗ Failed to ban IP {ip}")
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


async def cmd_ban_list(client, args: Namespace) -> int:
    """List banned IPs."""
    try:
        # Get filters
        limit = getattr(args, 'limit', 50)
        offset = getattr(args, 'offset', 0)
        filters = {}
        
        if hasattr(args, 'reason') and args.reason:
            filters['reason'] = args.reason
        if hasattr(args, 'since') and args.since:
            filters['since'] = args.since
        
        # Call service
        result = await client.get_bans(limit=limit, offset=offset, filters=filters)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        bans = result.get('bans', [])
        if not bans:
            print("No bans found")
            return 0
        
        # Format for table display
        table_data = []
        for ban in bans:
            expires = ban.get('expires_at')
            if expires:
                import datetime
                try:
                    exp_dt = datetime.datetime.fromisoformat(expires)
                    expires_display = exp_dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    expires_display = expires
            else:
                expires_display = 'Permanent'
            
            table_data.append([
                ban.get('ip', 'N/A'),
                ban.get('reason', 'N/A')[:30],
                ban.get('added_by', 'N/A'),
                expires_display,
                ban.get('active', True)
            ])
        
        headers = ['IP Address', 'Reason', 'Added By', 'Expires', 'Active']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print(f"\nTotal: {result.get('total', len(bans))} bans")
        
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


async def cmd_ban_remove(client, args: Namespace) -> int:
    """Remove IP from ban list."""
    try:
        ip = args.ip
        
        # Call service
        result = await client.unban_ip(ip=ip)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ IP {ip} unbanned successfully")
            else:
                print(f"✗ Failed to unban IP {ip}")
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


async def cmd_ban_bulk(client, args: Namespace) -> int:
    """Bulk ban IPs from CIDR range or CSV file."""
    try:
        ips_file = getattr(args, 'file', None)
        cidr = getattr(args, 'cidr', None)
        reason = getattr(args, 'reason', 'Bulk ban via CLI')
        dry_run = getattr(args, 'dry_run', False)
        
        ips_to_ban = []
        
        # Load from file
        if ips_file:
            try:
                with open(ips_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ips_to_ban.append(line)
            except IOError as e:
                raise CLIError(f"Cannot read file: {e}")
        
        # Generate from CIDR
        elif cidr:
            try:
                import ipaddress
                network = ipaddress.ip_network(cidr)
                ips_to_ban = [str(ip) for ip in network.hosts()]
            except ValueError as e:
                raise CLIError(f"Invalid CIDR notation: {e}")
        
        else:
            raise CLIError("Must specify either --file or --cidr")
        
        if not ips_to_ban:
            raise CLIError("No IPs to ban")
        
        # Show preview
        if args.verbose or dry_run:
            print(f"IPs to ban ({len(ips_to_ban)}):")
            for ip in ips_to_ban[:10]:
                print(f"  {ip}")
            if len(ips_to_ban) > 10:
                print(f"  ... and {len(ips_to_ban) - 10} more")
        
        if dry_run:
            print(f"\n[DRY RUN] Would ban {len(ips_to_ban)} IPs")
            return 0
        
        # Confirm
        if not getattr(args, 'force', False):
            response = input(f"\nBan {len(ips_to_ban)} IPs? (yes/no): ")
            if response.lower() != 'yes':
                print("Cancelled")
                return 1
        
        # Call service
        result = await client.bulk_ban_ips(ips=ips_to_ban, reason=reason)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Bulk ban completed")
                print(f"  Banned: {result.get('banned_count', 0)}/{len(ips_to_ban)}")
                if result.get('failed_count', 0) > 0:
                    print(f"  Failed: {result.get('failed_count')}")
            else:
                print(f"✗ Bulk ban failed")
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


def register_ban_commands(subparsers):
    """Register ban command parsers."""
    
    # Main ban parser
    ban_parser = subparsers.add_parser('ban', help='Manage IP bans')
    ban_subparsers = ban_parser.add_subparsers(dest='ban_cmd', required=True)
    
    # ban add
    add_parser = ban_subparsers.add_parser('add', help='Ban an IP address')
    add_parser.add_argument('ip', help='IP address to ban')
    add_parser.add_argument('-d', '--duration', help='Ban duration (e.g., 24h, 7d)')
    add_parser.add_argument('-r', '--reason', help='Reason for ban')
    add_parser.set_defaults(handler='ban_add')
    
    # ban list
    list_parser = ban_subparsers.add_parser('list', help='List banned IPs')
    list_parser.add_argument('-l', '--limit', type=int, default=50, help='Limit results')
    list_parser.add_argument('-o', '--offset', type=int, default=0, help='Offset')
    list_parser.add_argument('-r', '--reason', help='Filter by reason')
    list_parser.add_argument('-s', '--since', help='Filter by date (YYYY-MM-DD)')
    list_parser.set_defaults(handler='ban_list')
    
    # ban remove
    remove_parser = ban_subparsers.add_parser('remove', help='Unban an IP address')
    remove_parser.add_argument('ip', help='IP address to unban')
    remove_parser.set_defaults(handler='ban_remove')
    
    # ban bulk
    bulk_parser = ban_subparsers.add_parser('bulk', help='Bulk ban IPs')
    bulk_parser.add_argument('-f', '--file', help='File with IPs (one per line)')
    bulk_parser.add_argument('-c', '--cidr', help='CIDR range to ban')
    bulk_parser.add_argument('-r', '--reason', help='Reason for ban')
    bulk_parser.add_argument('--dry-run', action='store_true', help='Show what would be banned')
    bulk_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    bulk_parser.set_defaults(handler='ban_bulk')


async def handle_ban_command(args: Namespace) -> int:
    """Main handler for ban commands."""
    client = get_client(args)
    
    cmd_name = getattr(args, 'ban_cmd', None)
    if not cmd_name:
        print("Usage: wardenips ban {add|list|remove|bulk}")
        return 1
    
    handler_map = {
        'add': cmd_ban_add,
        'list': cmd_ban_list,
        'remove': cmd_ban_remove,
        'bulk': cmd_ban_bulk,
    }
    
    handler = handler_map.get(cmd_name)
    if not handler:
        print(f"Unknown ban command: {cmd_name}")
        return 1
    
    return await handler(client, args)
