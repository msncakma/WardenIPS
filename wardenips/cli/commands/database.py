"""Database management CLI commands."""
import asyncio
import json
from argparse import Namespace
from tabulate import tabulate
from ..client import get_client
from ..client.exceptions import CLIError


async def cmd_database_stats(client, args: Namespace) -> int:
    """Show database statistics."""
    try:
        # Call service
        result = await client.get_database_stats()
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        if result.get('ok'):
            stats = result.get('stats', {})
            print(f"Database Statistics:")
            print(f"  Total Events: {stats.get('total_events', 0):,}")
            print(f"  Ban Records: {stats.get('ban_records', 0):,}")
            print(f"  Whitelist Entries: {stats.get('whitelist_entries', 0):,}")
            print(f"  Active Bans: {stats.get('active_bans', 0):,}")
            print(f"  Database Size: {stats.get('database_size_mb', 0):.2f} MB")
            
            if stats.get('last_optimized'):
                print(f"  Last Optimized: {stats.get('last_optimized')}")
        else:
            print(f"✗ Failed to get database stats")
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


async def cmd_database_optimize(client, args: Namespace) -> int:
    """Optimize database (VACUUM + ANALYZE)."""
    try:
        dry_run = getattr(args, 'dry_run', False)
        
        # Call service
        result = await client.optimize_database(dry_run=dry_run)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Database optimization completed")
                print(f"  Time elapsed: {result.get('elapsed_seconds', 0):.2f}s")
                print(f"  Size before: {result.get('size_before_mb', 0):.2f} MB")
                print(f"  Size after: {result.get('size_after_mb', 0):.2f} MB")
                saved = result.get('size_before_mb', 0) - result.get('size_after_mb', 0)
                if saved > 0:
                    print(f"  Space saved: {saved:.2f} MB")
                if dry_run:
                    print(f"  [DRY RUN - No changes made]")
            else:
                print(f"✗ Database optimization failed")
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


async def cmd_database_cleanup(client, args: Namespace) -> int:
    """Clean up old database records."""
    try:
        days = getattr(args, 'days', 30)
        dry_run = getattr(args, 'dry_run', False)
        
        # Call service
        result = await client.cleanup_database(days=days, dry_run=dry_run)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('ok'):
                print(f"✓ Database cleanup completed")
                print(f"  Deleted: {result.get('deleted_records', 0)} old records")
                print(f"  Cleaned up events before: {days} days ago")
                if dry_run:
                    print(f"  [DRY RUN - No changes made]")
            else:
                print(f"✗ Database cleanup failed")
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


async def cmd_database_export(client, args: Namespace) -> int:
    """Export database to file."""
    try:
        file_path = args.file
        format_type = getattr(args, 'format', 'json')
        table = getattr(args, 'table', None)
        
        # Call service
        result = await client.export_database(table=table, format_type=format_type)
        
        if not result.get('ok'):
            raise CLIError(result.get('error', 'Export failed'))
        
        data = result.get('data', '')
        
        # Write to file
        try:
            with open(file_path, 'w') as f:
                f.write(data)
            
            if args.output == 'json':
                print(json.dumps({'ok': True, 'file': file_path}, indent=2))
            else:
                print(f"✓ Exported {format_type.upper()} to {file_path}")
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


async def cmd_database_query(client, args: Namespace) -> int:
    """Execute SQL query on database."""
    try:
        sql = args.query
        
        if not sql:
            raise CLIError("Query cannot be empty")
        
        # Call service - only for SELECT queries
        if not sql.strip().upper().startswith('SELECT'):
            raise CLIError("Only SELECT queries are allowed")
        
        # Call service
        result = await client.execute_query(sql=sql)
        
        # Output result
        if args.output == 'json':
            print(json.dumps(result, indent=2))
            return 0
        
        if result.get('ok'):
            rows = result.get('rows', [])
            columns = result.get('columns', [])
            
            if not rows:
                print("No results")
                return 0
            
            # Format for table
            table_data = []
            for row in rows:
                table_data.append(row)
            
            print(tabulate(table_data, headers=columns, tablefmt='grid'))
            print(f"\nTotal: {len(rows)} rows")
        else:
            print(f"✗ Query failed")
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


def register_database_commands(subparsers):
    """Register database command parsers."""
    
    # Main database parser
    db_parser = subparsers.add_parser('database', help='Manage database')
    db_subparsers = db_parser.add_subparsers(dest='database_cmd', required=True)
    
    # database stats
    stats_parser = db_subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.set_defaults(handler='database_stats')
    
    # database optimize
    optimize_parser = db_subparsers.add_parser('optimize', help='Optimize database')
    optimize_parser.add_argument('--dry-run', action='store_true', help='Preview changes')
    optimize_parser.set_defaults(handler='database_optimize')
    
    # database cleanup
    cleanup_parser = db_subparsers.add_parser('cleanup', help='Clean up old records')
    cleanup_parser.add_argument('-d', '--days', type=int, default=30, help='Delete events older than N days')
    cleanup_parser.add_argument('--dry-run', action='store_true', help='Preview changes')
    cleanup_parser.set_defaults(handler='database_cleanup')
    
    # database export
    export_parser = db_subparsers.add_parser('export', help='Export database')
    export_parser.add_argument('file', help='Output file')
    export_parser.add_argument('--format', choices=['json', 'csv', 'sql'], default='json')
    export_parser.add_argument('-t', '--table', help='Specific table to export')
    export_parser.set_defaults(handler='database_export')
    
    # database query
    query_parser = db_subparsers.add_parser('query', help='Execute SELECT query')
    query_parser.add_argument('query', help='SQL SELECT query')
    query_parser.set_defaults(handler='database_query')


async def handle_database_command(args: Namespace) -> int:
    """Main handler for database commands."""
    client = get_client(args)
    
    cmd_name = getattr(args, 'database_cmd', None)
    if not cmd_name:
        print("Usage: wardenips database {stats|optimize|cleanup|export|query}")
        return 1
    
    handler_map = {
        'stats': cmd_database_stats,
        'optimize': cmd_database_optimize,
        'cleanup': cmd_database_cleanup,
        'export': cmd_database_export,
        'query': cmd_database_query,
    }
    
    handler = handler_map.get(cmd_name)
    if not handler:
        print(f"Unknown database command: {cmd_name}")
        return 1
    
    return await handler(client, args)
