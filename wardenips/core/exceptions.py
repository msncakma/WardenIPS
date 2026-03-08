"""
WardenIPS - Custom Error Classes (Exceptions)
==============================================

All WardenIPS-specific exceptions are defined in this module.
"""


class WardenError(Exception):
    """WardenIPS base exception class. All custom errors inherit from this."""
    pass


class WardenConfigError(WardenError):
    """
    Configuration error.

    Raised when the config.yaml file cannot be read, contains 
    invalid values, or is missing required fields.
    """
    pass


class WardenWhitelistError(WardenError):
    """
    Whitelist error.

    Raised for invalid IP/CIDR formats inside the whitelist manager.
    """
    pass


class WardenFirewallError(WardenError):
    """
    Firewall error.

    Raised when an error occurs executing ipset commands
    or applying firewall rules.
    """
    pass


class WardenDatabaseError(WardenError):
    """
    Database error.

    Raised during aSQLite/PostgreSQL connection, read, 
    or write errors.
    """
    pass


class WardenPluginError(WardenError):
    """
    Plugin error.

    Raised when a plugin encounters a problem during 
    initialization, start, or execution.
    """
    pass
