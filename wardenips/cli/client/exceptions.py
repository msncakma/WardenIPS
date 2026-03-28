"""CLI-specific exceptions."""


class CLIError(Exception):
    """Base exception for CLI errors."""
    pass


class ClientError(CLIError):
    """Client operational error."""
    pass


class APIError(ClientError):
    """API connection or response error."""
    pass


class DirectClientError(ClientError):
    """Direct client (DB/firewall) error."""
    pass


class ConfigError(CLIError):
    """Configuration loading/validation error."""
    pass


class CommandError(CLIError):
    """Command execution error."""
    pass


class ValidationError(CommandError):
    """Argument or data validation error."""
    pass


class AuthenticationError(ClientError):
    """Authentication/authorization error."""
    pass
