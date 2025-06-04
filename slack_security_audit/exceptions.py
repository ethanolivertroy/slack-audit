"""
Custom exceptions for the Slack Security Audit Platform.
"""


class SlackAuditException(Exception):
    """Base exception for all Slack audit related errors."""
    pass


class AuthenticationError(SlackAuditException):
    """Raised when authentication with Slack API fails."""
    pass


class InsufficientPermissionsError(SlackAuditException):
    """Raised when the API token lacks required permissions."""
    pass


class APIError(SlackAuditException):
    """Raised when Slack API returns an error."""
    pass


class ConfigurationError(SlackAuditException):
    """Raised when there's an issue with the audit configuration."""
    pass


class FrameworkNotFoundError(SlackAuditException):
    """Raised when a requested compliance framework is not found."""
    pass


class ControlNotImplementedError(SlackAuditException):
    """Raised when a control check is not yet implemented."""
    pass