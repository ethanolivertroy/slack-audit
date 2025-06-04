"""
Slack Security Audit Platform

A comprehensive security assessment tool for Slack workspaces that evaluates
compliance with industry standards, FedRAMP requirements, and NIST 800-53 controls.
"""

__version__ = "2.0.0"
__author__ = "Security Engineering Team"

from .core import SecurityAuditPlatform
from .config import AuditConfig
from .exceptions import *

__all__ = [
    "SecurityAuditPlatform",
    "AuditConfig",
]