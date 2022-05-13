class WarrantException(Exception):
    """Base class for all Warrant exceptions"""

class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""


class TokenVerificationException(WarrantException):
    """Raised when token verification fails."""

class SoftwareTokenException(WarrantException):
    """Raised when user is required to verify software token."""
    def __init__(self, device_name):
        self.device_name = device_name

    def __str__(self):
        if self.device_name:
            return self.device_name
        else:
            return "Device Name not set"
    
class SMSMFAException(WarrantException):
    """Raised when user is required to verify authentication via SMS."""
