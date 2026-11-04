"""promptwall - prompt-injection firewall for browsing agents."""
from .firewall import Decision, Firewall
from .models import Finding, HiddenSpan, ScanResult, Severity
from .sanitize import sanitize_text
from .scanner import Scanner

__version__ = "0.2.0"
__all__ = ["Firewall", "Decision", "Scanner", "ScanResult", "Finding", "HiddenSpan",
           "Severity", "sanitize_text"]