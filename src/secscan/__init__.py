"""SecScan SAST engine: secrets, entropy, API paths, and quality gates."""

from .rules import DEFAULT_RULES, Rule
from .scanner import (
    Finding,
    ScanReport,
    calculate_entropy,
    load_rules,
    mask_secret,
    scan_path,
    scan_text,
)
from .version import __version__

__all__ = [
    "__version__",
    "DEFAULT_RULES",
    "Finding",
    "Rule",
    "ScanReport",
    "calculate_entropy",
    "load_rules",
    "mask_secret",
    "scan_path",
    "scan_text",
]
