"""Public errors raised by the scanner."""


class Error(Exception):
    """Base error for SecScan."""


class InputError(Error):
    """Invalid path, rules file, or CLI option."""
