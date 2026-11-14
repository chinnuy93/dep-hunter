class DepHunterError(Exception):
    """Base error for expected, user-facing failures."""


class ConfigError(DepHunterError):
    """Invalid configuration or scope file."""


class ScopeViolation(DepHunterError):
    """A URL or action falls outside the declared authorization scope."""


class PolicyViolation(DepHunterError):
    """An operation is forbidden by the tool's passive-only policy."""


class NetworkError(DepHunterError):
    """A network operation failed after retries."""


class RegistryError(DepHunterError):
    """A registry response could not be interpreted safely."""


class ExtractionError(DepHunterError):
    """A manifest could not be parsed; callers record a warning."""
