"""Scanner check plugins."""

from autodit.scanner.checks.auth import AuthCheck
from autodit.scanner.checks.data import DataExposureCheck
from autodit.scanner.checks.rate import RateLimitCheck

__all__ = ["AuthCheck", "DataExposureCheck", "RateLimitCheck"]
