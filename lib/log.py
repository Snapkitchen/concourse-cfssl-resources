# stdlib
import sys
from typing import Any


# =============================================================================
# log
# =============================================================================

def log(value: Any) -> None:
    print(value, file=sys.stderr)
