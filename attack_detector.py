from __future__ import annotations

import sys

from hids.cli import main


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.", file=sys.stderr)
        raise SystemExit(130)
