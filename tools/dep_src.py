#!/usr/bin/env python3
"""Print the src/ path of a source dependency (used by pixi tasks).

Resolution order: $MOJO_DEPS_DIR/<name>/src, then .deps/<name>/src
(populated by tools/fetch_deps.py in a standalone checkout), then a
sibling ../<name>/src (monorepo or side-by-side clones).
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    name = sys.argv[1]
    candidates = []
    if os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(os.environ["MOJO_DEPS_DIR"]) / name / "src")
    candidates.append(ROOT / ".deps" / name / "src")
    candidates.append(ROOT.parent / name / "src")
    for c in candidates:
        if c.is_dir():
            print(c)
            return 0
    print(
        f"dependency '{name}' not found; run `python3 tools/fetch_deps.py`",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
