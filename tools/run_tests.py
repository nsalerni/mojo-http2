#!/usr/bin/env python3
"""Run every test executable in test/ (pixi's task shell has no loops).

h2 depends on mojo-net; its src/ path is resolved the same way as
tools/dep_src.py: $MOJO_DEPS_DIR, .deps/ (fetch_deps.py), or a sibling
../mojo-net checkout.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def net_src() -> str:
    candidates = []
    if os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(os.environ["MOJO_DEPS_DIR"]) / "mojo-net" / "src")
    candidates.append(ROOT / ".deps" / "mojo-net" / "src")
    candidates.append(ROOT.parent / "mojo-net" / "src")
    for c in candidates:
        if c.is_dir():
            return str(c)
    sys.exit("dependency 'mojo-net' not found; run `python3 tools/fetch_deps.py`")


def main() -> int:
    net = net_src()
    failed = 0
    for t in sorted((ROOT / "test").glob("test_*.mojo")):
        r = subprocess.run(
            ["mojo", "run", "-I", "src", "-I", net, "-I", "test",
             str(t.relative_to(ROOT))],
            cwd=ROOT,
        )
        print(("PASS " if r.returncode == 0 else "FAIL ") + t.name)
        failed += r.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
