#!/usr/bin/env python3
"""Run every test executable in test/ (pixi's task shell has no loops).

h2 depends on mojo-net and mojo-tls; their src/ paths are resolved the
same way as tools/dep_src.py: $MOJO_DEPS_DIR, .deps/ (fetch_deps.py), or
sibling package checkouts.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def dep_src(name: str) -> str:
    candidates = []
    if os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(os.environ["MOJO_DEPS_DIR"]) / name / "src")
    candidates.append(ROOT / ".deps" / name / "src")
    candidates.append(ROOT.parent / name / "src")
    for c in candidates:
        if c.is_dir():
            return str(c)
    sys.exit(f"dependency '{name}' not found; run `python3 tools/fetch_deps.py`")


def main() -> int:
    net = dep_src("mojo-net")
    tls = dep_src("mojo-tls")
    failed = 0
    for t in sorted((ROOT / "test").glob("test_*.mojo")):
        try:
            r = subprocess.run(
                ["mojo", "run", "-I", "src", "-I", net, "-I", tls, "-I", "test",
                 str(t.relative_to(ROOT))],
                cwd=ROOT, timeout=600,
            )
            ok = r.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT {t.name} (600s)")
            ok = False
        print(("PASS " if ok else "FAIL ") + t.name)
        failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
