#!/usr/bin/env python3
"""Build mojo-tls test assets inside the mojo-http2 pixi environment."""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def dep_root(name: str) -> Path:
    candidates: list[Path] = []
    if os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(os.environ["MOJO_DEPS_DIR"]) / name)
    candidates.append(ROOT / ".deps" / name)
    candidates.append(ROOT.parent / name)
    for candidate in candidates:
        if (candidate / "src").is_dir():
            return candidate
    sys.exit(
        f"dependency '{name}' not found; run `python3 tools/fetch_deps.py`"
    )


def main() -> int:
    tls = dep_root("mojo-tls")
    subprocess.run(["bash", str(tls / "tools" / "build_shim.sh")], check=True)
    subprocess.run(
        ["bash", str(tls / "tools" / "gen_test_certs.sh")], check=True
    )

    build = ROOT / "build"
    certs = build / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    shim = "libmojotls.dylib" if platform.system() == "Darwin" else "libmojotls.so"
    shutil.copy2(tls / "build" / shim, build / shim)
    for source in (tls / "build" / "certs").iterdir():
        if source.is_file():
            shutil.copy2(source, certs / source.name)
    print(f"prepared TLS shim and certificates in {build}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
