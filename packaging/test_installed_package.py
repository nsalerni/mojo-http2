#!/usr/bin/env python3
"""Build mojo-http2 and test it in an isolated package environment."""

import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MOJO_NET = ROOT / ".deps" / "mojo-net"
MOJO_TLS = ROOT / ".deps" / "mojo-tls"
CHANNELS = ["https://conda.modular.com/max", "conda-forge"]
RATTLER_BUILD = "rattler-build>=0.30,<0.31"
RATTLER_INDEX = "rattler-index>=0.30,<0.31"
PACKAGE_BUILD_TIMEOUT_SECONDS = 20 * 60
PACKAGE_TEST_TIMEOUT_SECONDS = 5 * 60


def run(command: list[str], timeout_seconds: int) -> None:
    environment = os.environ.copy()
    environment.pop("PIXI_PROJECT_MANIFEST", None)
    subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=True,
        timeout=timeout_seconds,
    )


def platform_subdir() -> str:
    machine = platform.machine().lower()
    if platform.system() == "Darwin" and machine == "arm64":
        return "osx-arm64"
    if platform.system() == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-64"
    if platform.system() == "Linux" and machine in {"aarch64", "arm64"}:
        return "linux-aarch64"
    raise RuntimeError(f"unsupported package platform: {platform.system()} {machine}")


def add_channels(command: list[str], local_channel: Path) -> None:
    command.extend(["--channel", local_channel.as_uri()])
    for channel in CHANNELS:
        command.extend(["--channel", channel])


def index_channel(channel: Path) -> None:
    run(
        [
            "pixi",
            "exec",
            "--spec",
            RATTLER_INDEX,
            "rattler-index",
            "fs",
            str(channel),
        ],
        PACKAGE_BUILD_TIMEOUT_SECONDS,
    )


def one_package(output: Path, pattern: str, name: str) -> Path:
    packages = sorted(output.rglob(pattern))
    if len(packages) != 1:
        raise RuntimeError(f"expected one {name} package, found {len(packages)}")
    return packages[0]


def main() -> None:
    for dependency in (MOJO_NET, MOJO_TLS):
        if not (dependency / "recipe" / "recipe.yaml").is_file():
            raise RuntimeError("run python3 tools/fetch_deps.py before package-test")

    with tempfile.TemporaryDirectory(prefix="mojo-http2-package-") as temp:
        work = Path(temp)
        channel = work / "channel"
        channel_subdir = channel / platform_subdir()
        channel_subdir.mkdir(parents=True)
        (channel / "noarch").mkdir()

        net_output = work / "mojo-net"
        run(
            [
                "pixi",
                "publish",
                "--clean",
                "--path",
                str(MOJO_NET),
                "--target-dir",
                str(net_output),
            ],
            PACKAGE_BUILD_TIMEOUT_SECONDS,
        )
        net_package = one_package(
            net_output, "mojo-net-0.2.2-*.conda", "mojo-net 0.2.2"
        )
        shutil.copy2(net_package, channel_subdir / net_package.name)
        index_channel(channel)

        tls_output = work / "mojo-tls"
        tls_command = [
            "pixi",
            "exec",
            "--spec",
            RATTLER_BUILD,
            "rattler-build",
            "build",
            "--recipe",
            str(MOJO_TLS / "recipe" / "recipe.yaml"),
            "--output-dir",
            str(tls_output),
            "--no-test",
        ]
        add_channels(tls_command, channel)
        run(tls_command, PACKAGE_BUILD_TIMEOUT_SECONDS)
        tls_package = one_package(
            tls_output, "mojo-tls-0.3.0-*.conda", "mojo-tls 0.3.0"
        )
        shutil.copy2(tls_package, channel_subdir / tls_package.name)
        index_channel(channel)

        output = work / "mojo-http2"
        build_command = [
            "pixi",
            "exec",
            "--spec",
            RATTLER_BUILD,
            "rattler-build",
            "build",
            "--recipe",
            str(ROOT / "recipe" / "recipe.yaml"),
            "--output-dir",
            str(output),
            "--no-test",
        ]
        add_channels(build_command, channel)
        run(build_command, PACKAGE_BUILD_TIMEOUT_SECONDS)

        package = one_package(
            output, "mojo-http2-0.2.4-*.conda", "mojo-http2 0.2.4"
        )

        test_command = [
            "pixi",
            "exec",
            "--spec",
            RATTLER_BUILD,
            "rattler-build",
            "test",
            "--package-file",
            str(package),
        ]
        add_channels(test_command, channel)
        run(test_command, PACKAGE_TEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    main()
