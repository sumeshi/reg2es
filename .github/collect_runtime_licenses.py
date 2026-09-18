"""Collect license material for CI-built standalone release archives."""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
import sys
import sysconfig

STANDALONE_DISTRIBUTIONS = (
    "sniffio",
    "idna",
    "anyio",
    "typing-extensions",
    "certifi",
    "elasticsearch",
    "elastic-transport",
    "orjson",
    "python-dateutil",
    "python-registry",
    "six",
    "tqdm",
    "urllib3",
)


def _is_license_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    filename = normalized.rsplit("/", 1)[-1]
    return ".dist-info/licenses/" in normalized or (
        ".dist-info/" in normalized
        and filename.startswith(("license", "licence", "notice", "copying"))
    )


def _runtime_distributions():
    """Return the distributions included by the standalone builds."""
    names = STANDALONE_DISTRIBUTIONS
    if sys.platform == "win32":
        names += ("colorama",)
    packages = []
    for package_name in names:
        try:
            packages.append(distribution(package_name))
        except PackageNotFoundError as exc:
            raise RuntimeError(
                f"runtime dependency is not installed: {package_name}"
            ) from exc
    return packages


def _project_url(metadata) -> str:
    for entry in metadata.get_all("Project-URL") or []:
        label, separator, url = entry.partition(",")
        if separator and label.strip().lower() in {
            "source",
            "source code",
            "repository",
            "homepage",
        }:
            return url.strip()
    return metadata.get("Home-page") or "Not specified"


def _python_license() -> str:
    # Read the bundled interpreter license, never the project license.
    for directory in (
        Path(sys.base_prefix),
        Path(sysconfig.get_path("stdlib")),
    ):
        for filename in ("LICENSE.txt", "LICENSE"):
            path = directory / filename
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                if text.strip():
                    return text
    raise RuntimeError(
        "Python runtime license not found in the build interpreter"
    )


def collect(output_file: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    sections = [
        "License and Third-Party Notices",
        "Bundled plugins are derived from airbus-cert/regrippy v2.0.3 "
        "(commit 32e3ab3243415b7bf46f812d933f4d29862e3046), Apache-2.0. "
        "The integrated Shim Cache parser is by Andrew Davis, "
        "andrew.davis@mandiant.com, Copyright 2012 Mandiant.",
    ]

    def append_text(title: str, text: str) -> None:
        sections.append(f"{title}\n{'=' * len(title)}\n\n{text.rstrip()}")

    append_text(
        "reg2es — MIT", (project_root / "LICENSE").read_text(encoding="utf-8")
    )
    append_text(
        "Apache License 2.0",
        (project_root / "LICENSES" / "Apache-2.0.txt").read_text(
            encoding="utf-8"
        ),
    )

    append_text(f"Python {sys.version.split()[0]}", _python_license())

    for package in _runtime_distributions():
        metadata = package.metadata
        package_name = metadata.get("Name", package.name)
        materials = []
        for package_path in sorted(package.files or [], key=str):
            if _is_license_file(str(package_path)):
                source = Path(package.locate_file(package_path))
                materials.append(
                    f"--- {package_path} ---\n"
                    + source.read_text(encoding="utf-8").rstrip()
                )
        if not materials:
            if (
                package_name == "python-registry"
                and package.version == "1.3.1"
            ):
                materials.append(
                    "Copyright 2011, 2012 Willi Ballenthin "
                    "<william.ballenthin@mandiant.com> while at Mandiant.\n"
                    "See Apache License 2.0 above. Attribution from "
                    "upstream Registry/Registry.py and "
                    "Registry/RegistryParse.py headers."
                )
            else:
                raise RuntimeError(
                    "no license file found for runtime dependency: "
                    f"{package_name}"
                )
        append_text(
            f"{package_name} {package.version}",
            f"Project: {_project_url(metadata)}\n\n" + "\n\n".join(materials),
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n\n".join(sections) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_file", type=Path)
    args = parser.parse_args()
    collect(args.output_file)


if __name__ == "__main__":
    main()
