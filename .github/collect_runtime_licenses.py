"""Collect license material for CI-built standalone release archives."""

from __future__ import annotations

import argparse
import shutil
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

STANDALONE_DISTRIBUTIONS = (
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
        and (filename.startswith("license") or filename.startswith("notice"))
    )


def _runtime_distributions():
    """Return the distributions included by the standalone builds."""
    packages = []
    for package_name in STANDALONE_DISTRIBUTIONS:
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


def collect(output_dir: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(project_root / "LICENSE", output_dir / "reg2es-MIT.txt")
    shutil.copyfile(
        project_root / "LICENSES" / "Apache-2.0.txt",
        output_dir / "Apache-2.0.txt",
    )

    manifest = [
        "# License and Third-Party Notices",
        "",
        "## reg2es",
        "",
        "The original reg2es code is licensed under the MIT License.",
        "See reg2es-MIT.txt.",
        "",
        "## Bundled regrippy-derived code",
        "",
        "The bundled registry plugins are derived from airbus-cert/regrippy",
        "commit 32e3ab3243415b7bf46f812d933f4d29862e3046 and are licensed",
        "under Apache License 2.0. See Apache-2.0.txt.",
        "The integrated Shim Cache parser retains its original copyright:",
        "Andrew Davis, andrew.davis@mandiant.com, Mandiant 2012.",
        "",
        "## Runtime dependency licenses",
        "",
        "The standalone binaries include the following Python distributions.",
        "Their copied license and NOTICE files are stored in this directory.",
        "",
    ]

    for package in _runtime_distributions():
        metadata = package.metadata
        package_name = metadata.get("Name", package.name)
        license_name = (
            metadata.get("License-Expression")
            or metadata.get("License")
            or "See bundled license files"
        )
        copied_files = []
        for package_path in package.files or []:
            if not _is_license_file(str(package_path)):
                continue
            source = Path(package.locate_file(package_path))
            target_name = f"{package_name}-{source.name}"
            shutil.copyfile(source, output_dir / target_name)
            copied_files.append(target_name)

        manifest.extend(
            [
                f"## {metadata.get('Name', package_name)} {package.version}",
                "",
                f"- Project: {_project_url(metadata)}",
                f"- License: {license_name}",
            ]
        )
        if copied_files:
            manifest.append(f"- Files: {', '.join(sorted(copied_files))}")
        elif "Apache" in license_name:
            manifest.append("- File: Apache-2.0.txt (shared copy)")
        else:
            raise RuntimeError(
                f"no license file found for runtime dependency: {package_name}"
            )
        manifest.append("")

    (output_dir / "README.md").write_text(
        "\n".join(manifest),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    collect(args.output_dir)


if __name__ == "__main__":
    main()
