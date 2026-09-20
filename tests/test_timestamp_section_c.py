"""Section C regression: plugins with no reliable artifact time keep LastWrite.

These plugins do not parse an intrinsic event time, so every document must
fall back to the key LastWrite and record an explicit fallback reason, while
preserving the original LastWrite under reg2es.timestamps.
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path

import pytest

from reg2es.models.Reg2es import plugin_result_to_document

SECTION_C_PLUGINS = [
    "antivirus",
    "auditpol",
    "compname",
    "env",
    "filedialogmru",
    "gpo",
    "keyboard",
    "lastloggedon",
    "localgroups",
    "mndmru",
    "mstscmru",
    "portproxy",
    "printer_history",
    "printer_ports",
    "proxy",
    "putty",
    "rdphint",
    "recentdocs",
    "run",
    "runmru",
    "services",
    "srum",
    "sysinternals",
    "timezone",
    "usersids",
    "version",
]

HIVE_TO_SAMPLE = {
    "SYSTEM": "SYSTEM",
    "SOFTWARE": "SOFTWARE",
    "NTUSER.DAT": "sumeshi_NTUSER.dat",
    "SAM": "SAM",
    "SECURITY": "SECURITY",
}


def _plugin_reghives(name: str) -> list[str]:
    module = importlib.import_module(f"reg2es.plugins.{name}")
    hive = module.Plugin.__REGHIVE__
    if isinstance(hive, str):
        return [hive]
    return list(hive)


def _hives_available(hives: list[str]) -> bool:
    sample_dir = Path(__file__).resolve().parents[1] / "sample"
    for hive in hives:
        if hive == "ALL":
            continue
        sample = sample_dir / HIVE_TO_SAMPLE.get(hive, hive)
        if not sample.exists():
            return False
    return True


def test_section_c_plugins_do_not_set_an_event_time() -> None:
    """None of the Section C plugins declares an artifact time in source."""
    for name in SECTION_C_PLUGINS:
        source = Path(f"src/reg2es/plugins/{name}.py").read_text(encoding="utf-8")
        assert "set_event_time" not in source, f"{name} unexpectedly sets an event time"


@pytest.mark.skipif(
    not _hives_available(["SYSTEM", "SOFTWARE", "NTUSER.DAT", "SAM", "SECURITY"]),
    reason="real sample hives are not checked out",
)
def test_section_c_plugins_fall_back_to_last_write_on_real_hives() -> None:
    """Every Section C document keeps LastWrite with an explicit reason."""
    sample_dir = Path(__file__).resolve().parents[1] / "sample"
    failures = []

    for name in SECTION_C_PLUGINS:
        module = importlib.import_module(f"reg2es.plugins.{name}")
        for hive in _plugin_reghives(name):
            if hive == "ALL":
                continue
            sample_file = sample_dir / HIVE_TO_SAMPLE[hive]
            if not sample_file.exists():
                continue
            from Registry import Registry

            reg = Registry.Registry(str(sample_file))
            plugin = module.Plugin(reg, logging.getLogger(name), hive, str(sample_file))
            try:
                results = list(plugin.run())
            except Exception as exc:  # pragma: no cover - diagnostics only
                failures.append(f"{name}/{hive}: raised {exc!r}")
                continue
            if not results:
                continue
            for result in results:
                document = plugin_result_to_document(
                    result, name, hive, str(sample_file)
                )
                timestamp = document["reg2es"]["timestamp"]
                if timestamp["source"] != "key.last_write":
                    failures.append(
                        f"{name}/{hive}: source={timestamp['source']!r} "
                        f"for {result.path!r}"
                    )
                if timestamp["fallback_reason"] is None:
                    failures.append(
                        f"{name}/{hive}: missing fallback_reason for {result.path!r}"
                    )
                if "modified" not in document["reg2es"]["timestamps"]:
                    failures.append(
                        f"{name}/{hive}: LastWrite not preserved for {result.path!r}"
                    )

    assert not failures, "\n".join(failures[:50])
