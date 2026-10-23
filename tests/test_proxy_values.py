"""Read the Windows ProxyEnable value through the real registry parser."""

from pathlib import Path
import runpy
import struct

import pytest

from reg2es import reg2json


@pytest.mark.parametrize("enabled", [0, 1, None])
def test_native_proxy_enable_uses_the_windows_value_name(tmp_path, enabled):
    fixture_path = (
        Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py"
    )
    values = [("ProxyServer", 1, "127.0.0.1:8080\0".encode("utf-16le"))]
    if enabled is not None:
        values.append(("ProxyEnable", 4, struct.pack("<I", enabled)))
    # A nonstandard similarly named value must not override the real setting.
    values.append(("ProxyEnabled", 4, struct.pack("<I", 1 if enabled != 1 else 0)))
    settings = ("Internet Settings", [], values)
    current = ("CurrentVersion", [settings], [])
    windows = ("Windows", [current], [])
    microsoft = ("Microsoft", [windows], [])
    tree = [("Software", [microsoft], [])]
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(runpy.run_path(str(fixture_path))["make_hive"](tree=tree))
    before = source.read_bytes()

    documents = reg2json(str(source), plugin_names=["proxy"])

    assert len(documents) == 2
    proxy = next(doc for doc in documents if doc["reg2es"]["custom"]["type"] == "proxy")
    assert proxy["reg2es"]["custom"]["enabled"] is (enabled == 1)
    assert proxy["reg2es"]["custom"]["proxy"] == "127.0.0.1:8080"
    assert source.read_bytes() == before
