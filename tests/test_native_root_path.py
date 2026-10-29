"""ECS paths use the actual native root name without rewriting source paths."""

from pathlib import Path
import runpy

import pytest
from Registry import Registry

from reg2es import reg2json

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)["make_hive"]


@pytest.mark.parametrize("hive", ["NTUSER.DAT", "SOFTWARE"])
@pytest.mark.parametrize(
    "root_name", ["ROOT", "REAL", "CMI-CreateHive{1234}", "\\REAL", "REAL\\"]
)
def test_native_root_names_produce_logical_ecs_paths(tmp_path, hive, root_name):
    parts = ["Microsoft", "Windows", "CurrentVersion", "Run"]
    if hive == "NTUSER.DAT":
        parts.insert(0, "Software")
    tree = []
    for part in reversed(parts):
        tree = [
            (
                part,
                tree,
                [("example", 1, "test.exe\0".encode("utf-16le"))] if not tree else [],
            )
        ]
    source = tmp_path / hive
    source.write_bytes(MAKE_HIVE(tree=tree, root_name=root_name))
    before = source.read_bytes()
    native = Registry.Registry(str(source))
    key = native.open("\\".join(parts))
    assert native.root().name() == root_name
    documents = reg2json(source, plugin_names=["run"])
    assert len(documents) == 1
    document = documents[0]
    expected = "\\".join(parts)
    if hive == "SOFTWARE":
        expected = "SOFTWARE\\" + expected
    assert document["registry"]["key"] == expected
    prefix = "HKCU" if hive == "NTUSER.DAT" else "HKLM"
    assert document["registry"]["path"] == prefix + "\\" + expected + "\\example"
    assert document["reg2es"]["source"]["key_path"] == key.path()
    assert source.read_bytes() == before


def test_native_child_named_root_is_retained(tmp_path):
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(MAKE_HIVE(tree=[("ROOT", [], [])], root_name="REAL"))
    docs = reg2json(source, plugin_names=["regtime"])
    assert [doc["registry"]["key"] for doc in docs] == ["", "ROOT"]
    assert [doc["reg2es"]["source"]["key_path"] for doc in docs] == [
        "REAL",
        "REAL\\ROOT",
    ]
