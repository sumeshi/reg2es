"""Unreadable native Office key names do not hide readable versions."""

from pathlib import Path
import runpy
import struct

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github/artifact_fixture.py")
)["make_hive"]
OFFICE = r"Software\Microsoft\Office"
VERSIONS = ("15.0", "16.0", "17.0")


def office_hive(tmp_path, versions=VERSIONS, programs=("Word",)):
    raw = bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFABDEB301FFFFFF7F")
    children = []
    for version in versions:
        applications = []
        for program in programs:
            leaf = ("TrustRecords", [], [(program + ".docm", 3, raw)])
            for name in ("Trusted Documents", "Security", program):
                leaf = (name, [leaf], [])
            applications.append(leaf)
        children.append((version, applications, []))
    tree = ("Office", children, [])
    for name in ("Microsoft", "Software"):
        tree = (name, [tree], [])
    path = tmp_path / "NTUSER.DAT"
    path.write_bytes(MAKE_HIVE(tree=[tree]))
    return path


def corrupt_version_name(path, name):
    key = Registry.Registry(str(path)).open(OFFICE + "\\" + name)
    offset = key._nkrecord.offset()
    raw = bytearray(path.read_bytes())
    flags = struct.unpack_from("<H", raw, offset + 2)[0]
    struct.pack_into("<H", raw, offset + 2, flags & ~0x20)
    struct.pack_into("<H", raw, offset + 0x48, 2)
    raw[offset + 0x4C : offset + 0x4E] = b"\x00\xd8"
    path.write_bytes(raw)


@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize("bad_version", VERSIONS)
def test_unreadable_version_keeps_readable_siblings(tmp_path, chunk_size, bad_version):
    path = office_hive(tmp_path)
    baseline = reg2json(path, plugin_names=["office_macros"])
    assert len(baseline) == 3
    expected = [
        doc for doc in baseline if f"\\{bad_version}\\" not in doc["registry"]["key"]
    ]
    corrupt_version_name(path, bad_version)
    original = path.read_bytes()
    keys = Registry.Registry(str(path)).open(OFFICE).subkeys()
    with pytest.raises(UnicodeDecodeError):
        keys[VERSIONS.index(bad_version)].name()

    runner = Reg2es(path, plugin_names=["office_macros"], chunk_size=chunk_size)
    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == expected
    assert runner.successful_records == 2
    assert runner.failed_records == 1
    assert runner.errors[0]["plugin"] == "office_macros"
    assert runner.errors[0]["stage"] == "subkeys"
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(path, plugin_names=["office_macros"], chunk_size=chunk_size)
    assert caught.value.records == expected
    assert len(caught.value.diagnostics) == 1
    assert path.read_bytes() == original


@pytest.mark.parametrize("error_policy", ["continue", "raise"])
def test_only_unreadable_version_is_reported(tmp_path, error_policy):
    path = office_hive(tmp_path, versions=("16.0",))
    corrupt_version_name(path, "16.0")
    original = path.read_bytes()
    runner = Reg2es(path, plugin_names=["office_macros"], error_policy=error_policy)

    if error_policy == "raise":
        with pytest.raises(UnicodeDecodeError):
            list(runner.gen_records())
    else:
        assert list(runner.gen_records()) == []
    assert runner.successful_records == 0
    assert runner.failed_records == 1
    assert len(runner.errors) == 1
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    assert path.read_bytes() == original


def test_strict_records_once_after_a_readable_version(tmp_path):
    path = office_hive(tmp_path)
    corrupt_version_name(path, "16.0")
    runner = Reg2es(
        path, plugin_names=["office_macros"], error_policy="raise", chunk_size=1
    )
    chunks = runner.gen_records()

    assert "\\15.0\\" in next(chunks)[0]["registry"]["key"]
    with pytest.raises(UnicodeDecodeError):
        next(chunks)
    assert len(runner.errors) == 1
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "subkeys"
    assert list(chunks) == []


@pytest.mark.parametrize("program", ["Word", "Excel", "PowerPoint"])
def test_normal_program_and_nonversion_keys(tmp_path, program):
    # Non-version Office keys and absent applications are ordinary absence.
    path = office_hive(tmp_path, versions=("Common", "16.0"), programs=(program,))
    runner = Reg2es(path, plugin_names=["office_macros"])
    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert len(documents) == 1
    assert documents[0]["registry"]["key"].endswith(
        f"16.0\\{program}\\Security\\Trusted Documents\\TrustRecords"
    )
    assert documents[0]["@timestamp"] == "2024-04-23T22:03:00Z"
    assert runner.failed_records == 0 and runner.errors == []
