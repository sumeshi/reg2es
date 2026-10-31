"""UserAssist duration units and original bytes through the native registry parser."""

import base64
import codecs
from pathlib import Path
import runpy
import struct

import orjson
import pytest

from reg2es import reg2json
from reg2es.plugins.userassist import UAObject

FIXTURE = Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py"
GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
USERASSIST = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
FILETIME = 133485408001234560


@pytest.mark.parametrize(
    "milliseconds,seconds",
    [(0, 0.0), (1, 0.001), (60000, 60.0), (60001, 60.001), (2**32 - 1, 4294967.295)],
)
def test_native_focus_duration_uses_seconds_and_retains_original_bytes(
    tmp_path, milliseconds, seconds
):
    raw = bytearray(72)
    struct.pack_into("<III", raw, 4, 7, 3, milliseconds)
    struct.pack_into("<Q", raw, 60, FILETIME)
    value_name = codecs.encode("example.exe", "rot13")
    tree = [(GUID, [("Count", [], [(value_name, 3, bytes(raw))])], [])]
    for name in reversed(USERASSIST.split("\\")):
        tree = [(name, tree, [])]
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(runpy.run_path(str(FIXTURE))["make_hive"](tree=tree))
    original = source.read_bytes()

    documents = reg2json(str(source), plugin_names=["userassist"])

    assert len(documents) == 1
    document = documents[0]
    ua = document["reg2es"]["custom"]["userassist"]
    assert ua == {
        "name": "example.exe",
        "number_of_execs": 7,
        "focus_count": 3,
        "focus_time_secs": seconds,
        "last_exec": 1704067200.123456,
    }
    assert type(ua["focus_time_secs"]) is float
    assert document["reg2es"]["value_data"] == bytes(raw).hex()
    assert document["registry"]["data"]["type"] == "REG_BINARY"
    assert base64.b64decode(document["registry"]["data"]["bytes"]) == bytes(raw)
    assert document["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    assert orjson.loads(orjson.dumps(document))["reg2es"]["custom"]["userassist"] == ua
    assert source.read_bytes() == original


def test_xp_has_no_focus_duration_field_in_its_binary_record():
    raw = struct.pack("<IIQ", 1, 8, FILETIME)

    assert UAObject("rknzcyr.rkr", raw).focus_time_secs == 0
