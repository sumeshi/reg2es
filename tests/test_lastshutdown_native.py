"""Parsed shutdown times stay date-or-null without losing source bytes."""

from pathlib import Path
import runpy
import struct

import orjson
import pytest

from reg2es import reg2json
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter

FIXTURE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (struct.pack("<Q", 133485408001234560), "2024-01-01T00:00:00.123456Z"),
        (bytes(8), None),
        (b"\xff" * 8, None),
        (b"short", None),
    ],
)
@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_native_shutdown_preserves_raw_and_exports_date_or_null(
    tmp_path, raw, expected, output_format
):
    tree = [
        ("Select", [], [("Current", 4, struct.pack("<I", 1))]),
        (
            "ControlSet001",
            [("Control", [("Windows", [], [("ShutdownTime", 3, raw)])], [])],
            [],
        ),
    ]
    source = tmp_path / "SYSTEM"
    original = FIXTURE["make_hive"](tree=tree)
    source.write_bytes(original)
    output = tmp_path / ("shutdown." + output_format)

    documents = reg2json(str(source), plugin_names=["lastshutdown"])
    presenter = Reg2jsonPresenter(
        source,
        output_path=str(output),
        plugin_names=["lastshutdown"],
        output_format=output_format,
        is_quiet=True,
    )
    assert presenter.export_json() == [output]
    assert presenter.failed_records == 0

    assert len(documents) == 1
    document = documents[0]
    exported = orjson.loads(output.read_bytes())
    assert (exported if output_format == "jsonl" else exported[0]) == document
    assert document["reg2es"]["custom"]["LastShutdownTime"] == expected
    assert document["reg2es"]["value_data"] == raw.hex()
    timestamp = document["reg2es"]["timestamp"]
    if expected is None:
        assert timestamp["source"] == "key.last_write"
        assert timestamp["fallback_reason"] == "invalid_shutdowntime_filetime"
    else:
        assert timestamp["source"] == "ShutdownTime"
        assert timestamp["fallback_reason"] is None
        assert document["@timestamp"] == expected
    assert source.read_bytes() == original
