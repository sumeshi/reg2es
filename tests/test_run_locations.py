"""Native startup extraction includes the 32-bit and user policy locations."""

from hashlib import sha1
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from tests.test_other_plugin_recovery import sz, write_hive
from tests.test_task_name_recovery import corrupt_name

LOCATIONS = {
    "SOFTWARE": [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ],
    "NTUSER.DAT": [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ],
}


def startup_hive(tmp_path, hive, *, bad_root=False, invalid_data=False):
    paths = [("Unrelated", [])] if bad_root else []
    for index, path in enumerate(LOCATIONS[hive]):
        value = (
            (str(index), 7, b"a\0b\0c")
            if invalid_data and index == 3
            else sz(str(index), f"startup-{index}.exe")
        )
        paths.append((path, [value]))
    return write_hive(tmp_path, hive, paths)


@pytest.mark.parametrize("hive", LOCATIONS)
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_all_supported_startup_locations_preserve_paths_and_values(
    tmp_path, hive, chunk_size
):
    source = startup_hive(tmp_path, hive)
    original = source.read_bytes()

    documents = reg2json(source, plugin_names=["run"], chunk_size=chunk_size)

    assert len(documents) == len(LOCATIONS[hive])
    assert [doc["reg2es"]["source"]["key_path"] for doc in documents] == [
        "ROOT\\" + path for path in LOCATIONS[hive]
    ]
    assert [doc["reg2es"]["value_data"] for doc in documents] == [
        f"startup-{i}.exe" for i in range(len(documents))
    ]
    ids = {
        sha1(orjson.dumps(doc, option=orjson.OPT_SORT_KEYS)).hexdigest()
        for doc in documents
    }
    assert len(ids) == len(documents)
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_bad_value_in_new_location_keeps_later_32bit_locations(tmp_path, chunk_size):
    source = startup_hive(tmp_path, "SOFTWARE")
    baseline = reg2json(source, plugin_names=["run"])
    startup_hive(tmp_path, "SOFTWARE", invalid_data=True)
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == baseline[:3] + baseline[4:]
    assert runner.failed_records == 1
    assert runner.errors[0]["key"].endswith(LOCATIONS["SOFTWARE"][3])
    assert source.read_bytes() == before


@pytest.mark.parametrize("hive", LOCATIONS)
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_root_name_failure_recovers_all_startup_locations(tmp_path, hive, chunk_size):
    source = startup_hive(tmp_path, hive, bad_root=True)
    baseline = reg2json(source, plugin_names=["run"])
    corrupt_name(source, key="Unrelated")
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == baseline
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["run"], chunk_size=chunk_size)
    assert caught.value.records == baseline
    assert len(caught.value.diagnostics) == 1
    assert source.read_bytes() == before


@pytest.mark.parametrize("hive", LOCATIONS)
def test_run_strict_open_failure_is_reported_once(tmp_path, hive):
    source = startup_hive(tmp_path, hive, bad_root=True)
    corrupt_name(source, key="Unrelated")
    runner = Reg2es(source, plugin_names=["run"], error_policy="raise")

    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())

    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"


@pytest.mark.parametrize("hive", LOCATIONS)
@pytest.mark.parametrize("output_format", ["json", "jsonl"])
@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize("damaged", [False, True])
def test_cli_recovers_and_commits_all_supported_startup_records(
    tmp_path, hive, output_format, chunk_size, damaged
):
    source = startup_hive(tmp_path, hive, bad_root=damaged)
    baseline = reg2json(source, plugin_names=["run"])
    if damaged:
        corrupt_name(source, key="Unrelated")
    before = source.read_bytes()
    output = tmp_path / ("output." + output_format)
    output.write_bytes(b"previous output")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "reg2es.views.Reg2jsonView",
            str(source),
            "--quiet",
            "--plugin",
            "run",
            "--size",
            str(chunk_size),
            "--format",
            output_format,
            "--output-file",
            str(output),
        ],
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
    )

    assert result.returncode == int(damaged), result.stderr
    data = output.read_bytes()
    documents = (
        orjson.loads(data)
        if output_format == "json"
        else [orjson.loads(line) for line in data.splitlines()]
    )
    assert documents == baseline
    if damaged:
        assert b"1 extraction failures" in result.stderr
    assert source.read_bytes() == before
    assert not list(tmp_path.glob(".*.tmp"))
