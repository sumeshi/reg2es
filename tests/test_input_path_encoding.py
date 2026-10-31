"""Native hives at POSIX byte paths remain serializable and distinguishable."""

import os
from pathlib import Path
import subprocess
import sys

import orjson
import pytest

from reg2es import reg2json
from reg2es.models.ElasticsearchUtils import ElasticsearchUtils
from reg2es.models.Reg2es import _display_filesystem_path, plugin_result_to_document
from reg2es.plugins import PluginResult
from tests.test_other_plugin_recovery import sz, write_hive

POSIX_BYTES = pytest.mark.skipif(
    os.name != "posix", reason="Non-UTF-8 filesystem byte names require POSIX"
)


def input_hives(tmp_path):
    sources = []
    for directory in ("a-good", os.fsdecode(b"z-bad-\xff"), r"z-bad-\udcff"):
        folder = tmp_path / directory
        folder.mkdir()
        sources.append(
            write_hive(
                folder,
                "NTUSER.DAT",
                [
                    (
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        [sz("example", "cmd.exe")],
                    )
                ],
            )
        )
    return sources


def assert_path_documents(documents, sources):
    assert len(documents) == 3
    assert all(doc["reg2es"]["value_data"] == "cmd.exe" for doc in documents)
    by_path = {
        doc["reg2es"]["source"].get("file_path_bytes_hex", "normal"): doc
        for doc in documents
        if "file_path_bytes_hex" in doc["reg2es"]["source"]
    }
    raw_path = os.fsencode(sources[1].resolve()).hex()
    assert set(by_path) == {raw_path}
    escaped = by_path[raw_path]
    assert os.fsdecode(bytes.fromhex(raw_path)) == str(sources[1].resolve())
    assert escaped["log"]["file"]["path"] == str(sources[2].resolve())
    # A real backslash sequence has the same display text, but a different ID.
    literal = next(
        doc
        for doc in documents
        if doc["log"]["file"]["path"] == str(sources[2].resolve())
        and "file_path_bytes_hex" not in doc["reg2es"]["source"]
    )
    assert ElasticsearchUtils.calc_hash(None, escaped) != ElasticsearchUtils.calc_hash(
        None, literal
    )
    assert len({ElasticsearchUtils.calc_hash(None, doc) for doc in documents}) == 3
    orjson.dumps(documents)


@POSIX_BYTES
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_api_preserves_filesystem_bytes(tmp_path, chunk_size):
    sources = input_hives(tmp_path)
    original = [source.read_bytes() for source in sources]

    documents = reg2json(sources, plugin_names=["run"], chunk_size=chunk_size)

    assert_path_documents(documents, sources)
    assert [source.read_bytes() for source in sources] == original


@POSIX_BYTES
@pytest.mark.parametrize("output_format", ["json", "jsonl"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_cli_commits_all_records_at_filesystem_byte_paths(
    tmp_path, output_format, chunk_size
):
    sources = input_hives(tmp_path)
    original = [source.read_bytes() for source in sources]
    output = tmp_path / ("records." + output_format)
    output.write_bytes(b"previous output")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "reg2es.views.Reg2jsonView",
            *map(str, sources),
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

    assert completed.returncode == 0, completed.stderr
    data = output.read_bytes()
    documents = (
        orjson.loads(data)
        if output_format == "json"
        else [orjson.loads(line) for line in data.splitlines()]
    )
    assert_path_documents(documents, sources)
    assert [source.read_bytes() for source in sources] == original
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("path", ["-", "ascii", "日本語", r"literal-\udcff"])
def test_ordinary_path_text_has_no_original_metadata(path):
    assert _display_filesystem_path(path) == (path, None)


@POSIX_BYTES
def test_recovery_log_paths_preserve_original_bytes_without_mutating_metadata(tmp_path):
    original_path = str(tmp_path / os.fsdecode(b"hive-\xff.LOG1"))
    normal_path = str(tmp_path / "hive.LOG2")
    recovery = {
        "applied": True,
        "method": "python-registry.RegistryLog",
        "logs": [original_path, normal_path],
    }
    result = PluginResult()

    document = plugin_result_to_document(
        result, "run", "NTUSER.DAT", "-", recovery=recovery
    )

    rendered = document["reg2es"]["recovery"]
    assert rendered["logs"] == [
        original_path.encode("utf-8", "backslashreplace").decode("utf-8"),
        normal_path,
    ]
    assert rendered["log_path_bytes_hex"] == [os.fsencode(original_path).hex(), None]
    assert recovery["logs"] == [original_path, normal_path]
    assert "log_path_bytes_hex" not in recovery
    assert "file_path_bytes_hex" not in document["reg2es"]["source"]
    orjson.dumps(document)
