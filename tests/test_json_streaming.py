"""JSON arrays stay compatible while writing only the current chunk."""

import importlib
from pathlib import Path

import orjson
import pytest

from reg2es.models.Reg2es import PartialExtractionError
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter


MODULE = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")


def document(plugin, value):
    return {"reg2es": {"plugin": {"name": plugin}}, "value": value}


def install_runner(monkeypatch, chunks, *, errors=()):
    state = []

    class Runner:
        def __init__(self, **kwargs):
            self.successful_records = 0
            self.errors = list(errors)

        def gen_records(self):
            try:
                for chunk in chunks():
                    self.successful_records += len(chunk)
                    yield chunk
            finally:
                state.append("generator closed")

        def close(self):
            state.append("parser closed")

    monkeypatch.setattr(MODULE, "Reg2es", Runner)
    return state


def presenter_for(tmp_path, *, split, quiet=True):
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"original evidence")
    output_dir = tmp_path / "out"
    output_dir.mkdir(exist_ok=True)
    presenter = Reg2jsonPresenter(
        source,
        str(output_dir if split else output_dir / "records.json"),
        split=split,
        is_quiet=quiet,
    )
    return presenter, source, output_dir


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("quiet", [False, True])
def test_json_is_written_before_requesting_the_next_chunk(
    tmp_path, monkeypatch, split, quiet
):
    presenter, source, output_dir = presenter_for(tmp_path, split=split, quiet=quiet)
    destinations = (
        [output_dir / "services.json", output_dir / "compname.json"]
        if split else [output_dir / "records.json"]
    )
    for destination in destinations:
        destination.write_bytes(b"previous output")
    first = [document("services", "first"), document("compname", "second")]

    def chunks():
        yield first
        temporary = list(output_dir.glob(".*.tmp"))
        assert len(temporary) == len(destinations)
        payloads = [path.read_text(encoding="utf-8") for path in temporary]
        assert all(payload.startswith("[\n") for payload in payloads)
        assert any('"first"' in payload for payload in payloads)
        assert any('"second"' in payload for payload in payloads)
        assert all(path.read_bytes() == b"previous output" for path in destinations)
        yield [document("services", "third")]

    state = install_runner(monkeypatch, chunks)
    monkeypatch.setattr(presenter, "reg2json", lambda: pytest.fail("retained all records"))

    paths = presenter.export_json()

    assert paths == destinations
    assert state == ["generator closed", "parser closed"]
    assert source.read_bytes() == b"original evidence"
    assert not list(output_dir.glob(".*.tmp"))


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("newline", [None, "\r\n"])
@pytest.mark.parametrize(
    "records",
    [
        [],
        [{}],
        [
            document("services", {"text": "端末\nnext\r\n", "list": [None, True, 3]}),
            document("compname", {"empty": {}, "array": []}),
            document("services", "last"),
            {"reg2es": {"plugin": {"name": ""}}, "ignored_when_split": True},
        ],
    ],
)
def test_json_matches_the_previous_whole_array_text_writer(
    tmp_path, monkeypatch, split, newline, records
):
    presenter, source, output_dir = presenter_for(tmp_path, split=split)
    install_runner(monkeypatch, lambda: iter([[], records[:2], [], records[2:], []]))
    if newline is not None:
        original_open = Path.open

        def platform_open(path, mode="r", *args, **kwargs):
            if mode == "a" and path.suffix == ".tmp":
                kwargs["newline"] = newline
            return original_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", platform_open)

    paths = presenter.export_json()

    if split:
        expected = {}
        for record in records:
            name = record.get("reg2es", {}).get("plugin", {}).get("name")
            if isinstance(name, str) and name:
                expected.setdefault(output_dir / f"{name}.json", []).append(record)
    else:
        expected = {output_dir / "records.json": records}
    assert paths == list(expected)
    expected_path = tmp_path / "expected.json"
    for path, values in expected.items():
        # The original writer used text mode with the platform newline policy.
        expected_path.write_text(
            orjson.dumps(values, option=orjson.OPT_INDENT_2).decode("utf-8"),
            encoding="utf-8", newline=newline,
        )
        assert path.read_bytes() == expected_path.read_bytes()
    assert source.read_bytes() == b"original evidence"
    assert not list(output_dir.glob(".*.tmp"))


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("failure", ["parser", "serialization", "writer"])
def test_late_failure_closes_resources_and_keeps_all_existing_outputs(
    tmp_path, monkeypatch, split, failure
):
    presenter, source, output_dir = presenter_for(tmp_path, split=split)
    destinations = (
        [output_dir / "services.json", output_dir / "compname.json"]
        if split else [output_dir / "records.json"]
    )
    for path in destinations:
        path.write_bytes(b"previous output")

    def chunks():
        yield [document("services", "first")]
        if failure == "parser":
            raise ValueError("late parser failure")
        yield [document("compname", object() if failure == "serialization" else "stop")]
        pytest.fail("continued after output failure")

    state = install_runner(monkeypatch, chunks)
    if failure == "writer":
        original_open = Path.open

        class FailingWriter:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.handle.close()

            def write(self, payload):
                if '"stop"' in payload:
                    raise OSError("late write failure")
                return self.handle.write(payload)

        def failing_open(path, mode="r", *args, **kwargs):
            handle = original_open(path, mode, *args, **kwargs)
            return FailingWriter(handle) if mode == "a" and path.suffix == ".tmp" else handle

        monkeypatch.setattr(Path, "open", failing_open)

    error = {"parser": ValueError, "serialization": TypeError, "writer": OSError}[failure]
    with pytest.raises(error):
        presenter.export_json()

    assert all(path.read_bytes() == b"previous output" for path in destinations)
    assert state == ["generator closed", "parser closed"]
    assert source.read_bytes() == b"original evidence"
    assert not list(output_dir.glob(".*.tmp"))


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_partial_and_all_failed_exports_keep_their_publication_policy(
    tmp_path, monkeypatch, split, partial
):
    presenter, source, output_dir = presenter_for(tmp_path, split=split)
    destination = output_dir / ("services.json" if split else "records.json")
    destination.write_bytes(b"previous output")
    errors = [{"hive_path": str(source), "error": "unreadable value"}]
    records = [document("services", "recovered")] if partial else []
    state = install_runner(monkeypatch, lambda: iter([records]), errors=errors)

    if partial:
        assert presenter.export_json() == [destination]
        assert orjson.loads(destination.read_bytes()) == records
    else:
        with pytest.raises(PartialExtractionError):
            presenter.export_json()
        assert destination.read_bytes() == b"previous output"

    assert presenter.errors == errors
    assert presenter.failed_records == 1
    assert presenter.successful_records == len(records)
    assert state == ["generator closed", "parser closed"]
    assert source.read_bytes() == b"original evidence"
    assert not list(output_dir.glob(".*.tmp"))
