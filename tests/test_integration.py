"""Major contracts between the public API, CLI, presenters, and Elasticsearch."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson
import pytest

import reg2es as package
from reg2es.models.ElasticsearchUtils import ElasticsearchUtils
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter


@pytest.mark.parametrize("command", ["reg2es", "reg2json"])
@pytest.mark.parametrize("option", ["--help", "--version"])
def test_cli_metadata_commands(run_cli, command, option) -> None:
    result = run_cli(command, [option])
    assert result.returncode == 0


@pytest.mark.parametrize("command", ["reg2es", "reg2json"])
def test_cli_lists_all_plugins_without_input(run_cli, command) -> None:
    result = run_cli(command, ["--list-plugins"])
    assert result.returncode == 0
    assert len(result.stdout.strip().splitlines()) == 41


@pytest.mark.parametrize("command", ["reg2es", "reg2json"])
def test_cli_rejects_missing_input_and_unknown_plugin(run_cli, command) -> None:
    missing = run_cli(command, [])
    assert missing.returncode == 2

    unknown = run_cli(command, ["--plugin", "not-a-plugin", "SYSTEM"])
    assert unknown.returncode == 2
    assert "invalid choice" in unknown.stderr


def test_elasticsearch_bulk_action_and_tls_configuration() -> None:
    with patch("reg2es.models.ElasticsearchUtils.Elasticsearch") as client:
        utils = ElasticsearchUtils(
            "localhost",
            9200,
            "https",
            "user",
            "secret",
            verify_certs=False,
        )
    assert client.call_args.kwargs == {
        "hosts": ["https://localhost:9200"],
        "verify_certs": False,
        "basic_auth": ("user", "secret"),
    }

    utils.es = MagicMock()
    with patch(
        "reg2es.models.ElasticsearchUtils.bulk",
        return_value=(1, []),
    ) as bulk:
        assert utils.bulk_indice([{"id": 1}], "registry", "pipeline") == (
            1,
            [],
        )
    action = list(bulk.call_args.args[1])[0]
    assert action["_index"] == "registry"
    assert action["_source"] == {"id": 1}
    assert action["pipeline"] == "pipeline"


def test_json_and_es_presenters_consume_the_same_nonempty_chunks() -> None:
    chunks = [[{"id": 1}], [{"id": 2}, {"id": 3}]]
    runners = []

    class FakeRunner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            runners.append(self)

        def gen_records(self):
            yield from chunks

        def close(self):
            self.closed = True

    json_presenter = Reg2jsonPresenter(
        ["/host/SYSTEM"],
        is_quiet=True,
        plugin_names=["services"],
        additional_tags=["case-1"],
    )
    es_presenter = Reg2esPresenter(
        [Path("/host/SYSTEM")],
        is_quiet=True,
        plugin_names=["services"],
        additional_tags=["case-1"],
    )

    with patch("reg2es.presenters.Reg2jsonPresenter.Reg2es", FakeRunner):
        json_documents = json_presenter.reg2json()
    with patch("reg2es.presenters.Reg2esPresenter.Reg2es", FakeRunner):
        es_documents = [
            document
            for chunk in es_presenter.reg2es()
            for document in chunk
        ]

    assert json_documents == es_documents == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert all(runner.closed for runner in runners)
    assert all(
        runner.kwargs["additional_tags"] == ["case-1"]
        for runner in runners
    )


def test_json_presenter_split_writes_one_file_per_plugin(tmp_path: Path) -> None:
    first_input = tmp_path / "SYSTEM"
    second_input = tmp_path / "SOFTWARE"

    class FakeRunner:
        def __init__(self, **_kwargs):
            pass

        def gen_records(self):
            yield [
                {"id": 1, "reg2es": {"plugin": {"name": "services"}}},
                {"id": 2, "reg2es": {"plugin": {"name": "compname"}}},
                {"id": 3, "reg2es": {"plugin": {"name": "services"}}},
            ]

        def close(self):
            pass

    output_directory = tmp_path / "json"
    presenter = Reg2jsonPresenter(
        [first_input, second_input],
        output_path=str(output_directory),
        is_quiet=True,
        split=True,
    )

    with patch("reg2es.presenters.Reg2jsonPresenter.Reg2es", FakeRunner):
        output_paths = presenter.export_json()

    assert [path.name for path in output_paths] == ["services.json", "compname.json"]
    assert orjson.loads(output_paths[0].read_bytes()) == [
        {"id": 1, "reg2es": {"plugin": {"name": "services"}}},
        {"id": 3, "reg2es": {"plugin": {"name": "services"}}},
    ]
    assert orjson.loads(output_paths[1].read_bytes()) == [
        {"id": 2, "reg2es": {"plugin": {"name": "compname"}}}
    ]


def test_bulk_import_reports_failures_instead_of_succeeding() -> None:
    presenter = Reg2esPresenter([Path("/host/SYSTEM")], is_quiet=True)
    presenter.reg2es = MagicMock(return_value=iter([[{"id": 1}]]))

    client = MagicMock()
    client.bulk_indice.return_value = (0, [{"index": {"error": "failed"}}])
    with patch(
        "reg2es.presenters.Reg2esPresenter.ElasticsearchUtils",
        return_value=client,
    ), pytest.raises(RuntimeError, match="failed to index 1"):
        presenter.bulk_import()


def test_public_api_accepts_single_path_and_propagates_options() -> None:
    expected_path = Path("/host/SYSTEM").resolve()
    presenter = MagicMock()
    with patch(
        "reg2es.presenters.Reg2esPresenter.Reg2esPresenter",
        return_value=presenter,
    ) as presenter_class:
        package.reg2es(
            "/host/SYSTEM",
            plugin_names=["services"],
            additional_tags=["case-1"],
            verify_certs=False,
        )

    kwargs = presenter_class.call_args.kwargs
    assert kwargs["input_paths"] == [expected_path]
    assert kwargs["plugin_names"] == ["services"]
    assert kwargs["additional_tags"] == ["case-1"]
    assert kwargs["verify_certs"] is False
    presenter.bulk_import.assert_called_once_with()


def test_public_reg2json_accepts_single_path_and_adds_tags() -> None:
    document = {"tags": ["registry", "case-1"]}
    expected_path = Path("/host/SYSTEM").resolve()

    class FakeRunner:
        def __init__(self, **kwargs):
            assert kwargs["input_paths"] == [expected_path]
            assert kwargs["additional_tags"] == ["case-1"]

        def gen_records(self):
            yield [document]

        def close(self):
            pass

    with patch.object(package, "Reg2es", FakeRunner):
        assert package.reg2json(
            "/host/SYSTEM",
            additional_tags=["case-1"],
        ) == [document]
