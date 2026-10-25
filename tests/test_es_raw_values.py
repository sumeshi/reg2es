"""Registry evidence uses Bulk without inspecting or managing mappings."""

from copy import deepcopy
from hashlib import sha1
import importlib
from unittest.mock import Mock

import orjson
import pytest

from reg2es.models.ElasticsearchAdapter import ElasticsearchAdapter

module = importlib.import_module("reg2es.models.ElasticsearchUtils")


@pytest.fixture
def client(monkeypatch):
    # Metadata, index, alias and template APIs are deliberately unavailable.
    connection = Mock(spec_set=["bulk", "close"])
    monkeypatch.setattr(module, "Elasticsearch", lambda **kwargs: connection)
    helper = module.ElasticsearchUtils("localhost", 9200, "http", "", "")
    helper.sent = []

    def bulk(connection, actions, **kwargs):
        assert kwargs == {"raise_on_error": False, "stats_only": False}
        batch = list(actions)
        helper.sent.extend(batch)
        connection.bulk(operations=batch)
        return len(batch), []

    monkeypatch.setattr(module, "bulk", bulk)
    return helper


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("pipeline", ["", "preserve-evidence"])
def test_mixed_values_and_ids_survive_using_only_bulk(client, reverse, pipeline):
    values = [
        1704067200,
        "Windows 11 Pro",
        2**64 - 1,
        None,
        True,
        False,
        1.5,
        ["first", "second"],
        {"nested": [1, "two", None]},
        "",
        [],
        {},
    ]
    if reverse:
        values.reverse()
    records = [{"reg2es": {"value_data": value}} for value in values]
    original = deepcopy(records)

    assert client.bulk_indice(iter(records), "target", pipeline) == (len(records), [])
    assert records == original
    assert [action["_source"] for action in client.sent] == original
    for action, record in zip(client.sent, records):
        assert action["_source"] is record
        assert (
            action["_id"]
            == sha1(orjson.dumps(record, option=orjson.OPT_SORT_KEYS)).hexdigest()
        )
        assert action["_index"] == "target"
        assert action.get("pipeline", "") == pipeline
    assert [call[0] for call in client.es.mock_calls] == ["bulk"]

    assert client.bulk_indice(records[:1], "target") == (1, [])
    assert [call[0] for call in client.es.mock_calls] == ["bulk", "bulk"]


@pytest.mark.parametrize(
    "documents",
    [[], [{}], [{"reg2es": {"plugin": {"name": "regtime"}}}]],
    ids=["empty", "no-reg2es", "key-only"],
)
def test_adapter_passes_records_and_sources_through_without_client_calls(
    client, documents
):
    adapter = ElasticsearchAdapter(client.es)
    records = iter(documents)
    assert adapter.prepare_records(records, "target") is records
    for document in records:
        assert adapter.prepare_source(document) is document
    assert client.es.mock_calls == []


def test_mapping_conflicts_are_returned_as_bulk_item_failures(client, monkeypatch):
    record = {"reg2es": {"value_data": {"nested": [1, "two"]}}}
    failure = {
        "index": {
            "_id": client.calc_hash(record),
            "status": 400,
            "error": {
                "type": "document_parsing_exception",
                "reason": "mapping conflict",
            },
        }
    }

    def bulk(connection, actions, **kwargs):
        connection.bulk(operations=list(actions))
        return 0, [failure]

    monkeypatch.setattr(module, "bulk", bulk)
    assert client.bulk_indice([record], "target") == (0, [failure])
    assert [call[0] for call in client.es.mock_calls] == ["bulk"]
