"""Raw registry evidence must not depend on Elasticsearch insertion order."""

from copy import deepcopy
import importlib
from unittest.mock import MagicMock

from elastic_transport import ApiResponseMeta, NodeConfig
from elasticsearch import BadRequestError, NotFoundError
import pytest


module = importlib.import_module("reg2es.models.ElasticsearchUtils")
RAW_MAPPING = {"type": "object", "enabled": False}
MISSING = object()


def index_info(raw=MISSING, aliases=None):
    properties = {} if raw is MISSING else {"value_data": raw}
    return {
        "aliases": aliases or {},
        "mappings": {"properties": {"reg2es": {"properties": properties}}},
    }


def api_error(error_type, status, kind):
    return error_type(
        kind,
        ApiResponseMeta(
            status=status, http_version="1.1", headers={}, duration=0,
            node=NodeConfig("http", "localhost", 9200),
        ),
        {"error": {"type": kind}},
    )


@pytest.fixture
def client(monkeypatch):
    connection = MagicMock()
    connection.indices.get.return_value = {"target": index_info(RAW_MAPPING)}
    monkeypatch.setattr(module, "Elasticsearch", lambda **kwargs: connection)
    client = module.ElasticsearchUtils("localhost", 9200, "http", "", "")
    client.sent = []

    def bulk(_connection, actions, **kwargs):
        batch = list(actions)
        client.sent.extend(batch)
        return len(batch), []

    monkeypatch.setattr(module, "bulk", bulk)
    return client


@pytest.mark.parametrize("reverse", [False, True])
def test_raw_values_and_ids_survive_mixed_types_without_mapping_writes(client, reverse):
    values = [
        1704067200, "Windows 11 Pro", 2**64 - 1, None,
        ["first", "second"], {"nested": [1, "two", None]}, "", [],
    ]
    if reverse:
        values.reverse()
    records = [{"reg2es": {"value_data": value}} for value in values]
    before = deepcopy(records)

    assert client.bulk_indice(iter(records), "target", "preserve-evidence") == (8, [])

    assert records == before
    assert [action["_source"] for action in client.sent] == before
    assert [action["_id"] for action in client.sent] == [client.calc_hash(r) for r in before]
    assert all(action["pipeline"] == "preserve-evidence" for action in client.sent)
    client.es.indices.put_mapping.assert_not_called()
    client.es.indices.create.assert_not_called()
    client.es.indices.get.assert_called_once()
    client.bulk_indice(records[:1], "target")
    client.es.indices.get.assert_called_once()


def test_new_index_is_created_with_disabled_raw_mapping_before_bulk(client):
    client.es.indices.get.side_effect = api_error(
        NotFoundError, 404, "index_not_found_exception"
    )
    assert client.bulk_indice([{"reg2es": {"value_data": 1}}], "target") == (1, [])
    client.es.indices.create.assert_called_once_with(
        index="target",
        mappings={"properties": {"reg2es": {"properties": {"value_data": RAW_MAPPING}}}},
    )
    client.es.indices.put_mapping.assert_not_called()


def test_create_race_rechecks_the_existing_index_instead_of_overwriting_it(client):
    client.es.indices.get.side_effect = [
        api_error(NotFoundError, 404, "index_not_found_exception"),
        {"target": index_info(RAW_MAPPING)},
    ]
    client.es.indices.create.side_effect = api_error(
        BadRequestError, 400, "resource_already_exists_exception"
    )
    assert client.bulk_indice([{"reg2es": {"value_data": 1}}], "target") == (1, [])
    client.es.indices.put_mapping.assert_not_called()


@pytest.mark.parametrize("existing_type", ["long", "text", "object"])
def test_incompatible_raw_mapping_stops_without_changing_existing_data(client, existing_type):
    client.es.indices.get.return_value = {"target": index_info({"type": existing_type})}
    with pytest.raises(Exception, match="incompatible reg2es.value_data.*Use a new index"):
        client.bulk_indice([{"reg2es": {"value_data": 1}}], "target")
    assert client.sent == []
    client.es.indices.put_mapping.assert_not_called()
    client.es.indices.create.assert_not_called()


def test_missing_raw_mapping_is_added_without_replacing_other_properties(client):
    client.es.indices.get.return_value = {"target": index_info()}
    client.bulk_indice([{"reg2es": {"value_data": None}}], "target")
    client.es.indices.put_mapping.assert_called_once_with(
        index="target",
        properties={"reg2es": {"properties": {"value_data": RAW_MAPPING}}},
    )


def test_alias_prepares_only_its_write_index_and_rechecks_after_rollover(client):
    client.es.indices.get.side_effect = [
        {
            "old": index_info({"type": "long"}, {"target": {"is_write_index": False}}),
            "current": index_info(aliases={"target": {"is_write_index": True}}),
        },
        {"next": index_info(aliases={"target": {"is_write_index": True}})},
    ]
    record = {"reg2es": {"value_data": 1}}
    client.bulk_indice([record], "target")
    client.bulk_indice([record], "target")
    assert [call.kwargs["index"] for call in client.es.indices.put_mapping.call_args_list] == [
        "current", "next"
    ]
    assert [action["_index"] for action in client.sent] == ["target", "target"]


def test_ambiguous_alias_does_not_change_any_index(client):
    client.es.indices.get.return_value = {
        "one": index_info(aliases={"target": {}}),
        "two": index_info(aliases={"target": {}}),
    }
    with pytest.raises(Exception, match="Cannot determine one write index"):
        client.bulk_indice([{"reg2es": {"value_data": 1}}], "target")
    assert client.sent == []
    client.es.indices.put_mapping.assert_not_called()


def test_key_only_records_do_not_require_index_metadata_permissions(client):
    records = [{"reg2es": {"plugin": {"name": "regtime"}}}]
    assert client.bulk_indice(records, "target") == (1, [])
    client.es.indices.get.assert_not_called()


def test_metadata_permission_failure_is_reported_before_sending_raw_values(client):
    client.es.indices.get.side_effect = PermissionError("view_index_metadata required")
    with pytest.raises(Exception, match="view_index_metadata required"):
        client.bulk_indice([{"reg2es": {"value_data": 1}}], "target")
    assert client.sent == []
    client.es.indices.create.assert_not_called()
    client.es.indices.put_mapping.assert_not_called()
