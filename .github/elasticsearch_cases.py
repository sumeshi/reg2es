"""Raw Registry values use user-defined mappings and report Bulk conflicts."""

from copy import deepcopy

RAW_MAPPING = {"type": "object", "enabled": False}
MAPPINGS = {"properties": {"reg2es": {"properties": {"value_data": RAW_MAPPING}}}}


def expected_source(document):
    return deepcopy(document)


def assert_native_documents(documents, mode):
    assert mode is None and len(documents) == 9
    values = {
        record["registry"]["value"]: record["reg2es"]["value_data"]
        for record in documents
    }
    assert values["InstallDate"] == 1704067200
    assert values["ProductName"] == "Windows 11 Pro"
    assert values["MaximumQword"] == 2**64 - 1
    assert values["EmptyString"] == ""
    assert values["MultiString"][:2] == ["first", "second"]
    assert all(
        isinstance(value, str)
        for document in documents
        for value in document["registry"]["data"].get("strings", [])
    )


def raw_mapping(client, index):
    return client.indices.get_mapping(index=index)[index]["mappings"]["properties"][
        "reg2es"
    ]["properties"]["value_data"]


def run_extra_cases(client, transport, new_index, stored_documents, document_id):
    values = [
        1704067200,
        "Windows 11 Pro",
        2**64 - 1,
        None,
        True,
        False,
        [],
        {},
        [1, "two", None],
        {"nested": [1, "two"]},
    ]
    documents = [{"reg2es": {"value_data": value}} for value in values]
    for label, records in (
        ("integer-first", documents),
        ("string-first", documents[1:] + documents[:1]),
    ):
        original = deepcopy(records)
        index = new_index(label)
        client.indices.create(index=index, mappings=MAPPINGS)
        # Separate writes exercise both insertion orders with a predefined mapping.
        assert transport.bulk_indice(records[:1], index) == (1, [])
        assert transport.bulk_indice(records[1:], index) == (len(records) - 1, [])
        assert stored_documents(client, index) == {
            document_id(record): record for record in original
        }
        assert records == original and raw_mapping(client, index) == RAW_MAPPING
        assert (
            client.count(index=index, query={"exists": {"field": "reg2es.value_data"}})[
                "count"
            ]
            == 0
        )

    conflicting = new_index("existing-long")
    client.indices.create(
        index=conflicting,
        mappings={
            "properties": {
                "reg2es": {"properties": {"value_data": {"type": "long"}}},
            }
        },
    )
    sentinel = {"reg2es": {"value_data": 7}, "marker": "keep"}
    client.index(index=conflicting, id="sentinel", document=sentinel, refresh=True)
    records = [
        {"reg2es": {"value_data": 8}},
        {"reg2es": {"value_data": "not-an-integer"}},
        {"reg2es": {"value_data": {"nested": [1, "two"]}}},
    ]
    original = deepcopy(records)
    success, failures = transport.bulk_indice(records, conflicting)
    assert success == 1 and len(failures) == 2
    assert {item["index"]["_id"] for item in failures} == {
        document_id(record) for record in records[1:]
    }
    assert all(item["index"]["status"] == 400 for item in failures)
    assert all(item["index"]["error"]["reason"] for item in failures)
    assert records == original
    expected_conflicting = {
        "sentinel": sentinel,
        document_id(records[0]): records[0],
    }
    assert stored_documents(client, conflicting) == expected_conflicting
    assert raw_mapping(client, conflicting) == {"type": "long"}

    write_index = new_index("alias-write")
    client.indices.create(index=write_index, mappings=MAPPINGS)
    alias = write_index + "-alias"
    client.indices.update_aliases(
        actions=[
            {"add": {"index": conflicting, "alias": alias, "is_write_index": False}},
            {"add": {"index": write_index, "alias": alias, "is_write_index": True}},
        ]
    )
    assert transport.bulk_indice(documents, alias) == (len(documents), [])
    assert stored_documents(client, write_index) == {
        document_id(record): record for record in documents
    }
    assert raw_mapping(client, write_index) == RAW_MAPPING
    assert raw_mapping(client, conflicting) == {"type": "long"}
    assert stored_documents(client, conflicting) == expected_conflicting
