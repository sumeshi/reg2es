"""Raw Registry values use user-defined mappings and report Bulk conflicts."""

from copy import deepcopy
from pathlib import Path
import runpy
import struct
from tempfile import TemporaryDirectory

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

    run_native_time_cases(client, transport, new_index, stored_documents, document_id)


def native_time_documents():
    """Read plugin time fields through actual python-registry, retaining raw values."""
    from reg2es import reg2json

    artifact = runpy.run_path(str(Path(__file__).with_name("artifact_fixture.py")))
    shutdown, userassist = [], []
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for label, filetime in (
            ("valid", artifact["FILETIME"]),
            ("zero", 0),
            ("invalid", 2**64 - 1),
        ):
            destination = root / label / "SYSTEM"
            destination.parent.mkdir()
            tree = [
                ("Select", [], [("Current", 4, struct.pack("<I", 1))]),
                (
                    "ControlSet001",
                    [
                        (
                            "Control",
                            [
                                (
                                    "Windows",
                                    [],
                                    [("ShutdownTime", 3, struct.pack("<Q", filetime))],
                                )
                            ],
                            [],
                        )
                    ],
                    [],
                ),
            ]
            destination.write_bytes(artifact["make_hive"](tree=tree))
            records = reg2json(str(destination), plugin_names=["lastshutdown"])
            assert len(records) == 1
            assert (
                records[0]["reg2es"]["value_data"] == struct.pack("<Q", filetime).hex()
            )
            shutdown.extend(records)

        values = []
        for index, milliseconds in enumerate((60000, 1234, 0)):
            raw = bytearray(72)
            struct.pack_into("<III", raw, 4, 1, 1, milliseconds)
            struct.pack_into("<Q", raw, 60, artifact["FILETIME"])
            values.append((f"rknzcyr{index}.rkr", 3, bytes(raw)))
        tree = [("Count", [], values)]
        for name in reversed(
            [
                "Software",
                "Microsoft",
                "Windows",
                "CurrentVersion",
                "Explorer",
                "UserAssist",
                "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            ]
        ):
            tree = [(name, tree, [])]
        destination = root / "NTUSER.DAT"
        destination.write_bytes(artifact["make_hive"](tree=tree))
        userassist = reg2json(str(destination), plugin_names=["userassist"])
        assert len(userassist) == len(values)
        assert [document["reg2es"]["value_data"] for document in userassist] == [
            raw.hex() for _name, _kind, raw in values
        ]
    return shutdown, userassist


def run_native_time_cases(client, transport, new_index, stored_documents, document_id):
    shutdown, userassist = native_time_documents()
    assert [record["reg2es"]["custom"]["LastShutdownTime"] for record in shutdown] == [
        "2024-01-01T00:00:00.123456Z",
        None,
        None,
    ]
    for record in shutdown[1:]:
        assert (
            record["reg2es"]["timestamp"]["fallback_reason"]
            == "invalid_shutdowntime_filetime"
        )
    for label, records in (
        ("date-first", shutdown),
        ("null-first", shutdown[1:] + shutdown[:1]),
    ):
        original = deepcopy(records)
        index = new_index(label)
        client.indices.create(index=index, mappings=MAPPINGS)
        # Separate Bulks exercise dynamic date detection in either arrival order.
        assert transport.bulk_indice(records[:1], index) == (1, [])
        assert transport.bulk_indice(records[1:], index) == (len(records) - 1, [])
        assert records == original
        assert stored_documents(client, index) == {
            document_id(record): record for record in original
        }
        field = "reg2es.custom.LastShutdownTime"
        properties = client.indices.get_mapping(index=index)[index]["mappings"][
            "properties"
        ]
        assert (
            properties["reg2es"]["properties"]["custom"]["properties"][
                "LastShutdownTime"
            ]["type"]
            == "date"
        )
        assert (
            client.count(index=index, query={"exists": {"field": field}})["count"] == 1
        )
        assert (
            client.count(
                index=index,
                query={"range": {field: {"gte": "2024-01-01", "lt": "2024-01-02"}}},
            )["count"]
            == 1
        )

    assert [
        record["reg2es"]["custom"]["userassist"]["focus_time_secs"]
        for record in userassist
    ] == [60.0, 1.234, 0.0]
    mappings = deepcopy(MAPPINGS)
    mappings["properties"]["reg2es"]["properties"]["custom"] = {
        "properties": {
            "userassist": {"properties": {"focus_time_secs": {"type": "double"}}}
        }
    }
    index = new_index("userassist-seconds")
    # The operator owns this mapping; the transport only uses Bulk.
    client.indices.create(index=index, mappings=mappings)
    original = deepcopy(userassist)
    assert transport.bulk_indice(userassist, index) == (len(userassist), [])
    assert userassist == original
    assert stored_documents(client, index) == {
        document_id(record): record for record in original
    }
    field = "reg2es.custom.userassist.focus_time_secs"
    for seconds in (60.0, 1.234, 0.0):
        assert client.count(index=index, query={"term": {field: seconds}})["count"] == 1
    assert (
        client.count(index=index, query={"range": {field: {"gt": 1.233, "lt": 1.235}}})[
            "count"
        ]
        == 1
    )
