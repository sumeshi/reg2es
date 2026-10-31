"""Raw Registry values use user-defined mappings and report Bulk conflicts."""

from copy import deepcopy
import os
from pathlib import Path
import runpy
import struct
from tempfile import TemporaryDirectory
from urllib.parse import unquote, urlsplit

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
    run_native_run_case(client, new_index, stored_documents, document_id)
    run_wide_recovery_cases(client, new_index, stored_documents, document_id)
    run_native_path_case(client, transport, new_index, stored_documents, document_id)


def native_path_documents(directory):
    """Parse normal, undecodable-byte and literal-escape paths with native REGF."""
    from reg2es import reg2json

    artifact = runpy.run_path(str(Path(__file__).with_name("artifact_fixture.py")))
    tree = [("Run", [], [("example", 1, "cmd.exe\0".encode("utf-16le"))])]
    for name in reversed(r"Software\Microsoft\Windows\CurrentVersion".split("\\")):
        tree = [(name, tree, [])]
    sources = []
    for name in ("normal", os.fsdecode(b"path-\xff"), r"path-\udcff"):
        folder = directory / name
        folder.mkdir()
        source = folder / "NTUSER.DAT"
        source.write_bytes(artifact["make_hive"](tree=tree))
        sources.append(source)
    original = [source.read_bytes() for source in sources]
    documents = reg2json(sources, plugin_names=["run"], chunk_size=1)
    assert len(documents) == 3
    assert [source.read_bytes() for source in sources] == original
    return sources, documents


def run_native_path_case(client, transport, new_index, stored_documents, document_id):
    if os.name != "posix":
        return
    with TemporaryDirectory() as directory:
        sources, documents = native_path_documents(Path(directory))
        expected = {document_id(record): record for record in documents}
        assert len(expected) == 3
        index = new_index("filesystem-byte-path")
        mappings = deepcopy(MAPPINGS)
        mappings["properties"]["log"] = {
            "properties": {"file": {"properties": {"path": {"type": "keyword"}}}}
        }
        mappings["properties"]["reg2es"]["properties"]["source"] = {
            "properties": {"file_path_bytes_hex": {"type": "keyword"}}
        }
        client.indices.create(index=index, mappings=mappings)
        assert transport.bulk_indice(documents, index) == (3, [])
        assert stored_documents(client, index) == expected
        raw_path = os.fsencode(sources[1].resolve()).hex()
        assert (
            client.count(
                index=index,
                query={"term": {"reg2es.source.file_path_bytes_hex": raw_path}},
            )["count"]
            == 1
        )
        # The two paths share display text; original bytes keep their IDs distinct.
        assert (
            client.count(
                index=index,
                query={"term": {"log.file.path": str(sources[2].resolve())}},
            )["count"]
            == 2
        )


def native_run_recovery(directory):
    """Recover healthy startup values around a native Registry decoding error."""
    from reg2es import PartialExtractionError, reg2json

    artifact = runpy.run_path(str(Path(__file__).with_name("artifact_fixture.py")))
    tree = [
        (
            "Run",
            [],
            [
                ("a", 1, "first.exe\0".encode("utf-16le")),
                ("b", 7, b"a\0b\0c"),
                ("c", 1, "last.exe\0".encode("utf-16le")),
            ],
        ),
        ("RunOnce", [], [("d", 1, "later.exe\0".encode("utf-16le"))]),
    ]
    for name in reversed(r"Software\Microsoft\Windows\CurrentVersion".split("\\")):
        tree = [(name, tree, [])]
    source = directory / "NTUSER.DAT"
    source.write_bytes(artifact["make_hive"](tree=tree))
    try:
        reg2json(source, plugin_names=["run"], chunk_size=1)
    except PartialExtractionError as error:
        recovered, diagnostics = error.records, error.diagnostics
    else:
        raise AssertionError("An unreadable Run value must report partial extraction")
    assert [record["registry"]["value"] for record in recovered] == ["a", "c", "d"]
    assert len(diagnostics) == 1
    assert diagnostics[0]["value"] == "b"
    assert (
        diagnostics[0]["key"] == r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    assert diagnostics[0]["stage"] == "record"
    assert diagnostics[0]["error"].startswith("UnicodeDecodeError:")
    return source, recovered, diagnostics


def run_native_run_case(client, new_index, stored_documents, document_id):
    from reg2es import PartialExtractionError, reg2es

    address = urlsplit(os.environ["ELASTICSEARCH_URL"])
    with TemporaryDirectory() as directory:
        source, recovered, diagnostics = native_run_recovery(Path(directory))
        index = new_index("run-recovery")
        # The caller defines raw-value mapping; the public API only sends Bulk.
        client.indices.create(index=index, mappings=MAPPINGS)
        try:
            reg2es(
                source,
                host=address.hostname,
                port=address.port or (443 if address.scheme == "https" else 80),
                scheme=address.scheme,
                login=unquote(address.username or ""),
                pwd=unquote(address.password or ""),
                index=index,
                plugin_names=["run"],
                chunk_size=1,
            )
        except PartialExtractionError as error:
            assert error.diagnostics == diagnostics
        else:
            raise AssertionError("ES ingestion must also report partial extraction")
        assert stored_documents(client, index) == {
            document_id(record): record for record in recovered
        }
        for name in ("a", "c", "d"):
            assert (
                client.count(
                    index=index, query={"term": {"registry.value.keyword": name}}
                )["count"]
                == 1
            )
        assert raw_mapping(client, index) == RAW_MAPPING


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


def native_wide_recovery_cases(directory):
    """Use native hives for root names, recovered times and original path bytes."""
    from reg2es import PartialExtractionError, reg2json
    from reg2es.plugins import shimcache

    artifact = runpy.run_path(str(Path(__file__).with_name("artifact_fixture.py")))

    def branch(path, values=(), children=()):
        parts = path.split("\\")
        tree = [(parts.pop(), list(children), list(values))]
        for part in reversed(parts):
            tree = [(part, tree, [])]
        return tree

    raw_paths = [
        r"C:\bad".encode("utf-16le")
        + struct.pack("<H", unit)
        + ".exe".encode("utf-16le")
        for unit in (0xD800, 0xD801)
    ]
    cache = bytes(shimcache.WIN10_STATS_SIZE)
    for raw in raw_paths:
        body = (
            struct.pack("<H", len(raw)) + raw + struct.pack("<Q", artifact["FILETIME"])
        )
        cache += struct.pack("<4sLL", shimcache.WIN10_MAGIC, 0, len(body)) + body
    system = [("Select", [], [("Current", 4, struct.pack("<I", 1))])]
    system += branch(
        r"ControlSet001\Control\Session Manager\AppCompatCache",
        [("AppCompatCache", 3, cache)],
    )
    urls = [
        (f"url{i}", 1, f"https://{i}.example/\0".encode("utf-16le"))
        for i in range(1, 4)
    ]
    times = [(f"url{i}", 3, struct.pack("<Q", artifact["FILETIME"])) for i in (1, 3)]
    times.insert(1, ("url2", 7, b"a\0b\0c"))
    ie = branch(
        r"Software\Microsoft\Internet Explorer",
        children=[
            ("TypedURLs", [], urls),
            ("TypedURLsTime", [], times),
        ],
    )
    run = branch(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        [
            ("example", 1, "test.exe\0".encode("utf-16le")),
        ],
    )
    cases = []
    for label, hive, plugin, tree, root_name, expected_count, failures in (
        ("root-path", "NTUSER.DAT", "run", run, "CMI-CreateHive{1234}", 1, 0),
        ("typed-time", "NTUSER.DAT", "typedurls", ie, "ROOT", 3, 1),
        ("shim-unicode", "SYSTEM", "shimcache", system, "ROOT", 2, 2),
    ):
        destination = directory / label
        destination.mkdir()
        source = destination / hive
        source.write_bytes(artifact["make_hive"](tree=tree, root_name=root_name))
        diagnostics = []
        try:
            records = reg2json(source, plugin_names=[plugin], chunk_size=1)
        except PartialExtractionError as error:
            records, diagnostics = error.records, error.diagnostics
        assert len(records) == expected_count and len(diagnostics) == failures
        if label == "root-path":
            assert (
                records[0]["registry"]["path"]
                == r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\example"
            )
            assert records[0]["reg2es"]["source"]["key_path"].startswith(
                root_name + "\\"
            )
        elif label == "typed-time":
            assert (
                records[1]["reg2es"]["custom"]["typedurls_time_raw"] == b"a\0b\0c".hex()
            )
        else:
            assert [
                record["reg2es"]["custom"]["path_utf16le"] for record in records
            ] == [p.hex() for p in raw_paths]
        cases.append((label, source, plugin, records, diagnostics))
    return cases


def run_wide_recovery_cases(client, new_index, stored_documents, document_id):
    from reg2es import PartialExtractionError, reg2es

    address = urlsplit(os.environ["ELASTICSEARCH_URL"])
    with TemporaryDirectory() as directory:
        cases = native_wide_recovery_cases(Path(directory))
        cases.extend(native_run_location_cases(Path(directory)))
        for label, source, plugin, records, diagnostics in cases:
            index = new_index(label)
            client.indices.create(index=index, mappings=MAPPINGS)
            try:
                reg2es(
                    source,
                    host=address.hostname,
                    port=address.port or (443 if address.scheme == "https" else 80),
                    scheme=address.scheme,
                    login=unquote(address.username or ""),
                    pwd=unquote(address.password or ""),
                    index=index,
                    plugin_names=[plugin],
                    chunk_size=1,
                )
            except PartialExtractionError as error:
                assert diagnostics and error.diagnostics == diagnostics
            else:
                assert not diagnostics
            assert stored_documents(client, index) == {
                document_id(record): record for record in records
            }
            assert len({document_id(record) for record in records}) == len(records)
            assert raw_mapping(client, index) == RAW_MAPPING
            assert client.count(
                index=index, query={"term": {"event.action.keyword": plugin}}
            )["count"] == len(records)
            if label.startswith("run-locations-"):
                for record in records:
                    assert (
                        client.count(
                            index=index,
                            query={
                                "term": {
                                    "registry.value.keyword": record["registry"][
                                        "value"
                                    ]
                                }
                            },
                        )["count"]
                        == 1
                    )
            if label == "shim-unicode":
                for record in records:
                    raw = record["reg2es"]["custom"]["path_utf16le"]
                    assert (
                        client.count(
                            index=index,
                            query={"term": {"reg2es.custom.path_utf16le.keyword": raw}},
                        )["count"]
                        == 1
                    )


def native_run_location_cases(directory):
    """Read both Run views and recover paths around unreadable sibling names."""
    from Registry import Registry
    from reg2es import PartialExtractionError, reg2json

    artifact = runpy.run_path(str(Path(__file__).with_name("artifact_fixture.py")))
    software = r"Microsoft\Windows\CurrentVersion"
    user = r"Software\Microsoft\Windows\CurrentVersion"
    paths = {
        "SOFTWARE": [
            software + r"\Run",
            software + r"\RunOnce",
            software + r"\Policies\Explorer\Run",
            "Wow6432Node\\" + software + r"\Run",
            "Wow6432Node\\" + software + r"\RunOnce",
            "Wow6432Node\\" + software + r"\Policies\Explorer\Run",
        ],
        "NTUSER.DAT": [
            user + r"\Run",
            user + r"\RunOnce",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
            user + r"\Policies\Explorer\Run",
        ],
    }

    def tree_from_paths(entries):
        root = {}
        for path, values in entries:
            node = root
            for component in path.split("\\"):
                node = node.setdefault(component, {"values": [], "children": {}})[
                    "children"
                ]
            node[None] = values

        def children(node):
            return [
                (name, children(data["children"]), data["children"].get(None, []))
                for name, data in node.items()
                if name is not None
            ]

        return children(root)

    cases = []
    for hive, target_paths in paths.items():
        for damaged in (False, True):
            label = (
                "run-locations-"
                + hive.lower().replace(".", "-")
                + ("-damaged" if damaged else "-normal")
            )
            folder = directory / label
            folder.mkdir()
            source = folder / hive
            bad_path = "Unrelated" if hive == "SOFTWARE" else user + r"\Unrelated"
            entries = [(bad_path, [])] + [
                (path, [(f"startup-{i}", 1, f"program-{i}.exe\0".encode("utf-16le"))])
                for i, path in enumerate(target_paths)
            ]
            source.write_bytes(artifact["make_hive"](tree=tree_from_paths(entries)))
            expected = reg2json(source, plugin_names=["run"], chunk_size=1)
            assert len(expected) == len(target_paths)
            if damaged:
                native = Registry.Registry(str(source))
                offset = native.open(bad_path)._nkrecord.offset()
                raw = bytearray(source.read_bytes())
                flags = struct.unpack_from("<H", raw, offset + 2)[0]
                struct.pack_into("<H", raw, offset + 2, flags & ~0x20)
                struct.pack_into("<H", raw, offset + 0x48, 2)
                raw[offset + 0x4C : offset + 0x4E] = b"\x00\xd8"
                source.write_bytes(raw)
            original = source.read_bytes()
            diagnostics = []
            try:
                records = reg2json(source, plugin_names=["run"], chunk_size=1)
            except PartialExtractionError as error:
                records, diagnostics = error.records, error.diagnostics
            assert records == expected
            assert len(diagnostics) == int(damaged)
            if damaged:
                assert diagnostics[0]["stage"] == "name"
                assert diagnostics[0]["error"].startswith("UnicodeDecodeError:")
            assert source.read_bytes() == original
            cases.append((label, source, "run", records, diagnostics))
    return cases
