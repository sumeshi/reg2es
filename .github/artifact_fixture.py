"""Generated clean SYSTEM hive with mixed raw values, never evidence."""

from pathlib import Path
import struct

PACKAGE = "reg2es"
JSON_COMMAND = "reg2json"
TIMELINE_MODES = (None,)
SUPPORTS_MULTIPROCESSING = False
EXPECTED_PLUGINS = ["env", "regtime", "shimcache"]
API_KWARGS = {"plugin_names": ["env"]}
CLI_ARGS = ("--plugin", "env")


FILETIME = 133485408001234560

VALUES = [
    ("InstallDate", 4, struct.pack("<I", 1704067200)),
    ("ProductName", 1, "Windows 11 Pro\x00".encode("utf-16le")),
    ("MaximumQword", 11, struct.pack("<Q", 2**64 - 1)),
    ("BinaryValue", 3, b"\x00\xff\x7f\x80"),
    ("MultiString", 7, "first\x00second\x00\x00".encode("utf-16le")),
    ("EmptyString", 1, b"\x00\x00"),
    ("EmptyBinary", 3, b""),
    ("EmptyMultiString", 7, b"\x00\x00\x00\x00"),
    ("ExpandableString", 2, "%SystemRoot%\\Temp\x00".encode("utf-16le")),
]


def make_hive(values=VALUES, *, tree=None):
    hbin = bytearray(0x20)
    hbin[:4] = b"hbin"

    def cell(payload):
        offset = len(hbin)
        size = (len(payload) + 4 + 7) & ~7
        hbin.extend(struct.pack("<i", -size) + payload + bytes(size - 4 - len(payload)))
        return offset

    def value(name, kind, data):
        encoded = name.encode("ascii")
        # Windows stores values of at most four bytes directly in the VK cell.
        if len(data) <= 4:
            length = 0x80000000 | len(data)
            data_offset = int.from_bytes(data.ljust(4, b"\x00"), "little")
        else:
            length, data_offset = len(data), cell(data)
        return cell(
            struct.pack(
                "<2sHIIIHH", b"vk", len(encoded), length, data_offset, kind, 1, 0
            )
            + encoded
        )

    def key(name, parent, children, values=()):
        encoded = name.encode("ascii")
        payload = bytearray(0x4C) + encoded
        payload[:2] = b"nk"
        struct.pack_into("<H", payload, 2, 0x24 if parent is None else 0x20)
        struct.pack_into("<Q", payload, 4, FILETIME)
        struct.pack_into("<L", payload, 0x10, 0xFFFFFFFF if parent is None else parent)
        struct.pack_into("<H", payload, 0x48, len(encoded))
        for field in (0x1C, 0x20, 0x28, 0x2C, 0x30):
            struct.pack_into("<L", payload, field, 0xFFFFFFFF)
        offset = cell(payload)
        descendants = [
            key(child_name, offset, child_children, child_values)
            for child_name, child_children, child_values in children
        ]
        if descendants:
            index = cell(
                struct.pack("<2sH", b"li", len(descendants))
                + struct.pack("<" + "L" * len(descendants), *descendants)
            )
            struct.pack_into("<L", hbin, offset + 4 + 0x14, len(descendants))
            struct.pack_into("<L", hbin, offset + 4 + 0x1C, index)
        value_offsets = [value(*item) for item in values]
        if value_offsets:
            index = cell(struct.pack("<" + "L" * len(value_offsets), *value_offsets))
            struct.pack_into("<L", hbin, offset + 4 + 0x24, len(value_offsets))
            struct.pack_into("<L", hbin, offset + 4 + 0x28, index)
        return offset

    env = ("Environment", [], values)
    manager = ("Session Manager", [env], [])
    control = ("Control", [manager], [])
    if tree is None:
        tree = [
            ("Select", [], [("Current", 4, struct.pack("<I", 1))]),
            ("ControlSet001", [control], []),
        ]
    root_offset = key("ROOT", None, tree)
    total = ((len(hbin) + 8 + 4095) // 4096) * 4096
    free_size = total - len(hbin)
    hbin.extend(struct.pack("<i", free_size) + bytes(free_size - 4))
    struct.pack_into("<L", hbin, 8, len(hbin))
    regf = bytearray(4096)
    regf[:4] = b"regf"
    struct.pack_into("<IIQ", regf, 4, 1, 1, FILETIME)
    struct.pack_into("<6I", regf, 0x14, 1, 5, 0, 1, root_offset, len(hbin))
    struct.pack_into("<I", regf, 0x2C, 1)
    name = r"\SystemRoot\System32\Config\SYSTEM".encode("utf-16le")
    regf[0x30 : 0x30 + len(name)] = name
    checksum = 0
    for offset in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", regf, offset)[0]
    checksum = (
        1 if checksum == 0 else (0xFFFFFFFE if checksum == 0xFFFFFFFF else checksum)
    )
    struct.pack_into("<I", regf, 0x1FC, checksum)
    return bytes(regf + hbin)


def create_artifact(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "SYSTEM"
    destination.write_bytes(make_hive())
    return destination
