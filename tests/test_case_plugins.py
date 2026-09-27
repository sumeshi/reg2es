"""Focused tests for plugins added from confirmed case-hive coverage."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

from Registry.Registry import RegBin, RegDWord, RegSZ

from reg2es.plugins.mounteddevices import Plugin as MountedDevices
from reg2es.plugins.usbstor import Plugin as USBStor
from reg2es.plugins.wordwheelquery import Plugin as WordWheelQuery
from tests.regrippy.reg_mock import LoggerMock, RegistryValueMock


def test_wordwheelquery_decodes_terms_and_keeps_mru_order():
    key = MagicMock()
    order_value = RegistryValueMock(
        "MRUListEx", struct.pack("<III", 1, 0, 0xFFFFFFFF), RegBin
    )
    first = RegistryValueMock("0", "first".encode("utf-16-le") + b"\0\0", RegBin)
    second = RegistryValueMock("1", "second".encode("utf-16-le") + b"\0\0", RegBin)
    key.values.return_value = [order_value, first, second]
    parser = MagicMock()
    parser.open.return_value = key

    results = list(WordWheelQuery(parser, LoggerMock(), "NTUSER.DAT", "NTUSER.DAT").run())

    assert [result.custom["search_term"] for result in results] == ["first", "second"]
    assert [result.custom["mru_order"] for result in results] == [["1", "0"], ["1", "0"]]
    assert results[0].value_data == first.value()


def test_usbstor_emits_device_and_instance_identifiers():
    select = MagicMock()
    select.value.return_value.value.return_value = 1
    current_set = MagicMock()
    device_type = MagicMock()
    device_type.name.return_value = "Disk&Vendor_Product"
    instance = MagicMock()
    instance.name.return_value = "SERIAL&0"
    instance.values.return_value = [RegistryValueMock("FriendlyName", "USB disk", RegSZ)]
    device_type.subkeys.return_value = [instance]
    current_set.subkeys.return_value = [device_type]
    parser = MagicMock()
    parser.open.side_effect = lambda path: {
        "Select": select,
        "ControlSet001\\Enum\\USBSTOR": current_set,
    }[path]

    results = list(USBStor(parser, LoggerMock(), "SYSTEM", "SYSTEM").run())

    assert len(results) == 1
    assert results[0].custom["device_type"] == "Disk&Vendor_Product"
    assert results[0].custom["instance_id"] == "SERIAL&0"
    assert results[0].custom["registry_values"] == {"FriendlyName": "USB disk"}


def test_mounteddevices_preserves_each_raw_value():
    key = MagicMock()
    value = RegistryValueMock("\\DosDevices\\C:", b"volume-id", RegBin)
    key.values.return_value = [value]
    parser = MagicMock()
    parser.open.return_value = key

    results = list(MountedDevices(parser, LoggerMock(), "SYSTEM", "SYSTEM").run())

    assert len(results) == 1
    assert results[0].value_name == "\\DosDevices\\C:"
    assert results[0].value_data == b"volume-id"
