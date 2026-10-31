"""Native Registry name lookups retain intact entries and matching rules."""

import logging

import pytest
from Registry import Registry

from reg2es.plugins.base import BasePlugin
from tests.test_configuration_name_recovery import damage_name
from tests.test_other_plugin_recovery import MAKE, dword, sz
from tests.test_task_name_recovery import corrupt_name


def source_key(tmp_path, *, values=(), children=()):
    source = tmp_path / "SYSTEM"
    source.write_bytes(MAKE(tree=[("Example", children, values)]))
    return source


def open_plugin(source):
    native = Registry.Registry(str(source))
    return BasePlugin(native, logging.getLogger(__name__), "SYSTEM", str(source))


@pytest.mark.parametrize("name", ["name", "NaMe", "NAME"])
def test_value_case_comparison_keeps_first_native_match(tmp_path, name):
    source = source_key(
        tmp_path,
        values=[sz("NaMe", "first"), sz("NAME", "second"), sz("NaMe", "third")],
    )
    original = source.read_bytes()
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")
    values = plugin.read_values(key)

    assert [name for name, _ in values] == ["NaMe", "NAME", "NaMe"]
    assert (
        plugin.get_value(key, name, values).value()
        == key.value(name).value()
        == "first"
    )
    assert plugin.errors == []
    assert source.read_bytes() == original


@pytest.mark.parametrize("unnamed_first", [False, True])
@pytest.mark.parametrize("name", ["", "(default)", "(DEFAULT)"])
def test_default_alias_distinguishes_literal_named_value(tmp_path, unnamed_first, name):
    values = [sz("(default)", "literal"), sz("", "unnamed")]
    if unnamed_first:
        values.reverse()
    source = source_key(tmp_path, values=values)
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")

    actual = plugin.get_value(key, name).value()

    assert actual == key.value(name).value()
    assert actual == ("literal" if name == "(DEFAULT)" else "unnamed")
    assert plugin.errors == []


@pytest.mark.parametrize("name", ["missing", "", "(default)"])
def test_missing_value_has_native_exception_and_context(tmp_path, name):
    source = source_key(tmp_path, values=[sz("Value", "present")])
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")

    with pytest.raises(Registry.RegistryValueNotFoundException) as native:
        key.value(name)
    with pytest.raises(Registry.RegistryValueNotFoundException) as actual:
        plugin.get_value(key, name)

    assert str(actual.value) == str(native.value)
    assert plugin.errors == []


@pytest.mark.parametrize("position", [0, 2])
def test_unreadable_value_name_preserves_other_lookups_once(tmp_path, position):
    values = [sz("First", "first"), sz("Second", "second")]
    values.insert(position, sz("Unrelated", "ignored"))
    source = source_key(tmp_path, values=values)
    damage_name(source, "Example", position)
    original = source.read_bytes()
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")

    names = plugin.read_values(key)

    assert plugin.get_value(key, "FIRST", names).value() == "first"
    assert plugin.get_value(key, "second", names).value() == "second"
    assert [name for name, _ in names] == ["First", "Second"]
    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"
    assert plugin.errors[0]["key"] == key.path()
    assert plugin.errors[0]["value"] is None
    assert source.read_bytes() == original


@pytest.mark.parametrize("position", [0, 2])
def test_strict_nested_value_name_failure_is_counted_once(tmp_path, position):
    values = [sz("First", "first"), sz("Second", "second")]
    values.insert(position, sz("Unrelated", "ignored"))
    source = source_key(tmp_path, values=values)
    damage_name(source, "Example", position)
    plugin = open_plugin(source)
    plugin.error_policy = "raise"
    key = plugin.reg.open("Example")

    with pytest.raises(UnicodeDecodeError):
        with plugin.recover(key, stage="values"):
            plugin.get_value(key, "First")

    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"


@pytest.mark.parametrize("name", ["child", "ChIlD", "CHILD"])
def test_subkey_case_comparison_keeps_first_native_match(tmp_path, name):
    source = source_key(
        tmp_path,
        children=[
            ("ChIlD", [], [sz("Value", "first")]),
            ("CHILD", [], [sz("Value", "second")]),
        ],
    )
    original = source.read_bytes()
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")
    children = plugin.read_subkeys(key)

    assert [name for name, _ in children] == ["ChIlD", "CHILD"]
    assert (
        plugin.get_subkey(key, name, children).value("Value").value()
        == key.subkey(name).value("Value").value()
        == "first"
    )
    assert source.read_bytes() == original


def test_missing_subkey_has_native_exception_and_context(tmp_path):
    source = source_key(tmp_path)
    plugin = open_plugin(source)
    key = plugin.reg.open("Example")

    with pytest.raises(Registry.RegistryKeyNotFoundException) as native:
        key.subkey("missing")
    with pytest.raises(Registry.RegistryKeyNotFoundException) as actual:
        plugin.get_subkey(key, "missing")

    assert str(actual.value) == str(native.value)
    assert plugin.errors == []


@pytest.mark.parametrize("position", [0, 2])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_unreadable_child_name_preserves_siblings_or_raises_once(
    tmp_path, position, policy
):
    children = [("First", [], []), ("Second", [], [])]
    children.insert(position, ("Unrelated", [], []))
    source = source_key(tmp_path, children=children)
    corrupt_name(source, key=r"Example\Unrelated")
    original = source.read_bytes()
    plugin = open_plugin(source)
    plugin.error_policy = policy
    key = plugin.reg.open("Example")

    if policy == "raise":
        with pytest.raises(UnicodeDecodeError):
            with plugin.recover(key, stage="subkeys"):
                plugin.get_subkey(key, "First")
    else:
        names = plugin.read_subkeys(key)
        assert [name for name, _ in names] == ["First", "Second"]
        assert plugin.get_subkey(key, "FIRST", names).name() == "First"
        assert plugin.get_subkey(key, "second", names).name() == "Second"
    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"
    assert plugin.errors[0]["key"] == key.path()
    assert source.read_bytes() == original


@pytest.mark.parametrize("position", [0, 1])
def test_currentcontrolset_ignores_unrelated_unreadable_value_name(tmp_path, position):
    values = [dword("Current", 1)]
    values.insert(position, sz("Unrelated", "ignored"))
    source = tmp_path / "SYSTEM"
    source.write_bytes(MAKE(tree=[("Select", [], values)]))
    plugin = open_plugin(source)
    assert plugin.get_currentcontrolset_path() == "ControlSet001"
    damage_name(source, "Select", position)
    original = source.read_bytes()
    plugin = open_plugin(source)

    assert plugin.get_currentcontrolset_path() == "ControlSet001"
    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"
    assert source.read_bytes() == original
