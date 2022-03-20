from unittest.mock import MagicMock, patch

import pytest

from pykdeconnect.exceptions import (
    IncompatiblePluginError, PayloadAlreadyRegisteredError,
    PluginAlreadyRegisteredError, PluginNotRegisteredError,
    PluginRegistryLockedError
)
from pykdeconnect.plugin_registry import PluginRegistry

MockPlugin = MagicMock()
MockPlugin.__name__ = "MockPlugin"


@patch("pykdeconnect.plugin_registry.builtin_plugins", [
    "tests.test_plugin_registry.MockPlugin"
])
def test_load_builtin_plugins():
    plugin_registry = PluginRegistry(load_builtin_plugins=True)

    assert MockPlugin in plugin_registry.plugins


def test_no_builtin_plugins():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)

    assert len(plugin_registry.plugins) == 0


def test_lock_plugin_registry():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)

    plugin_registry.lock()

    with pytest.raises(PluginRegistryLockedError):
        plugin_registry.register_plugin(MockPlugin)


def test_plugin_already_registered():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)

    plugin_registry.register_plugin(MockPlugin)

    with pytest.raises(PluginAlreadyRegisteredError):
        plugin_registry.register_plugin(MockPlugin)


def test_incoming_payload_already_registered():
    Plugin1 = MagicMock()
    Plugin1.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    Plugin2 = MagicMock()
    Plugin2.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})

    plugin_registry = PluginRegistry(load_builtin_plugins=False)

    plugin_registry.register_plugin(Plugin1)

    with pytest.raises(PayloadAlreadyRegisteredError) as e:
        plugin_registry.register_plugin(Plugin2)

    assert e.value.incoming is True


def test_outgoing_payload_already_registered():
    Plugin1 = MagicMock()
    Plugin1.get_outgoing_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    Plugin2 = MagicMock()
    Plugin2.get_outgoing_payload_types = MagicMock(return_value={"pykdeconnect.test"})

    plugin_registry = PluginRegistry(load_builtin_plugins=False)

    plugin_registry.register_plugin(Plugin1)

    with pytest.raises(PayloadAlreadyRegisteredError) as e:
        plugin_registry.register_plugin(Plugin2)

    assert e.value.incoming is False


def test_get_plugin():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(MockPlugin)
    device = MagicMock()

    plugin = plugin_registry.get_plugin(device, MockPlugin)

    MockPlugin.create_instance.assert_called_once_with(device)
    assert plugin == MockPlugin.create_instance(device)


def test_get_plugin_not_registered():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    device = MagicMock()

    with pytest.raises(PluginNotRegisteredError):
        plugin_registry.get_plugin(device, MockPlugin)


def test_get_plugin_incompatible_incoming():
    Plugin = MagicMock()
    Plugin.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.outgoing_capabilities = {}

    with pytest.raises(IncompatiblePluginError) as e:
        plugin_registry.get_plugin(device, Plugin)

    assert e.value.incoming is True


def test_get_plugin_incompatible_outgoing():
    Plugin = MagicMock()
    Plugin.get_outgoing_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.incoming_capabilities = {}

    with pytest.raises(IncompatiblePluginError) as e:
        plugin_registry.get_plugin(device, Plugin)

    assert e.value.incoming is False


def test_get_plugin_for_type():
    Plugin = MagicMock()
    Plugin.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.outgoing_capabilities = {"pykdeconnect.test"}

    plugin = plugin_registry.get_plugin_for_type(device, "pykdeconnect.test")

    Plugin.create_instance.assert_called_once_with(device)
    assert plugin == Plugin.create_instance(device)


def test_get_plugin_for_type_not_existing():
    Plugin = MagicMock()
    Plugin.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()

    plugin = plugin_registry.get_plugin_for_type(device, "pykdeconnect.test2")

    assert plugin is None


def test_is_plugin_compatible_true():
    Plugin = MagicMock()
    Plugin.get_outgoing_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    Plugin.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test2"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.outgoing_capabilities = {"pykdeconnect.test2"}
    device.incoming_capabilities = {"pykdeconnect.test"}

    assert plugin_registry.is_plugin_compatible(device, Plugin) is True


def test_is_plugin_compatible_false_incoming():
    Plugin = MagicMock()
    Plugin.get_incoming_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.outgoing_capabilities = {}

    assert plugin_registry.is_plugin_compatible(device, Plugin) is False


def test_is_plugin_compatible_false_outgoing():
    Plugin = MagicMock()
    Plugin.get_outgoing_payload_types = MagicMock(return_value={"pykdeconnect.test"})
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(Plugin)
    device = MagicMock()
    device.incoming_capabilities = {}

    assert plugin_registry.is_plugin_compatible(device, Plugin) is False
