from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pykdeconnect.plugin_registry import PluginRegistry
from pykdeconnect.plugins.ping import (
    PingPayload, PingReceiverPlugin, PingSenderPlugin
)
from tests.utils import get_faketime, patch_timestamp

payload: PingPayload = {
        "id": get_faketime(),
        "type": "kdeconnect.ping",
        "body": {}
    }


def test_register_ping_sender_plugin():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(PingSenderPlugin)


def test_register_ping_receiver_plugin():
    plugin_registry = PluginRegistry(load_builtin_plugins=False)
    plugin_registry.register_plugin(PingReceiverPlugin)


@pytest.mark.asyncio
async def test_ping_callback():
    device = MagicMock()
    plugin = PingReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_ping_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_remove_ping_callback():
    device = MagicMock()
    plugin = PingReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_ping_callback(callback)
    plugin.unregister_ping_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_not_awaited()


@patch_timestamp
def test_get_battery_state():
    device = MagicMock()
    device.is_connected = True
    device.send_payload = MagicMock()
    plugin = PingSenderPlugin.create_instance(device)

    plugin.send_ping()

    device.send_payload.assert_called_once_with(payload)
