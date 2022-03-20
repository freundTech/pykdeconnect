import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import voluptuous as vol

from pykdeconnect.payloads import AnyPayload
from pykdeconnect.plugins.battery import (
    BatteryPayload, BatteryReceiverPlugin, BatteryThreshold
)


def fake_timestamp():
    return 1559901600000


payload: BatteryPayload = {
    "id": fake_timestamp(),
    "type": "kdeconnect.battery",
    "body": {
        "currentCharge": 81,
        "isCharging": True,
        "thresholdEvent": BatteryThreshold.NONE.value,
    }
}


@pytest.mark.asyncio
async def test_battery_charge_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_charge_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_awaited_once_with(81)


@pytest.mark.asyncio
async def test_battery_charging_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_charging_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_awaited_once_with(True)


@pytest.mark.asyncio
async def test_battery_low_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_low_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_awaited_once_with(False)


@pytest.mark.asyncio
async def test_remove_battery_charge_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_charge_changed_callback(callback)
    plugin.unregister_charge_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_remove_battery_charging_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_charging_changed_callback(callback)
    plugin.unregister_charging_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_remove_battery_low_changed_callback():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    callback = AsyncMock()
    plugin.register_low_changed_callback(callback)
    plugin.unregister_low_changed_callback(callback)
    await plugin.handle_payload(payload)

    callback.assert_not_called()


@pytest.mark.asyncio
@patch("pykdeconnect.plugins.battery.get_timestamp", fake_timestamp)
async def test_get_battery_state():
    def send_response(request_payload):
        asyncio.create_task(plugin.handle_payload(payload))

    device = MagicMock()
    device.is_connected = True
    device.send_payload = MagicMock(side_effect=send_response)
    plugin = BatteryReceiverPlugin.create_instance(device)

    battery_state = await plugin.get_battery_state()

    device.send_payload.assert_called_once_with({
        "id": fake_timestamp(),
        "type": "kdeconnect.battery.request",
        "body": {
            "request": True
        }
    })

    assert battery_state.current_charge == 81
    assert battery_state.charging is True
    assert battery_state.low is False


@pytest.mark.asyncio
async def test_invalid_payload():
    device = MagicMock()
    plugin = BatteryReceiverPlugin.create_instance(device)

    payload: AnyPayload = {
        "id": fake_timestamp(),
        "type": "kdeconnect.other",
        "body": {}
    }

    with pytest.raises(vol.Invalid):
        await plugin.handle_payload(payload)
