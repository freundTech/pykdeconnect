from unittest.mock import AsyncMock, MagicMock

import pytest

from pykdeconnect.device_manager import DeviceManager


def test_device_manager_add_device():
    storage = MagicMock()
    device_manager = DeviceManager(storage)
    device = MagicMock()
    device.device_id = "foo"

    device_manager.add_device(device)

    assert device_manager.get_device("foo") == device
    assert len(device_manager.get_devices()) == 1
    assert device in device_manager.get_devices()


def test_device_manager_remove_device():
    storage = MagicMock()
    storage.load_device = MagicMock(return_value=None)
    device_manager = DeviceManager(storage)
    device = MagicMock()
    device.device_id = "foo"

    device_manager.add_device(device)
    device_manager.remove_device(device)

    assert device_manager.get_device("foo") is None
    assert len(device_manager.get_devices()) == 0


def test_device_manager_load_from_storage():
    device = MagicMock()
    device.device_id = "foo"
    storage = MagicMock()
    storage.load_device = MagicMock(return_value=device)
    device_manager = DeviceManager(storage)

    assert device_manager.get_device("foo") == device


@pytest.mark.asyncio
async def test_device_manager_disconnect_all():
    device = MagicMock()
    device.close_connection = AsyncMock()
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    await device_manager.disconnect_all()

    device.close_connection.assert_awaited_once()


@pytest.mark.asyncio
async def test_device_manager_pairing_accepted():
    device = MagicMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    callback = AsyncMock(return_value=True)
    device_manager.set_pairing_callback(callback)
    device_manager.add_device(device)

    await device_manager.on_pairing_request(device)

    storage.store_device.assert_called_with(device)
    callback.assert_awaited_with(device)
    device.confirm_pair.assert_called_once()


@pytest.mark.asyncio
async def test_device_manager_pairing_rejected():
    device = MagicMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    callback = AsyncMock(return_value=False)
    device_manager.set_pairing_callback(callback)
    device_manager.add_device(device)

    await device_manager.on_pairing_request(device)

    callback.assert_awaited_with(device)
    device.reject_pair.assert_called_once()


@pytest.mark.asyncio
async def test_device_manager_pairing_no_callback():
    device = MagicMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    await device_manager.on_pairing_request(device)

    device.reject_pair.assert_called_once()


def test_device_manager_unpair():
    device = MagicMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    device_manager.unpair(device)

    storage.remove_device.assert_called_once_with(device)
    device.set_unpaired.assert_called_once()


@pytest.mark.asyncio
async def test_device_manager_connected_callback():
    device = MagicMock()
    device.device_connected = AsyncMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    callback = AsyncMock()
    device_manager.register_device_connected_callback(callback)

    await device_manager.device_connected(device)

    callback.assert_called_once()
    callback.assert_awaited_once_with(device)
    device.device_connected.assert_awaited_once()


@pytest.mark.asyncio
async def test_device_manager_disconnected_callback():
    device = MagicMock()
    device.device_disconnected = AsyncMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    callback = AsyncMock()
    device_manager.register_device_disconnected_callback(callback)

    await device_manager.device_disconnected(device)

    callback.assert_awaited_once_with(device)
    device.device_disconnected.assert_awaited_once()


@pytest.mark.asyncio
async def test_device_manager_remove_connected_callback():
    device = MagicMock()
    device.device_connected = AsyncMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    callback = AsyncMock()
    device_manager.register_device_connected_callback(callback)
    device_manager.unregister_device_connected_callback(callback)

    await device_manager.device_connected(device)

    callback.assert_not_called()
    device.device_connected.assert_awaited_once()


@pytest.mark.asyncio
async  def test_device_manager_remove_disconnected_callback():
    device = MagicMock()
    device.device_disconnected = AsyncMock()
    device.device_id = "foo"
    storage = MagicMock()
    device_manager = DeviceManager(storage)

    device_manager.add_device(device)

    callback = AsyncMock()
    device_manager.register_device_disconnected_callback(callback)
    device_manager.unregister_device_disconnected_callback(callback)

    await device_manager.device_disconnected(device)

    callback.assert_not_called()
    device.device_disconnected.assert_awaited_once()
