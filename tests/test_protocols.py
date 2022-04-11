import asyncio
from asyncio import Transport
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pykdeconnect.payloads import IdentityPayload, payload_to_bytes
from pykdeconnect.protocols import UdpAdvertisementProtocol
from tests.utils import get_faketime


@pytest.mark.asyncio
@patch("asyncio.get_running_loop")
async def test_udp_advertisement_protocol(get_running_loop):
    client_info = MagicMock()
    plugin_registry = MagicMock()

    loop = MagicMock()
    loop.create_connection = AsyncMock()
    get_running_loop.return_value = loop

    device = MagicMock()
    device.is_connected = False
    device_manager = MagicMock()
    device_manager.get_device = MagicMock(return_value=device)

    protocol = UdpAdvertisementProtocol(client_info, device_manager, plugin_registry)

    transport = MagicMock(spec=Transport)

    protocol.connection_made(transport)
    payload: IdentityPayload = {
        "id": get_faketime(),
        "type": "kdeconnect.identity",
        "body": {
            "deviceId": "foo",
            "deviceName": "Foo",
            "protocolVersion": 7,
            "deviceType": "phone",
            "incomingCapabilities": [],
            "outgoingCapabilities": [],
            "tcpPort": 1716
        }
    }
    with patch("pykdeconnect.protocols.TcpClientSideProtocol") as tcp_protocol:
        protocol.datagram_received(payload_to_bytes(payload), ("192.0.2.2", 1717))

    device_manager.get_device.assert_called_once_with("foo")
    loop.create_connection.assert_called_once()
    loop.create_connection.call_args.args[0]()
    tcp_protocol.assert_called_once_with(client_info, device_manager, plugin_registry, device_manager.get_device("foo"))
    assert loop.create_connection.call_args.args[1] == "192.0.2.2"
    assert loop.create_connection.call_args.args[2] == "1716"
