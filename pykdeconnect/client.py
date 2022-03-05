import asyncio
import logging
from asyncio import BaseTransport
from asyncio.base_events import Server
from pathlib import Path
from socket import (
    AF_INET, SO_BROADCAST, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, socket
)
from typing import Optional

from .const import (
    ADDRESS_BROADCAST, KDECONNECT_PORT, KDECONNECT_PORT_MAX,
    KDECONNECT_PORT_MIN, KdeConnectDeviceType, KdeConnectProtocolVersion
)
from .device_manager import DeviceManager, PairingCallback
from .devices import KdeConnectDevice
from .helpers import get_timestamp
from .payloads import IdentityPayload, payload_to_bytes
from .plugin_registry import PluginRegistry
from .protocols import TcpServerSideProtocol, UdpAdvertisementProtocol
from .storage import AbstractStorage

logger = logging.getLogger(__name__)


class ClientInfo:
    device_name: str
    device_type: KdeConnectDeviceType
    protocol_version: KdeConnectProtocolVersion
    port: Optional[int]

    _storage: AbstractStorage
    _plugin_registry: PluginRegistry

    def __init__(
            self,
            storage: AbstractStorage,
            plugin_registry: PluginRegistry,
            device_name: str,
            device_type: KdeConnectDeviceType,
            protocol_version: KdeConnectProtocolVersion,
            port: Optional[int] = None
    ) -> None:
        self._storage = storage
        self._plugin_registry = plugin_registry

        self.device_name = device_name
        self.device_type = device_type
        self.protocol_version = protocol_version
        self.port = port

    @property
    def device_id(self) -> str:
        return self._storage.device_id

    @property
    def private_key_path(self) -> Path:
        return self._storage.private_key_path

    @property
    def cert_path(self) -> Path:
        return self._storage.cert_path

    def identity_payload(self, *, with_port: bool) -> IdentityPayload:
        payload: IdentityPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.identity",
            "body": {
                "deviceName": self.device_name,
                "deviceId": self.device_id,
                "deviceType": self.device_type.value,
                "incomingCapabilities": list(self._plugin_registry.incoming_payloads),
                "outgoingCapabilities": list(self._plugin_registry.outgoing_payloads),
                "protocolVersion": self.protocol_version.value,
            }
        }
        if with_port:
            assert self.port is not None
            payload["body"]["tcpPort"] = self.port

        return payload


class KdeConnectClient:
    _client_info: ClientInfo
    _device_manager: DeviceManager

    _storage: AbstractStorage
    _plugin_registry: PluginRegistry

    _udp_transport: Optional[BaseTransport] = None
    _tcp_server: Optional[Server] = None

    def __init__(self, device_name: str, device_type: KdeConnectDeviceType,
                 storage: AbstractStorage,
                 plugin_registry: PluginRegistry,
                 protocol_version: KdeConnectProtocolVersion = KdeConnectProtocolVersion.V7):
        logger.debug("Client created")
        self._client_info = ClientInfo(
            storage,
            plugin_registry,
            device_name,
            device_type,
            protocol_version
        )

        self._storage = storage
        self._plugin_registry = plugin_registry

        self._device_manager = DeviceManager(storage)

    async def start(
            self,
            *,
            advertise_addr: str = ADDRESS_BROADCAST,
            listen_addr: str = ''
    ) -> None:
        loop = asyncio.get_running_loop()

        self._plugin_registry.lock()

        # create_datagram_endpoint and create_server does not allow binding to all addresses, so
        # we create the sockets manually
        udp_sock = socket(AF_INET, SOCK_DGRAM)
        udp_sock.bind((listen_addr, KDECONNECT_PORT))

        tcp_sock = None
        for port in range(KDECONNECT_PORT_MIN, KDECONNECT_PORT_MAX):
            tcp_sock = socket(AF_INET, SOCK_STREAM)
            try:
                tcp_sock.bind((listen_addr, port))
                tcp_sock.listen()
            except OSError:
                tcp_sock.close()
                logger.warning("Port %d taken. Trying next", port)
            else:
                self._client_info.port = port
                break

        if self._client_info.port is None:
            raise RuntimeError("Couldn't bind to a suitable tcp port")

        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: UdpAdvertisementProtocol(
                self._client_info,
                self._device_manager,
                self._plugin_registry
            ),
            sock=udp_sock
        )
        self._tcp_server = await loop.create_server(
            lambda: TcpServerSideProtocol(
                self._client_info,
                self._device_manager,
                self._plugin_registry
            ),
            sock=tcp_sock
        )
        loop.create_task(self.advertise_once(advertise_addr))

    async def stop(self) -> None:
        # First stop listening to udp advertisements
        if self._udp_transport is not None:
            self._udp_transport.close()

        # Then stop accepting new connections
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

        # Once we don't accept new connections any more close all current connections
        await self._device_manager.disconnect_all()

    @property
    def pairable_devices(self) -> list[KdeConnectDevice]:
        return [
            d for d in self._device_manager.connected_devices.values()
            if not d.is_paired
        ]

    @property
    def connected_devices(self) -> dict[str, KdeConnectDevice]:
        return self._device_manager.connected_devices

    def set_pairing_callback(self, callback: PairingCallback) -> None:
        self._device_manager.set_pairing_callback(callback)

    async def advertise_once(self, advertise_addr: str = ADDRESS_BROADCAST) -> None:
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        try:
            sock.connect((advertise_addr, KDECONNECT_PORT))
            payload = payload_to_bytes(self._client_info.identity_payload(with_port=True))
            sock.send(payload)
            logger.debug("Sent udp advertisement")
        finally:
            sock.close()

    def get_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        return self._device_manager.get_device(device_id)

    @property
    def plugin_registry(self) -> PluginRegistry:
        return self._plugin_registry
