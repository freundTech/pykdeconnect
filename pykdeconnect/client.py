import asyncio
import logging
import ssl
from asyncio import BaseTransport, Queue
from asyncio.base_events import Server
from socket import (
    AF_INET, SO_BROADCAST, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, socket
)
from typing import Awaitable, Callable, Dict, Optional, Set

from cryptography.hazmat.primitives import serialization

from . import ssl_workaround
from .config import AbstractKdeConnectConfig
from .const import (
    ADDRESS_BROADCAST, KDECONNECT_PORT, KDECONNECT_PORT_MAX,
    KDECONNECT_PORT_MIN, KdeConnectDeviceType, KdeConnectProtocolVersion
)
from .devices import KdeConnectDevice
from .helpers import get_timestamp
from .payloads import IdentityPayload, payload_to_bytes
from .plugin_registry import PluginRegistry
from .protocols import (
    TcpClientSideProtocol, TcpServerSideProtocol, UdpAdvertisementProtocol
)

logger = logging.getLogger(__name__)


PairingCallback = Callable[[KdeConnectDevice], Awaitable[bool]]
DeviceCallback = Callable[[KdeConnectDevice], Awaitable[None]]


class KdeConnectClient:
    device_name: str
    device_type: KdeConnectDeviceType
    protocol_version: KdeConnectProtocolVersion

    connected_devices: Dict[str, KdeConnectDevice]

    pairing_queue: Queue
    pairing_callback: Optional[PairingCallback] = None

    device_connected_callbacks: Set[DeviceCallback]
    device_disconnected_callbacks: Set[DeviceCallback]

    port: int

    config: AbstractKdeConnectConfig
    plugin_registry: PluginRegistry

    udp_transport: Optional[BaseTransport] = None
    tcp_server: Optional[Server] = None

    def __init__(self, device_name: str, device_type: KdeConnectDeviceType,
                 config: AbstractKdeConnectConfig,
                 plugin_registry: PluginRegistry,
                 protocol_version: KdeConnectProtocolVersion = KdeConnectProtocolVersion.V7):
        logger.debug("Client created")
        self.device_name = device_name
        self.device_type = device_type
        self.protocol_version = protocol_version

        self.config = config
        self.plugin_registry = plugin_registry

        self.connected_devices = {}
        self.pairing_queue = Queue()

        self.device_connected_callbacks = set()
        self.device_disconnected_callbacks = set()

    async def start(self, *, advertise_addr: str = ADDRESS_BROADCAST, listen_addr: str = ''):
        loop = asyncio.get_running_loop()

        self.plugin_registry.lock()

        # create_datagram_endpoint and create_server does not allow binding to all addresses, so
        # we create the sockets manually
        udp_sock = socket(AF_INET, SOCK_DGRAM)
        udp_sock.bind((listen_addr, KDECONNECT_PORT))

        tcp_sock = None
        found_port = None
        for port in range(KDECONNECT_PORT_MIN, KDECONNECT_PORT_MAX):
            tcp_sock = socket(AF_INET, SOCK_STREAM)
            try:
                tcp_sock.bind((listen_addr, port))
                tcp_sock.listen()
            except OSError:
                tcp_sock.close()
                logger.warning(f"Port {port} taken. Trying next")
            else:
                found_port = port
                break

        if found_port is None:
            raise RuntimeError("Couldn't bind to a suitable tcp port. Exiting")
        else:
            self.port = found_port

        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: UdpAdvertisementProtocol(self),
            sock=udp_sock
        )
        self.tcp_server = await loop.create_server(
            lambda: TcpServerSideProtocol(self),
            sock=tcp_sock
        )
        loop.create_task(self.advertise_once(advertise_addr))

    async def stop(self):
        # First stop listening to udp advertisements
        if self.udp_transport is not None:
            self.udp_transport.close()

        # Then stop accepting new connections
        if self.tcp_server is not None:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()

        # Once we don't accept new connections any more close all current connections
        await asyncio.gather(
            *(device.close_connection() for device in self.connected_devices.values())
        )

    @property
    def pairable_devices(self):
        return [
            d for d in self.connected_devices.values()
            if d.protocol is not None and not d.is_paired
        ]

    def set_pairing_callback(self, callback: PairingCallback):
        self.pairing_callback = callback

    async def on_pairing_request(self, device: KdeConnectDevice):
        if self.pairing_callback is not None:
            result = await self.pairing_callback(device)
            if result:
                device.confirm_pair()
                self.config.trust_device(device)
            else:
                device.reject_pair()
        else:
            logger.warning(f'"{device.device_name}" requested pairing, but no pairing callback '
                           f'was set. Rejecting.')
            device.unpair()

    async def device_connected(self, device: KdeConnectDevice):
        callbacks = [callback(device) for callback in self.device_connected_callbacks]
        callbacks.append(device.device_connected())
        await asyncio.gather(*callbacks)

    async def device_disconnected(self, device: KdeConnectDevice):
        callbacks = [callback(device) for callback in self.device_disconnected_callbacks]
        callbacks.append(device.device_disconnected())
        await asyncio.gather(*callbacks)

    def register_device_connected_callback(self, callback: DeviceCallback):
        self.device_connected_callbacks.add(callback)

    def unregister_device_connected_callback(self, callback: DeviceCallback):
        self.device_connected_callbacks.remove(callback)

    def register_device_disconnected_callback(self, callback: DeviceCallback):
        self.device_disconnected_callbacks.add(callback)

    def unregister_device_disconnected_callback(self, callback: DeviceCallback):
        self.device_disconnected_callbacks.remove(callback)

    def get_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        if device_id in self.connected_devices:
            return self.connected_devices[device_id]

        return self.config.get_device(device_id)

    async def advertise_once(self, advertise_addr: str = ADDRESS_BROADCAST):
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        try:
            sock.connect((advertise_addr, KDECONNECT_PORT))
            payload = payload_to_bytes(self.identity_payload(with_port=True))
            sock.send(payload)
            logger.debug("Sent udp advertisement")
        finally:
            sock.close()

    async def send_tcp_identity(self, addr: str, port: int, device: KdeConnectDevice):
        loop = asyncio.get_running_loop()

        await loop.create_connection(lambda: TcpClientSideProtocol(self, device), addr, port)

    def identity_payload(self, *, with_port: bool) -> IdentityPayload:
        payload: IdentityPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.identity",
            "body": {
                "deviceName": self.device_name,
                "deviceId": self.config.device_id,
                "deviceType": self.device_type.value,
                "incomingCapabilities": list(self.plugin_registry.incoming_payloads),
                "outgoingCapabilities": list(self.plugin_registry.outgoing_payloads),
                "protocolVersion": self.protocol_version.value,
            }
        }
        if with_port:
            payload["body"]["tcpPort"] = self.port

        return payload

    def get_ssl_context(self, server_side: bool, device: KdeConnectDevice):
        if server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA"
        )
        ctx.check_hostname = False

        ctx.load_cert_chain(self.config.cert_path, self.config.private_key_path)

        ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        if device.is_paired:
            assert device.certificate is not None
            ctx.load_verify_locations(cadata=device.certificate.public_bytes(
                serialization.Encoding.DER
            ))
        else:
            ssl_workaround.set_verify_always_pass(ctx, True)
            pass

        ctx.keylog_filename = "server.log" if server_side else "client.log"
        return ctx
