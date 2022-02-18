import asyncio
import logging
import ssl
from asyncio import Queue
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SOCK_STREAM
from typing import List, Callable, Awaitable, Optional

from cryptography.hazmat.primitives import serialization

from . import ssl_workaround
from .config import AbstractKdeConnectConfig
from .const import ADDRESS_BROADCAST, KDECONNECT_PORT, KDECONNECT_PORT_MIN, KDECONNECT_PORT_MAX, \
    KdeConnectDeviceType, \
    KdeConnectProtocolVersion
from .devices import KdeConnectDevice
from .helpers import get_timestamp
from .payloads import IdentityPayload, PayloadDecoder, PayloadEncoder
from .plugins.plugin import Plugin
from .protocols import UdpAdvertisementProtocol, TcpClientSideProtocol, TcpServerSideProtocol


logger = logging.getLogger(__name__)


PairingCallback = Callable[[KdeConnectDevice], Awaitable[bool]]


class KdeConnectClient:
    device_name: str
    device_type: KdeConnectDeviceType
    protocol_version: KdeConnectProtocolVersion

    encoder: PayloadEncoder
    decoder: PayloadDecoder
    plugins: List[Plugin]
    known_devices: List[KdeConnectDevice]
    trusted_devices: List[KdeConnectDevice]
    pairing_queue: Queue
    pairing_callback: Optional[PairingCallback] = None

    port: Optional[int] = None

    config: AbstractKdeConnectConfig

    def __init__(self, device_name: str, device_type: KdeConnectDeviceType,
                 config: AbstractKdeConnectConfig,
                 protocol_version: KdeConnectProtocolVersion = KdeConnectProtocolVersion.V7):
        self.device_name = device_name
        self.device_type = device_type
        self.protocol_version = protocol_version

        self.config = config

        self.encoder = PayloadEncoder()
        self.decoder = PayloadDecoder()
        self.plugins = []
        self.known_devices = []
        self.trusted_devices = []
        self.pairing_queue = Queue()

    async def start(self, *, advertise_addr: str = ADDRESS_BROADCAST, listen_addr: str = ''):
        loop = asyncio.get_running_loop()

        # create_datagram_endpoint and create_server does not allow binding to all addresses, so
        # we create the sockets manually
        udp_sock = socket(AF_INET, SOCK_DGRAM)
        udp_sock.setblocking(False)
        udp_sock.bind((listen_addr, KDECONNECT_PORT))

        tcp_sock = None
        for port in range(KDECONNECT_PORT_MIN, KDECONNECT_PORT_MAX):
            tcp_sock = socket(AF_INET, SOCK_STREAM)
            tcp_sock.setblocking(False)
            try:
                tcp_sock.bind((listen_addr, port))
                tcp_sock.listen()
                self.port = port
            except OSError:
                tcp_sock.close()
                logger.warning(f"Port {port} taken. Trying next")
            else:
                break

        if self.port is None:
            logger.critical("Couldn't bind to a suitable tcp port. Exiting")
            exit(1)

        await loop.create_datagram_endpoint(
            lambda: UdpAdvertisementProtocol(self),
            sock=udp_sock
        )
        await loop.create_server(
            lambda: TcpServerSideProtocol(self),
            sock=tcp_sock
        )
        loop.create_task(self.advertise_once(advertise_addr))

    def set_pairing_callback(self, callback: PairingCallback):
        self.pairing_callback = callback

    async def on_pairing_request(self, device: KdeConnectDevice):
        if self.pairing_callback is not None:
            loop = asyncio.get_running_loop()
            result = await loop.create_task(self.pairing_callback(device))
            if result:
                device.confirm_pair()
            else:
                device.reject_pair()
        else:
            logger.warning(f'"{device.device_name}" requested pairing, but no pairing callback '
                           f'was set. Rejecting.')
            device.unpair()

    async def advertise_once(self, advertise_addr: str):
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        try:
            sock.connect((advertise_addr, KDECONNECT_PORT))
            payload = self.encoder.encode(self.identity_payload(with_port=True))
            sock.send(payload)
            logger.debug("Sent udp advertisement")
        finally:
            sock.close()

    async def send_tcp_identity(self, addr: str, port: int, device: KdeConnectDevice):
        loop = asyncio.get_running_loop()

        await loop.create_connection(lambda: TcpClientSideProtocol(self, device), addr, port)

    def identity_payload(self, *, with_port: bool) -> IdentityPayload:
        return IdentityPayload(get_timestamp(), IdentityPayload.Body(
            deviceName=self.device_name,
            deviceId=self.config.device_id,
            deviceType=self.device_type.value,
            incomingCapabilities=["kdeconnect.ping"],
            outgoingCapabilities=[],
            protocolVersion=self.protocol_version.value,
            tcpPort=self.port if with_port else None,
        ))

    def get_ssl_context(self, server_side: bool, device: KdeConnectDevice):
        if server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA")
        ctx.check_hostname = False

        ctx.load_cert_chain(self.config.cert_path, self.config.private_key_path)

        ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        if device.is_paired:
            assert device.certificate is not None
            ctx.load_verify_locations(cadata=device.certificate.public_bytes(serialization.Encoding.DER))
        else:
            ssl_workaround.set_verify_always_pass(ctx, True)
        return ctx