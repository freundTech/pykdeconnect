import asyncio
import logging
import traceback
from abc import ABCMeta, abstractmethod, ABC
from asyncio import transports, Transport
from typing import Tuple, TYPE_CHECKING, Optional

from cryptography.x509 import load_der_x509_certificate

from . import devices
from .const import MIN_PROTOCOL_VERSION
from .helpers import get_timestamp
from .payloads import IdentityPayload, PairPayload, Payload

if TYPE_CHECKING:
    from .client import KdeConnectClient


logger = logging.getLogger(__name__)


class UdpAdvertisementProtocol(asyncio.DatagramProtocol):
    client: 'KdeConnectClient'
    transport: transports.Transport

    def __init__(self, client: 'KdeConnectClient'):
        self.client = client

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, transports.Transport)
        logger.debug("UDP connection made")
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        #payload = self.client.decoder.decode(data, IdentityPayload)
        if payload.body.deviceId == self.client.config.device_id:
            return
        if payload.body.protocolVersion < MIN_PROTOCOL_VERSION:
            logger.warning(f"Received udp advertisement with too low protocol version. Ignoring")
            return
        logger.debug(f"Received udp advertisement: {payload}")
        device = devices.KdeConnectDevice.from_payload(payload, self.client)

        if payload.body.tcpPort is not None and device.device_id not in self.client.known_devices:
            self.client.known_devices[device.device_id] = device
            loop = asyncio.get_event_loop()
            loop.create_task(self.client.send_tcp_identity(addr[0], payload.body.tcpPort, device))
        else:
            logger.debug("Already connected. Ignoring")


class PayloadProtocol(asyncio.Protocol, ABC):
    client: 'KdeConnectClient'
    buffer: bytearray

    def __init__(self, client: 'KdeConnectClient'):
        self.client = client
        self.buffer = bytearray()

    def data_received(self, data: bytes) -> None:
        self.buffer += data

        payload_str, found, rest = self.buffer.partition(b'\n')
        if found:
            self.buffer = rest
            try:
                payload = self.client.decoder.decode(payload_str)
            except (ValueError, TypeError) as e:
                logger.warning("Received corrupt package:")
                logger.warning(payload_str.decode('utf-8'))
                logger.error(e, exc_info=True)
                return

            self.payload_received(payload)
        else:
            self.buffer = payload_str

    @abstractmethod
    def payload_received(self, payload: Payload):
        pass


class UpgradableProtocol(PayloadProtocol, ABC):
    device: Optional['devices.KdeConnectDevice']
    transport: transports.Transport

    def __init__(self, client: 'KdeConnectClient'):
        super().__init__(client)
        self.device = None

    def start_connection(self, *, server_side: bool):
        assert self.device is not None
        loop = asyncio.get_event_loop()
        device_listener = self.device.get_protocol()
        future = loop.create_task(loop.start_tls(
            self.transport, device_listener,
            self.client.get_ssl_context(server_side, self.device),
            server_side=server_side
        ))
        future.add_done_callback(lambda t: device_listener.connection_made(t.result()))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self.device is None:
            # logger.warning(f'Lost connection before receiving identity packet')
            pass
        else:
            del self.client.known_devices[self.device.device_id]
            logger.warning(f'Lost connection to "{self.device.device_name}" before starting tls')
            if exc is not None:
                logger.warning(traceback.format_exception(None, exc, exc.__traceback__))


class TcpServerSideProtocol(UpgradableProtocol):
    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport

    def payload_received(self, payload: Payload) -> None:
        if not isinstance(payload, IdentityPayload):
            logger.warning("Received payload that isn't an identity packet")
            return
        if payload.body.deviceId == self.client.config.device_id:
            self.transport.close()
            return
        if payload.body.protocolVersion < MIN_PROTOCOL_VERSION:
            self.transport.close()
            return
        logger.debug(f"Received tcp advertisement: {payload}")
        if payload.body.deviceId in self.client.known_devices:
            logger.debug("Already connected. Ignoring")
            self.transport.close()
        else:
            self.device = devices.KdeConnectDevice.from_payload(payload, self.client)
            self.client.known_devices[self.device.device_id] = self.device

            self.start_connection(server_side=False)


class TcpClientSideProtocol(UpgradableProtocol):
    def __init__(self, client: 'KdeConnectClient', device: 'devices.KdeConnectDevice'):
        super().__init__(client)
        self.device = device

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport

        payload = self.client.encoder.encode(self.client.identity_payload(with_port=False))
        self.transport.write(payload)
        logger.debug(f"Sent identity to {self.transport.get_extra_info('peername')}")

        self.start_connection(server_side=True)

    def payload_received(self, payload: Payload) -> None:
        logger.warning("Received payload before upgrading to TLS")


class DeviceProtocol(PayloadProtocol):
    transport: transports.Transport
    client: 'KdeConnectClient'
    device: 'devices.KdeConnectDevice'

    def __init__(self, device: 'devices.KdeConnectDevice', client: 'KdeConnectClient'):
        super().__init__(client)
        self.device = device

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport
        logger.debug(f"Upgraded connection to TLS: {self.device.device_name}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        del self.client.known_devices[self.device.device_id]

    def payload_received(self, payload: Payload) -> None:
        logger.debug(f"Received payload {payload}")
        if isinstance(payload, PairPayload):
            if payload.body.pair:
                if self.device.wants_pairing:
                    self.device.set_paired()
                else:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self.client.on_pairing_request(self.device))
            else:
                self.device.set_unpaired()
        else:
            # self.device.handle_message(payload)
            pass

    def send_pairing_packet(self, pair) -> None:
        payload = PairPayload(get_timestamp(), PairPayload.Body(pair))
        payload_str = self.client.encoder.encode(payload)
        self.transport.write(payload_str)

    def get_certificate(self):
        ssl_obj = self.transport.get_extra_info("ssl_object")
        return load_der_x509_certificate(ssl_obj.getpeercert(True))
