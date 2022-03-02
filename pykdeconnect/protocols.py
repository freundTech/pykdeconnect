from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from asyncio import Future, Transport, transports
from json import JSONDecodeError
from typing import TYPE_CHECKING, Optional, Tuple, cast

from cryptography.x509 import load_der_x509_certificate

from . import devices
from .const import MIN_PROTOCOL_VERSION
from .helpers import get_timestamp
from .payloads import (
    AnyPayload, IdentityPayload, PairPayload, Payload, bytes_to_payload,
    payload_to_bytes
)
from .vol_extra import verify_typed_dict

if TYPE_CHECKING:
    from .client import KdeConnectClient


logger = logging.getLogger(__name__)


class KdeConnectProtocol(asyncio.Protocol):
    client: KdeConnectClient

    def __init__(self, client: KdeConnectClient):
        self.client = client


class PairingProtocol(KdeConnectProtocol):
    def get_device_from_payload(self, payload: IdentityPayload) -> devices.KdeConnectDevice:
        device_id = payload["body"]["deviceId"]
        device = self.client.get_device(device_id)

        if device is not None:
            device.update_from_payload(payload)
        else:
            device = devices.KdeConnectDevice.from_payload(payload)

        return device


class UdpAdvertisementProtocol(PairingProtocol, asyncio.DatagramProtocol):
    transport: transports.Transport

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, transports.Transport)
        logger.debug("UDP connection made")
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        payload = bytes_to_payload(data)
        if payload["type"] != "kdeconnect.identity":
            logger.warning('Received payload with type "%s" over udp', payload["type"])
            return
        payload = cast(IdentityPayload, payload)
        device_id = payload["body"]["deviceId"]
        if device_id == self.client.config.device_id:
            # Don't connect to ourselves
            return
        if payload["body"]["protocolVersion"] < MIN_PROTOCOL_VERSION:
            logger.warning("Received udp advertisement with too low protocol version. Ignoring")
            return
        logger.debug(f"Received udp advertisement: {payload}")

        device = self.get_device_from_payload(payload)

        if device.is_connected:
            logger.debug("Already connected. Ignoring")
        elif payload["body"]["tcpPort"] is None:
            logger.debug("Udp identity packet didn't contain tcpPort")
        else:
            device.is_connected = True
            self.client.connected_devices[device.device_id] = device
            asyncio.create_task(
                self.client.send_tcp_identity(addr[0], payload["body"]["tcpPort"], device)
            )


class PayloadProtocol(KdeConnectProtocol, ABC):
    buffer: bytearray

    def __init__(self, client: KdeConnectClient):
        super().__init__(client)
        self.client = client
        self.buffer = bytearray()

    def data_received(self, data: bytes) -> None:
        self.buffer += data

        found = bytearray(b'\n')
        while found:
            payload_str, found, rest = self.buffer.partition(b'\n')
            if found:
                self.parse_payload(payload_str)
                self.buffer = rest

    def parse_payload(self, payload_str: bytearray):
        try:
            payload = bytes_to_payload(payload_str)
            payload = verify_typed_dict(payload, AnyPayload)
        except JSONDecodeError as e:
            logger.warning(f"Received corrupt package: {payload_str.decode()}")
            logger.warning(e, exc_info=True)
            return

        self.payload_received(payload)

    @abstractmethod
    def payload_received(self, payload: Payload):
        pass


class UpgradableProtocol(PayloadProtocol, ABC):
    device: Optional[devices.KdeConnectDevice]
    transport: transports.Transport

    def __init__(self, client: KdeConnectClient):
        super().__init__(client)
        self.device = None

    def start_connection(self, *, server_side: bool):
        assert self.device is not None
        loop = asyncio.get_event_loop()
        protocol = DeviceProtocol(self.device, self.client, self.transport)
        future = loop.create_task(loop.start_tls(
            self.transport, protocol,
            self.client.get_ssl_context(server_side, self.device),
            server_side=server_side
        ))
        future.add_done_callback(lambda t: protocol.connection_made(t.result()))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self.device is None:
            # logger.warning(f'Lost connection before receiving identity packet')
            pass
        else:
            del self.client.connected_devices[self.device.device_id]
            logger.warning(f'Lost connection to "{self.device.device_name}" before starting tls')
            if exc is not None:
                logger.warning(exc, exc_info=True)


class TcpServerSideProtocol(PairingProtocol, UpgradableProtocol):
    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport

    def payload_received(self, payload: Payload) -> None:
        if payload["type"] != "kdeconnect.identity":
            logger.warning("Received payload that isn't an identity packet")
            return
        payload = cast(IdentityPayload, payload)
        if payload["body"]["deviceId"] == self.client.config.device_id:
            logger.error("We somehow tried to connect to ourselves. Closing connection")
            self.transport.close()
            return
        if payload["body"]["protocolVersion"] < MIN_PROTOCOL_VERSION:
            logger.warning("Received tcp advertisement with too low protocol version. "
                           "Closing connection")
            self.transport.close()
            return

        logger.debug(f"Received tcp advertisement: {payload}")
        self.device = self.get_device_from_payload(payload)
        if self.device.is_connected:
            logger.warning("Device with existing connection tried to connect again. "
                           "Ignoring")
        else:
            self.client.connected_devices[self.device.device_id] = self.device
            self.start_connection(server_side=False)


class TcpClientSideProtocol(UpgradableProtocol):
    def __init__(self, client: KdeConnectClient, device: devices.KdeConnectDevice):
        super().__init__(client)
        self.device = device

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport

        payload = payload_to_bytes(self.client.identity_payload(with_port=False))
        self.transport.write(payload)
        logger.debug(f"Sent identity to {self.transport.get_extra_info('peername')}")

        self.start_connection(server_side=True)

    def payload_received(self, payload: Payload) -> None:
        logger.warning("Received payload before upgrading to TLS")


class DeviceProtocol(PayloadProtocol):
    _transport: transports.Transport
    _old_transport: transports.Transport
    device: devices.KdeConnectDevice

    on_con_lost: Optional[Future[None]]

    def __init__(self, device: devices.KdeConnectDevice, client: KdeConnectClient,
                 old_transport: Transport):
        super().__init__(client)
        self.device = device
        self._old_transport = old_transport
        self.on_con_lost = asyncio.get_event_loop().create_future()

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self._transport = transport
        self.device.protocol = self
        asyncio.create_task(self.client.device_connected(self.device))
        logger.debug(f"Upgraded connection to TLS: {self.device.device_name}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.device.protocol = None

        # TODO: bug
        del self.client.connected_devices[self.device.device_id]
        asyncio.create_task(self.client.device_disconnected(self.device))

        if self.on_con_lost is not None:
            self.on_con_lost.set_result(None)

    def payload_received(self, payload: Payload) -> None:
        if payload["type"] == "kdeconnect.pair":
            pairpayload: PairPayload = verify_typed_dict(payload, PairPayload)
            if pairpayload["body"]["pair"]:
                if self.device.wants_pairing:
                    self.device.set_paired()
                else:
                    asyncio.create_task(self.client.on_pairing_request(self.device))
            else:
                if self.device.is_paired:
                    self.device.set_unpaired()
                    self.client.config.untrust_device(self.device)
        else:
            plugin = self.client.plugin_registry.get_plugin_for_type(
                self.device,
                payload["type"]
            )
            if plugin is not None:
                asyncio.create_task(plugin.handle_payload(payload))
            else:
                logger.debug(f'Received payload {payload} from "{self.device.device_name}" but '
                             f'found no handler for it')

    def send_pairing_payload(self, pair) -> None:
        payload: PairPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.pair",
            "body": {
                "pair": pair
            }
        }
        self.send_payload(payload)

    def send_payload(self, payload: Payload):
        payload_str = payload_to_bytes(payload)
        self._transport.write(payload_str)

    def get_certificate(self):
        ssl_obj = self._transport.get_extra_info("ssl_object")
        return load_der_x509_certificate(ssl_obj.getpeercert(True))

    async def close_connection(self):
        self._transport.close()

        try:
            await asyncio.wait_for(asyncio.shield(self.on_con_lost), 1)
        except asyncio.TimeoutError:
            # If our partner doesn't close the connection after receiving notify-close we have to
            # close it ourselves.
            self._old_transport.close()

            await self.on_con_lost
