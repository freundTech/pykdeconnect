from __future__ import annotations

import asyncio
import logging
import ssl
from abc import ABC, abstractmethod
from asyncio import Future, Transport, transports
from json import JSONDecodeError
from typing import TYPE_CHECKING, Optional, Tuple, cast

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate, load_der_x509_certificate

from . import devices, ssl_workaround
from .const import MIN_PROTOCOL_VERSION
from .helpers import get_timestamp
from .payloads import (
    AnyPayload, IdentityPayload, PairPayload, Payload, bytes_to_payload,
    payload_to_bytes
)
from .plugin_registry import PluginRegistry
from .vol_extra import TypedDictVerifier

if TYPE_CHECKING:
    from .client import ClientInfo
    from .device_manager import DeviceManager

logger = logging.getLogger(__name__)


class KdeConnectProtocol(asyncio.Protocol):
    _client_info: ClientInfo
    _device_manager: DeviceManager
    _plugin_registry: PluginRegistry

    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry
    ):
        self._client_info = client_info
        self._device_manager = device_manager
        self._plugin_registry = plugin_registry


class PairingProtocol(KdeConnectProtocol):
    def get_device_from_payload(self, payload: IdentityPayload) -> devices.KdeConnectDevice:
        device_id = payload["body"]["deviceId"]
        device = self._device_manager.get_device(device_id)

        if device is not None:
            device.update_from_payload(payload)
        else:
            device = devices.KdeConnectDevice.from_payload(payload)

        return device


class UdpAdvertisementProtocol(PairingProtocol, asyncio.DatagramProtocol):
    _transport: transports.Transport
    _any_payload_verifier: TypedDictVerifier[AnyPayload]

    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry
    ):
        super().__init__(client_info, device_manager, plugin_registry)
        self._any_payload_verifier = TypedDictVerifier[AnyPayload]()

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, transports.Transport)
        logger.debug("UDP connection made")
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        payload = bytes_to_payload(data)
        payload = self._any_payload_verifier.verify(payload)
        if payload["type"] != "kdeconnect.identity":
            logger.warning('Received payload with type "%s" over udp', payload["type"])
            return
        payload = cast(IdentityPayload, payload)
        device_id = payload["body"]["deviceId"]
        if device_id == self._client_info.device_id:
            # Don't connect to ourselves
            return
        if payload["body"]["protocolVersion"] < MIN_PROTOCOL_VERSION:
            logger.warning("Received udp advertisement with too low protocol version. Ignoring")
            return
        logger.debug("Received udp advertisement: %s", payload)

        device = self.get_device_from_payload(payload)

        if device.is_connected:
            logger.debug("Already connected. Ignoring")
        elif "tcpPort" not in payload["body"]:
            logger.debug("Udp identity packet didn't contain tcpPort")
        else:
            device.is_connected = True
            self._device_manager.connected_devices[device.device_id] = device
            loop = asyncio.get_running_loop()
            asyncio.create_task(
                loop.create_connection(
                    lambda: TcpClientSideProtocol(
                        self._client_info,
                        self._device_manager,
                        self._plugin_registry,
                        device
                    ),
                    addr[0],
                    payload["body"]["tcpPort"]
                )
            )


class PayloadProtocol(KdeConnectProtocol, ABC):
    _buffer: bytearray
    _any_payload_verifier: TypedDictVerifier[AnyPayload]

    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry
    ) -> None:
        super().__init__(client_info, device_manager, plugin_registry)
        self._buffer = bytearray()
        self._any_payload_verifier = TypedDictVerifier[AnyPayload]()

    def data_received(self, data: bytes) -> None:
        self._buffer += data

        found = bytearray(b'\n')
        while found:
            payload_str, found, rest = self._buffer.partition(b'\n')
            if found:
                self.parse_payload(payload_str)
                self._buffer = rest

    def parse_payload(self, payload_str: bytearray) -> None:
        try:
            payload = bytes_to_payload(payload_str)
            payload = self._any_payload_verifier.verify(payload)
        except JSONDecodeError as e:
            logger.warning("Received corrupt package: %s", payload_str.decode())
            logger.warning(e, exc_info=True)
            return

        self.payload_received(payload)

    @abstractmethod
    def payload_received(self, payload: Payload) -> None:
        pass


class UpgradableProtocol(PayloadProtocol, ABC):
    _device: Optional[devices.KdeConnectDevice]
    _plugin_registry: PluginRegistry
    _transport: transports.Transport

    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry
    ) -> None:
        super().__init__(client_info, device_manager, plugin_registry)
        self._device = None
        self.ssl_context_factory = SSLContextFactory(self._client_info)

    def start_connection(self, *, server_side: bool) -> None:
        assert self._device is not None
        loop = asyncio.get_event_loop()
        protocol = DeviceProtocol(
            self._client_info,
            self._device_manager,
            self._plugin_registry,
            self._device,
            self._transport)
        future = loop.create_task(loop.start_tls(
            self._transport, protocol,
            self.ssl_context_factory.get_ssl_context(server_side, self._device),
            server_side=server_side
        ))
        future.add_done_callback(lambda t: protocol.connection_made(t.result()))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._device is None:
            # logger.warning(f'Lost connection before receiving identity packet')
            pass
        else:
            del self._device_manager.connected_devices[self._device.device_id]
            logger.warning('Lost connection to "%s" before starting tls', self._device.device_name)
            if exc is not None:
                logger.warning(exc, exc_info=True)


class TcpServerSideProtocol(PairingProtocol, UpgradableProtocol):
    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self._transport = transport

    def payload_received(self, payload: Payload) -> None:
        if payload["type"] != "kdeconnect.identity":
            logger.warning("Received payload that isn't an identity packet")
            return
        payload = cast(IdentityPayload, payload)
        if payload["body"]["deviceId"] == self._client_info.device_id:
            logger.error("We somehow tried to connect to ourselves. Closing connection")
            self._transport.close()
            return
        if payload["body"]["protocolVersion"] < MIN_PROTOCOL_VERSION:
            logger.warning("Received tcp advertisement with too low protocol version. "
                           "Closing connection")
            self._transport.close()
            return

        logger.debug("Received tcp advertisement: %s", payload)
        self._device = self.get_device_from_payload(payload)
        if self._device.is_connected:
            logger.warning("Device with existing connection tried to connect again. "
                           "Ignoring")
        else:
            self._device_manager.connected_devices[self._device.device_id] = self._device
            self.start_connection(server_side=False)


class TcpClientSideProtocol(UpgradableProtocol):
    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry,
            device: devices.KdeConnectDevice
    ):
        super().__init__(client_info, device_manager, plugin_registry)
        self._device = device

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self._transport = transport

        payload = payload_to_bytes(self._client_info.identity_payload(with_port=False))
        self._transport.write(payload)
        logger.debug("Sent identity to %s", self._transport.get_extra_info('peername'))

        self.start_connection(server_side=True)

    def payload_received(self, payload: Payload) -> None:
        logger.warning("Received payload before upgrading to TLS")


class DeviceProtocol(PayloadProtocol):
    _transport: transports.Transport
    _old_transport: transports.Transport
    _device: devices.KdeConnectDevice
    _plugin_registry: PluginRegistry

    _pair_payload_verifier: TypedDictVerifier[PairPayload]

    _on_con_lost: Future[None]

    def __init__(
            self,
            client_info: ClientInfo,
            device_manager: DeviceManager,
            plugin_registry: PluginRegistry,
            device: devices.KdeConnectDevice,
            old_transport: Transport
    ) -> None:
        super().__init__(client_info, device_manager, plugin_registry)
        self._device = device
        self._old_transport = old_transport
        self._pair_payload_verifier = TypedDictVerifier[PairPayload]()
        self._on_con_lost = asyncio.get_event_loop().create_future()

    def connection_made(self, transport: transports.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self._transport = transport
        self._device.protocol = self
        asyncio.create_task(self._device_manager.device_connected(self._device))
        logger.debug("Upgraded connection to TLS: %s", self._device.device_name)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.debug("Connection lost to %s", self._device.device_name)
        del self._device_manager.connected_devices[self._device.device_id]
        self._device.protocol = None

        asyncio.create_task(self._device_manager.device_disconnected(self._device))

        self._on_con_lost.set_result(None)

    def payload_received(self, payload: Payload) -> None:
        if payload["type"] == "kdeconnect.pair":
            payload = self._pair_payload_verifier.verify(payload)
            if payload["body"]["pair"]:
                if self._device.wants_pairing:
                    self._device.set_paired()
                else:
                    asyncio.create_task(self._device_manager.on_pairing_request(self._device))
            else:
                if self._device.is_paired:
                    self._device_manager.unpair(self._device)
        else:
            plugin = self._plugin_registry.get_plugin_for_type(self._device, payload["type"])

            if plugin is not None:
                asyncio.create_task(plugin.handle_payload(payload))
            else:
                logger.debug(
                    'Received payload %s from "%s" but found no handler for it',
                    payload,
                    self._device.device_name
                )

    def send_pairing_payload(self, pair: bool) -> None:
        payload: PairPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.pair",
            "body": {
                "pair": pair
            }
        }
        self.send_payload(payload)

    def send_payload(self, payload: Payload) -> None:
        payload_str = payload_to_bytes(payload)
        self._transport.write(payload_str)

    def get_certificate(self) -> Certificate:
        ssl_obj = self._transport.get_extra_info("ssl_object")
        return load_der_x509_certificate(ssl_obj.getpeercert(True))

    async def close_connection(self) -> None:
        self._transport.close()

        try:
            await asyncio.wait_for(asyncio.shield(self._on_con_lost), 1)
        except asyncio.TimeoutError:
            # If our partner doesn't close the connection after receiving notify-close we have to
            # close it ourselves.
            self._old_transport.close()

            await self._on_con_lost


class SSLContextFactory:
    client_info: ClientInfo

    def __init__(self, client_info: ClientInfo):
        self.client_info = client_info

    def get_ssl_context(
            self,
            server_side: bool,
            device: devices.KdeConnectDevice
    ) -> ssl.SSLContext:
        if server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(
            # Ciphers taken from KDEConnect source code
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA"
        )
        ctx.check_hostname = False

        ctx.load_cert_chain(self.client_info.cert_path, self.client_info.private_key_path)

        ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        if device.is_paired:
            assert device.certificate is not None
            ctx.load_verify_locations(cadata=device.certificate.public_bytes(
                serialization.Encoding.DER
            ))
        else:
            ssl_workaround.set_verify_always_pass(ctx, True)

        return ctx
