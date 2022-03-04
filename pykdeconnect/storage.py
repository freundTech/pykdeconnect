import logging
from abc import ABC, abstractmethod
from configparser import ConfigParser, DuplicateSectionError
from pathlib import Path
from typing import Optional, Set

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificate

from .const import KdeConnectDeviceType
from .devices import KdeConnectDevice
from .helpers import CertificateHelper

CONF_KEY_GENERAL = 'general'
CONF_KEY_ID = 'id'
CONF_KEY_NAME = 'name'
CONF_KEY_TYPE = 'type'
CONF_KEY_INCOMING_CAPS = 'incoming_capabilities'
CONF_KEY_OUTGOING_CAPS = 'outgoing_capabilities'


logger = logging.getLogger(__name__)


def _capabilities_to_str(caps: Set[str]) -> str:
    return "\n".join(caps)


def _str_to_capabilities(string: str) -> Set[str]:
    return set(string.split("\n"))


class AbstractStorage(ABC):
    """A storage object storing information on this device and trusted devices."""
    @property
    @abstractmethod
    def device_id(self) -> str:
        """Returns the device id of the local device."""
        pass

    @property
    @abstractmethod
    def cert_path(self) -> Path:
        """Returns the path to this device's SSL certificate."""
        pass

    @property
    @abstractmethod
    def private_key_path(self) -> Path:
        """Returns the path to this device's SSL private key."""
        pass

    @abstractmethod
    def store_device(self, device: KdeConnectDevice) -> None:
        """
        Mark `device` as trusted.

        This method should store the devices SSL certificate.
        """
        pass

    @abstractmethod
    def remove_device(self, device: KdeConnectDevice) -> None:
        """
        Mark `device` as not trusted.

        This method should delete the devices SSL certificate.
        """
        pass

    @abstractmethod
    def load_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        """Try loading a device from storage."""
        pass


class FileStorage(AbstractStorage):
    _config: ConfigParser
    _cert_path: Path
    _private_key_path: Path
    _device_certs_path: Path
    _cert: Certificate
    _private_key: PRIVATE_KEY_TYPES

    def __init__(self, path: Path) -> None:
        self.path = path
        self._ensure_is_dir(path)

        self._config = ConfigParser()
        self._config.read(path / "config.ini")
        if not self._config.has_section(CONF_KEY_GENERAL):
            self._config.add_section(CONF_KEY_GENERAL)

        self._cert_path = path / "cert.pem"
        self._private_key_path = path / "privateKey.pem"

        self._device_certs_path = path / "device_certificates"
        self._ensure_is_dir(self._device_certs_path)

        if not self.private_key_path.is_file():
            self._private_key = CertificateHelper.generate_private_key()
            CertificateHelper.save_private_key(self.private_key_path, self._private_key)
        else:
            self._load_private_key()

        if not self.cert_path.is_file():
            self._cert = CertificateHelper.generate_cert(self.device_id, self._private_key)
            CertificateHelper.save_certificate(self.cert_path, self._cert)
        else:
            self._load_certificate()

    @property
    def device_id(self) -> str:
        if CONF_KEY_ID not in self._config[CONF_KEY_GENERAL]:
            device_id = '1234567890'
            self._config[CONF_KEY_GENERAL][CONF_KEY_ID] = device_id
            self._save()
        else:
            device_id = self._config[CONF_KEY_GENERAL].get(CONF_KEY_ID, None)

        return device_id

    @device_id.setter
    def device_id(self, value: str) -> None:
        self._config[CONF_KEY_GENERAL][CONF_KEY_ID] = value
        self._save()

    @property
    def cert_path(self) -> Path:
        return self._cert_path

    @property
    def private_key_path(self) -> Path:
        return self._private_key_path

    def store_device(self, device: KdeConnectDevice) -> None:
        try:
            self._config.add_section(device.device_id)
        except DuplicateSectionError:
            raise Exception(f'Device "{device.device_name}" is already trusted')
        section = self._config[device.device_id]
        section[CONF_KEY_NAME] = device.device_name
        section[CONF_KEY_TYPE] = device.device_type.value
        section[CONF_KEY_INCOMING_CAPS] = _capabilities_to_str(device.incoming_capabilities)
        section[CONF_KEY_OUTGOING_CAPS] = _capabilities_to_str(device.outgoing_capabilities)
        self._save()
        cert = device.certificate
        assert cert is not None

        with open(self._get_device_cert_path(device.device_id), "wb+") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def remove_device(self, device: KdeConnectDevice) -> None:
        self._config.remove_section(device.device_id)
        self._save()
        self._get_device_cert_path(device.device_id).unlink(missing_ok=True)

    def load_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        if not self._config.has_section(device_id):
            return None

        section = self._config[device_id]
        return KdeConnectDevice(
            section[CONF_KEY_NAME],
            device_id,
            KdeConnectDeviceType(section[CONF_KEY_TYPE]),
            _str_to_capabilities(section[CONF_KEY_INCOMING_CAPS]),
            _str_to_capabilities(section[CONF_KEY_OUTGOING_CAPS]),
            self._get_device_cert(device_id)
        )

    @staticmethod
    def _ensure_is_dir(path: Path) -> None:
        if path.is_dir():
            return
        elif path.exists():
            raise OSError(f'"{path}" is not a directory')
        else:
            path.mkdir(parents=True)

    def _save(self) -> None:
        with open(self.path / "config.ini", "w+") as f:
            self._config.write(f)

    def _get_device_cert_path(self, device_id: str) -> Path:
        return self._device_certs_path / f"{device_id}.pem"

    def _get_device_cert(self, device_id: str) -> Optional[Certificate]:
        path = self._get_device_cert_path(device_id)
        if not path.exists():
            return None

        if not self._config.has_section(device_id):
            return None

        with open(path, 'rb') as f:
            data = f.read()
            return load_pem_x509_certificate(data)

    def _load_private_key(self) -> None:
        with open(self.private_key_path, 'rb') as f:
            data = f.read()
            self._private_key = load_pem_private_key(data, None)

    def _load_certificate(self) -> None:
        with open(self.cert_path, 'rb') as f:
            data = f.read()
            self._cert = load_pem_x509_certificate(data)
