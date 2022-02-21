import logging
from abc import ABC, abstractmethod
from configparser import ConfigParser, DuplicateSectionError
from pathlib import Path
from typing import Optional, Set

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
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


def _capabilities_to_str(caps: Set[str]):
    return "\n".join(caps)


def _str_to_capabilities(string: str) -> Set[str]:
    return set(str.split("\n"))


class AbstractKdeConnectConfig(ABC):
    """
    A config object storing information on this device and trusted devices
    """
    @property
    @abstractmethod
    def device_id(self) -> str:
        """
        Return the device id of the local device
        """
        pass

    @property
    @abstractmethod
    def cert_path(self) -> Path:
        """
        Return the path to this device's SSL certificate
        """
        pass

    @property
    @abstractmethod
    def private_key_path(self) -> Path:
        """
        Return the path to this device's SSL private key
        """
        pass

    @abstractmethod
    def trust_device(self, device: KdeConnectDevice):
        """
        Mark `device` as trusted. This method should store the devices SSL certificate
        """
        pass

    @abstractmethod
    def untrust_device(self, device: KdeConnectDevice):
        """
        Mark `device` as not trusted. This method should delete the devices SSL certificate
        """
        pass

    @abstractmethod
    def get_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        pass


class KdeConnectConfig(AbstractKdeConnectConfig):
    config: ConfigParser
    _cert_path: Path
    _private_key_path: Path
    device_certs_path: Path
    cert: Certificate
    private_key: RSAPrivateKey

    def __init__(self, path: Path):
        self.path = path
        self.ensure_is_dir(path)

        self.config = ConfigParser()
        self.config.read(path / "config.ini")
        if not self.config.has_section(CONF_KEY_GENERAL):
            self.config.add_section(CONF_KEY_GENERAL)

        self._cert_path = path / "cert.pem"
        self._private_key_path = path / "privateKey.pem"

        self.device_certs_path = path / "device_certificates"
        self.ensure_is_dir(self.device_certs_path)

        if not self.private_key_path.is_file():
            self.private_key = CertificateHelper.generate_private_key()
            CertificateHelper.save_private_key(self.private_key_path, self.private_key)
        else:
            self.load_private_key()

        if not self.cert_path.is_file():
            self.cert = CertificateHelper.generate_cert(self.device_id, self.private_key)
            CertificateHelper.save_certificate(self.cert_path, self.cert)
        else:
            self.load_certificate()

    @property
    def cert_path(self) -> Path:
        return self._cert_path

    @property
    def private_key_path(self) -> Path:
        return self._private_key_path

    def ensure_is_dir(self, path: Path):
        if path.is_dir():
            return
        elif path.exists():
            raise OSError(f'"{path}" is not a directory')
        else:
            path.mkdir(parents=True)

    def trust_device(self, device: KdeConnectDevice):
        try:
            self.config.add_section(device.device_id)
        except DuplicateSectionError:
            raise Exception(f'Device "{device.device_name}" is already trusted')
        section = self.config[device.device_id]
        section[CONF_KEY_NAME] = device.device_name
        section[CONF_KEY_TYPE] = device.device_type.value
        section[CONF_KEY_INCOMING_CAPS] = _capabilities_to_str(device.incoming_capabilities)
        section[CONF_KEY_OUTGOING_CAPS] = _capabilities_to_str(device.outgoing_capabilities)
        self.save()
        cert = device.certificate
        assert cert is not None

        with open(self._get_device_cert_path(device.device_id), "wb+") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def untrust_device(self, device: KdeConnectDevice):
        self.config.remove_section(device.device_id)
        self.save()
        self._get_device_cert_path(device.device_id).unlink(missing_ok=True)

    def _get_device_cert_path(self, device_id: str) -> Path:
        return self.device_certs_path / f"{device_id}.pem"

    def _get_device_cert(self, device_id: str) -> Optional[Certificate]:
        path = self._get_device_cert_path(device_id)
        if not path.exists():
            return None

        if not self.config.has_section(device_id):
            return None

        with open(path, 'rb') as f:
            data = f.read()
            return load_pem_x509_certificate(data)

    @property
    def device_id(self) -> str:
        device_id = self.config[CONF_KEY_GENERAL].get(CONF_KEY_ID, None)
        if device_id is None:
            device_id = '1234567890'
            self.config[CONF_KEY_GENERAL][CONF_KEY_ID] = device_id
            self.save()
        return device_id

    @device_id.setter
    def device_id(self, value: str):
        self.config[CONF_KEY_GENERAL][CONF_KEY_ID] = value
        self.save()

    def save(self):
        with open(self.path / "config.ini", "w+") as f:
            self.config.write(f)

    def load_private_key(self):
        with open(self.private_key_path, 'rb') as f:
            data = f.read()
            self.private_key = load_pem_private_key(data, None)

    def load_certificate(self):
        with open(self.cert_path, 'rb') as f:
            data = f.read()
            self.cert = load_pem_x509_certificate(data)

    def get_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        if not self.config.has_section(device_id):
            return None

        section = self.config[device_id]
        return KdeConnectDevice(
            section[CONF_KEY_NAME],
            device_id,
            KdeConnectDeviceType(section[CONF_KEY_TYPE]),
            _str_to_capabilities(section[CONF_KEY_INCOMING_CAPS]),
            _str_to_capabilities(section[CONF_KEY_OUTGOING_CAPS]),
            self._get_device_cert(device_id)
        )
