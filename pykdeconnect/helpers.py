import asyncio
from asyncio import Future
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import TypeVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def get_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


async def keyboard_interrupt():
    while True:
        try:
            await asyncio.sleep(1)
        except KeyboardInterrupt:
            raise SystemExit


T = TypeVar('T')


async def async_timeout(future: Future[T], default: T, timeout: int):
    await asyncio.sleep(timeout)
    if not future.done():
        future.set_result(default)


class CertificateHelper:
    @staticmethod
    def generate_private_key() -> RSAPrivateKey:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        return key

    @staticmethod
    def save_private_key(path: Path, key: RSAPrivateKey):
        with open(path, 'wb+') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    @staticmethod
    def generate_cert(device_id: str, private_key: RSAPrivateKey) -> Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "freundTech"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "pyKDEConnect"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            # Complain to KDEConnect, not me. That's how they do it
            datetime.utcnow() - timedelta(days=365)
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=10 * 365)
        ).sign(private_key, hashes.SHA256())

        return cert

    @staticmethod
    def save_certificate(path: Path, cert: Certificate):
        with open(path, "wb+") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
