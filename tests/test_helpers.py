import asyncio
from asyncio import CancelledError, Future
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat._oid import NameOID

from pykdeconnect.helpers import (
    CertificateHelper, async_timeout, get_timestamp, keyboard_interrupt
)
from tests.utils import timeout

TIMESTAMP = 1591524000


@patch("pykdeconnect.helpers.datetime")
def test_timestamp(mocktime):
    mocktime.now = MagicMock(return_value=datetime.fromtimestamp(TIMESTAMP))

    assert get_timestamp() == TIMESTAMP * 1000


@pytest.mark.asyncio
@timeout(10)
@patch("asyncio.Event")
async def test_keyboard_interrupt(event):
    event().wait = AsyncMock(side_effect=KeyboardInterrupt)

    await keyboard_interrupt()


@pytest.mark.asyncio
@timeout(10)
@patch("asyncio.Event")
async def test_keyboard_interrupt_cancelled_error(event):
    event().wait = AsyncMock(side_effect=CancelledError)

    await keyboard_interrupt()


@pytest.mark.asyncio
@timeout(10)
async def test_timeout_not_activated():
    future = Future()
    asyncio.create_task(async_timeout(future, True, 1000))

    future.set_result(False)

    assert await future is False


@pytest.mark.asyncio
@timeout(10)
async def test_timeout_activated():
    future = Future()
    asyncio.create_task(async_timeout(future, True, 0.01))

    assert await future is True


def test_save_load_private_key(tmp_path):
    p = tmp_path / "privateKey.pem"

    key = CertificateHelper.generate_private_key()
    CertificateHelper.save_private_key(p, key)

    key2 = CertificateHelper.load_private_key(p)

    assert key.private_numbers() == key2.private_numbers()


def test_save_load_certificate(tmp_path):
    p = tmp_path / "cert.pem"

    key = CertificateHelper.generate_private_key()
    cert = CertificateHelper.generate_cert("foo", key)

    CertificateHelper.save_certificate(p, cert)

    cert2 = CertificateHelper.load_certificate(p)

    assert cert.public_key().public_numbers() == cert2.public_key().public_numbers()
    assert cert2.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "foo"
