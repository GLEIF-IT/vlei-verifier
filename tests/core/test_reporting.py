import pytest
from hashlib import sha256

from keri import kering

from src.verifier.core.utils import DigerBuilder


def test_diger_builder():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256_{dig}"
    diger = DigerBuilder.sha256(dig)
    assert diger.verify(BASE_STR) is True


def test_diger_builder_fail():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    WRONG_BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KDT".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256_{dig}"
    diger = DigerBuilder.sha256(dig)
    assert diger.verify(WRONG_BASE_STR) is False


def test_diger_builder_wrong_dig():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    # Here the dig is not prefixed
    with pytest.raises(kering.ValidationError) as exc_info:
        diger = DigerBuilder.sha256(dig)

