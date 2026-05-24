import os
from datetime import datetime, timedelta, timezone

import lmdb
from keri.db import subing, koming

from verifier.core.basing import (
    CRED_AGE_OFF,
    CRED_CRYPT_VALID,
    CredProcessState,
    VerifierBaser,
    cred_age_off,
)


def test_vdb():
    baser = VerifierBaser(reopen=True)  # default is to not reopen
    assert isinstance(baser, VerifierBaser)
    assert baser.name == "vdb"
    assert baser.temp is False
    assert isinstance(baser.env, lmdb.Environment)
    assert baser.path.endswith("/vdb/vdb")
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.iss, koming.Komer)
    assert isinstance(baser.rev, subing.CesrSuber)
    assert isinstance(baser.accts, koming.Komer)
    assert isinstance(baser.rpts, subing.CesrIoSetSuber)
    assert isinstance(baser.stts, koming.Komer)
    assert isinstance(baser.imgs, lmdb._Database)
    assert isinstance(baser.stats, koming.Komer)

    baser.close(clear=True)
    assert not os.path.exists(baser.path)
    assert not baser.opened


def test_cred_age_off_returns_aged_state():
    old_date = (datetime.now(timezone.utc) - timedelta(seconds=700)).isoformat()
    state = CredProcessState(
        said="Esaid",
        aid="Eaid",
        state=CRED_CRYPT_VALID,
        date=old_date,
    )
    is_aged_off, result = cred_age_off(state, 600.0)
    assert is_aged_off is True
    assert result.state == CRED_AGE_OFF
    assert result.said == "Esaid"


def test_cred_age_off_keeps_fresh_state():
    state = CredProcessState(said="Esaid", aid="Eaid", state=CRED_CRYPT_VALID)
    is_aged_off, result = cred_age_off(state, 600.0)
    assert is_aged_off is False
    assert result.state == CRED_CRYPT_VALID
