import os

import lmdb
from keri.db import subing, koming

from verifier.core.basing import VerifierBaser


def test_vdb():
    baser = VerifierBaser(reopen=True)  # default is to not reopen
    assert isinstance(baser, VerifierBaser)
    assert baser.name == "vdb"
    assert baser.temp is False
    assert isinstance(baser.env, lmdb.Environment)
    assert baser.path.endswith("/vdb/vdb")
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.iss, subing.CesrSuber)
    assert isinstance(baser.rev, subing.CesrSuber)
    assert isinstance(baser.accts, subing.Suber)
    assert isinstance(baser.rpts, subing.CesrIoSetSuber)
    assert isinstance(baser.stts, subing.CesrIoSetSuber)
    assert isinstance(baser.imgs, lmdb._Database)
    assert isinstance(baser.stats, koming.Komer)

    baser.close(clear=True)
    assert not os.path.exists(baser.path)
    assert not baser.opened
