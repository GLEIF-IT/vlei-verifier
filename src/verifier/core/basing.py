# -*- encoding: utf-8 -*-
"""
vLEI Verification Servcie
verifier.core.basing module

Database support
"""
from dataclasses import dataclass

from keri.core import coring
from keri.db import dbing, subing, koming
from keri.db.subing import CesrIoSetSuber


@dataclass
class ReportStats:
    """ Report statistics dataclass for tracking"""

    submitter: str = None
    filename: str = None
    status: str = None
    contentType: str = None
    size: int = 0
    message: str = ""


class VerifierBaser(dbing.LMDBer):
    """
    VerifierBaser stores credential presentations, successful verifications and revocations alongside holder AIDs

    This database also provides sub-databases for report verification status

    """
    TailDirPath = "keri/vdb"
    AltTailDirPath = ".verifier/vdb"
    TempPrefix = "keri_vdb_"

    def __init__(self, name="vdb", headDirPath=None, reopen=True, **kwa):
        """  Create verifier database

        Parameters:
            headDirPath (str): override for root directory
            reopen (bool): True means call reopen on database object creations
            kwa (dict): additional key word argument pass through for database initialization
        """
        self.iss = None
        self.rev = None

        self.accts = None

        # Report database linking AID of uploader to SAID of uploaded report
        self.rpts = None

        # Report SAIDs indexed by status
        self.stts = None

        # Data chunks for uploaded report, indexed by SAID plus chunk index
        self.imgs = None

        # Komer instance of ReportStats data class, keyed by SAID
        self.stats = None

        super(VerifierBaser, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """  Opens database environment and initializes all sub-dbs

        Parameters:
            **kwa (dict): key word argument pass through for database initialization

        Returns:
            env: database environment for verifier database

        """
        super(VerifierBaser, self).reopen(**kwa)

        # presentations that are waiting for the credential to be received and parsed
        self.iss = subing.CesrSuber(db=self, subkey='iss.', klas=coring.Dater)

        # revocations that are waiting for the TEL event to be received and processed
        self.rev = subing.CesrSuber(db=self, subkey='rev.', klas=coring.Dater)

        # presentations with resolved credentials are granted access
        self.accts = subing.Suber(db=self, subkey='accts', klas=(coring.Saider,))

        # Report database linking AID of uploader to DIG of uploaded report
        self.rpts = CesrIoSetSuber(db=self, subkey='rpts.', klas=coring.Diger)

        # Report DIGs indexed by status
        self.stts = CesrIoSetSuber(db=self, subkey='stts.', klas=coring.Diger)

        # Data chunks for uploaded report, indexed by DIG plus chunk index
        self.imgs = self.env.open_db(key=b'imgs.')

        # Komer instance of ReportStats data class, keyed by SAID
        self.stats = koming.Komer(db=self,
                                  subkey='stats.',
                                  schema=ReportStats)

        return self.env
