# -*- encoding: utf-8 -*-
"""
vLEI Verification Servcie
verfier.core.handling module

EXN Message handling
"""
import datetime

from hio.base import doing
from keri import kering
from keri.core import coring
from keri.help import helping


# Hard-coded vLEI Engagement context role to accept.  This would be configurable in production
EBA_DOCUMENT_SUBMITTER_ROLE = "EBA Data Submitter"


# Hard coded credential JSON Schema SAID for the vLEI Engagement Context Role Credential
class Schema:
    ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"


def setup(hby, vdb, reger, cf):
    """

    Parameters:
        hby (Habery): key store and key log database environment
        vdb (VerifierBaser): verifier specific database for storing accepted credentials and AIDs
        reger (Reger): credential registry database environment
        cf (Configer): configuation file loaded at initialization

    Returns:
        list: list of doers (coroutines) to run for this module

    """
    data = dict(cf.get())
    if "LEIs" not in data:
        raise kering.ConfigurationError("invalid configuration, no LEIs available to accept")

    leis = data.get("LEIs")
    if not isinstance(leis, list) or len(leis) == 0:
        raise kering.ConfigurationError("invalid configuration, invalid LEIs in configuration")

    authorizer = Authorizer(hby, vdb, reger, leis)

    # These lines representing AID keystate and credential revocation state monitoring.
    # witq = agenting.WitnessInquisitor(hby=hby)
    # monitor = Monitorer()

    return [AuthorizationDoer(authorizer)]


class Authorizer:
    """
    Authorizer is responsible for comminucating the receipt and verification of credential
    presentation and revocation messages from external third parties via web API calls.


    """

    TimeoutAuth = 600

    def __init__(self, hby, vdb, reger, leis):
        """
        Create a Authenticator capable of persistent processing of messages and performing
        web hook calls.

        Parameters:
            hby (Habery): identifier database environment
            vdb (VerifierBaser): communication escrow database environment
            reger (Reger): credential registry and database
            leis (list): list of str LEIs to accept credential presentations from

        """
        self.hby = hby
        self.vdb = vdb
        self.reger = reger
        self.leis = leis

        self.clients = dict()

    def processPresentations(self):
        """ Loop over any credential presentations in the iss database.

        Credential presentations are placed in the iss database and this loop processes them, first checking to see
        if the credential has been cryptographically verified then applies the EBA specific business logic.

        """

        for (said,), dater in self.vdb.iss.getItemIter():
            # cancel presentations that have been around longer than timeout
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(seconds=self.TimeoutAuth):
                self.vdb.iss.rem(keys=(said,))
                print(f"removing {said}, it expired")
                continue

            if self.reger.saved.get(keys=(said,)) is not None:
                self.vdb.iss.rem(keys=(said,))
                creder = self.reger.creds.get(keys=(said,))
                match creder.schema:
                    case Schema.ECR_SCHEMA_SAID:
                        self.processEcr(creder)
                    case _:
                        print(f"invalid credential presentation, schema {creder.schema}")

    def processEcr(self, creder):
        """ Process a fully verified engagement context role vLEI credential presentation

        1.  Ensure the LEI is in the list of acceptable LEIs
        2.  Ensure the role matches the required role for submission
        3.  Save the credential as successful for submission acceptance.

        Parameters:
            creder (Creder):  Serializable credential object

        """
        if creder.subject["i"] not in self.hby.kevers:
            print(f"unknown presenter {creder.subject['i']}")
            return

        kever = self.hby.kevers[creder.subject["i"]]

        LEI = creder.subject["LEI"]
        if LEI not in self.leis:
            print(f"LEI: {LEI} not allowed")
            return

        role = creder.subject["engagementContextRole"]

        if role not in (EBA_DOCUMENT_SUBMITTER_ROLE,):
            print(f"{role} in not a valid submitter role")
            return

        print("Successful authentication, storing user.")
        self.vdb.accts.pin(keys=(kever.serder.pre,), val=creder.saider)

    def processRevocations(self):
        """ Loop over database of credential revocations.

        Successful verification of revocation removes submission authorization for the holder's AID

        """

        for (said,), dater in self.vdb.rev.getItemIter():

            # cancel revocations that have been around longer than timeout
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(seconds=self.TimeoutAuth):
                self.vdb.rev.rem(keys=(said,))
                continue

            creder = self.reger.ccrd.get(keys=(said,))
            if creder is None:  # received revocation before credential.  probably an error but let it timeout
                continue

            regk = creder.status
            state = self.reger.tevers[regk].vcState(creder.said)
            if state is None:  # received revocation before status.  probably an error but let it timeout
                continue

            elif state.ked['et'] in (coring.Ilks.iss, coring.Ilks.bis):  # haven't received revocation event yet
                continue

            elif state.ked['et'] in (coring.Ilks.rev, coring.Ilks.brv):  # revoked
                self.vdb.rev.rem(keys=(said,))
                self.vdb.revk.pin(keys=(said, dater.qb64), val=creder)

    def processEscrows(self):
        """
        Process credental presentation pipelines

        """
        self.processPresentations()
        self.processRevocations()


class AuthorizationDoer(doing.Doer):
    """ Doer (coroutine) responsible for recurringly execute escrow process for credential processing """

    def __init__(self, authn):
        """ Create coroutine for processing authorizer escrows

        Parameters:
            authn (Authorizer):  Authorizer to process escrows for
        """
        self.authn = authn
        super(AuthorizationDoer, self).__init__()

    def recur(self, tyme):
        """ Process all escrows once per recurrence. """
        self.authn.processEscrows()

        return False


class Monitorer(doing.Doer):
    """ Class to Monitor key state of tracked identifiers and revocation state of their credentials

    WORK IN PROGRESS
    """

    def __init__(self, hby, hab, vdb, reger, witq):
        """
        Create a communicator capable of persistent processing of messages and performing
        web hook calls.

        Parameters:
            hby (Habery): identifier database environment
            hab (Hab): AID environment for default identifier
            vdb (VerifierBaser): communication escrow database environment
            reger (Reger): credential registry and database
            witq (WitnessInquisitor): utility for querying witnesses for updated KEL information

        """

        self.witq = witq
        self.hby = hby,
        self.hab = hab,
        self.vdb = vdb
        self.reger = reger,

        super(Monitorer, self).__init__()

    def recur(self, tymth):
        """ Process active account AIDs to update on rotations

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.

        """
        for (said,), (prefixer, seqner) in self.vdb.accts.getItemIter():
            self.witq.query(src=self.hab.pre, pre=prefixer.qb64)

            kever = self.hby.kevers[prefixer.qb64]
            if kever.sner.num > seqner.num:
                print("Identifier rotation detected")
                creder = self.reger.creds.get(keys=(said,))
                match creder.schema:
                    case Schema.ECR_SCHEMA_SAID:
                        user = creder.subject["LEI"]
                    case _:
                        continue

                self.vdb.accts.pin(keys=(creder.said,), val=(kever.prefixer, kever.sner))

