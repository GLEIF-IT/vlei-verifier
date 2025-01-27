# -*- encoding: utf-8 -*-
"""
vLEI Verification Servcie
verfier.core.handling module

EXN Message handling
"""
import datetime
from typing import List, Set
import os
from typing import List
from hio.base import doing

from keri import kering
from keri.core import coring
from keri.help import helping

from verifier.core.basing import Account, CredProcessState, AUTH_REVOKED, AUTH_PENDING, AUTH_SUCCESS, AUTH_EXPIRE, \
    AUTH_FAIL, CRED_CRYPT_VALID
from verifier.core.constants import Schema, EBA_DATA_SUBMITTER_ROLE
from verifier.core.resolve_env import VerifierEnvironment

# Hard-coded vLEI Engagement context role to accept.  This would be configurable in production
DEFAULT_EBA_ROLE = "EBA Data Submitter"


# Hard coded credential JSON Schema SAID for the vLEI Engagement Context Role Credential


def setup(hby, vdb, reger):
    """

    Parameters:
        hby (Habery): key store and key log database environment
        vdb (VerifierBaser): verifier specific database for storing accepted credentials and AIDs
        reger (Reger): credential registry database environment
        cf (Configer): configuation file loaded at initialization

    Returns:
        list: list of doers (coroutines) to run for this module

    """
    env = VerifierEnvironment.resolve_env()
    print(env)
    leis = env.trustedLeis
    if leis is not None and not isinstance(leis, list):
        raise kering.ConfigurationError(
            "invalid configuration, invalid LEIs in configuration"
        )

    accepted_schemas = env.authAllowedSchemas
    if not isinstance(accepted_schemas, list):
        raise kering.ConfigurationError(
            "invalid configuration, invalid Allowed Schemas in configuration"
        )

    authorizer = Authorizer(hby, vdb, reger)

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

    def __init__(self, hby, vdb, reger):
        """
        Create a Authenticator capable of persistent processing of messages and performing
        web hook calls.

        Parameters:
            hby (Habery): identifier database environment
            vdb (VerifierBaser): communication escrow database environment
            reger (Reger): credential registry and database
            leis (list): list of str LEIs to accept credential presentations from
            accepted_roles (set): set of accepted engagement context roles
        """
        self.env = VerifierEnvironment.resolve_env()
        self.hby = hby
        self.vdb = vdb
        self.reger = reger

        self.clients = dict()

    def processPresentations(self):
        """Loop over any credential presentations in the iss database.

        Credential presentations are placed in the iss database and this loop processes them, first checking to see
        if the credential has been cryptographically verified then applies the EBA specific business logic.

        """

        for (aid,), state in self.vdb.iss.getItemIter():
            # cancel presentations that have been around longer than timeout
            now = helping.nowUTC()
            age = now - datetime.datetime.fromisoformat(state.date)
            cred_state = None
            if state.state == AUTH_EXPIRE and age > datetime.timedelta(seconds=self.TimeoutAuth * 2):
                self.vdb.iss.rem(keys=(aid,))
            # We keep revoked credentials in the DB because their auth should never expire and the state
            # must always be AUTH_REVOKED to avoid logging in again with the older version of the credential
            elif state.state != AUTH_REVOKED and state.state != AUTH_EXPIRE and age > datetime.timedelta(
                    seconds=self.TimeoutAuth):
                cred_state = CredProcessState(said=state.said, state=AUTH_EXPIRE,
                                              info=f"Cred state exceeded {self.TimeoutAuth}")
                self.vdb.iss.pin(keys=(aid,), val=cred_state)
                print(
                    f"{state.said} for {aid}, has expired: {age} greater than {self.TimeoutAuth}"
                )
            elif (
                    self.reger.saved.get(keys=(state.said,)) is not None
                    and state.state == CRED_CRYPT_VALID
            ):
                print(f"{state.said} for {aid}, {AUTH_PENDING}")
                self.vdb.iss.rem(keys=(aid,))
                cred_state = CredProcessState(said=state.said, state=AUTH_PENDING)
                creder = self.reger.creds.get(keys=(state.said,))
                # are there multiple creds for the same said?
                passed_cred_filters, info = self.cred_filters(creder)
                if passed_cred_filters:
                    cred_state = CredProcessState(said=state.said, state=AUTH_SUCCESS, info=info,
                                                  role=creder.attrib["engagementContextRole"] or creder.attrib[
                                                      "officialRole"])
                    acct = Account(creder.attrib["i"], creder.said, creder.attrib["LEI"])
                    self.vdb.accts.pin(keys=(creder.attrib["i"],), val=acct)
                else:
                    cred_state = CredProcessState(said=state.said, state=AUTH_FAIL, info=info)
                self.vdb.iss.pin(keys=(aid,), val=cred_state)
            else:
                # No need to process state.state == CRED_CRYPT_INVALID or state.state == AUTH_EXPIRE or state.state == AUTH_FAIL or state.state == AUTH_REVOKED or state.state == AUTH_SUCCESS:
                continue

    def cred_filters(self, creder) -> tuple[bool, str]:
        """Process a fully verified engagement context role vLEI credential presentation

        1.  If the LEI filter is configured, ensure the LEI is in the list of acceptable LEIs
        2.  Ensure the role matches the required role for submission
        3.  Save the credential as successful for submission acceptance.

        Parameters:
            creder (Creder):  Serializable credential object

        """
        res = False, f"Cred filters not processed"
        print("SCHEMA!!: ", creder.schema, self.env.authAllowedSchemas)
        if creder.schema in self.env.authAllowedSchemas:
            res = True, f"passed schema check"
        elif Schema.schema_names.get(creder.schema):
            res = False, f"Can't authorize cred with {Schema.schema_names[creder.schema]} schema"
        else:
            res = False, f"Can't authorize cred with unknown schema {creder.schema}"

        if res[0]:
            if creder.issuer not in self.hby.kevers:
                res = False, f"unknown issuer {creder.issuer}"
            elif creder.attrib["i"] is None or creder.attrib["i"] not in self.hby.kevers:
                print(f"unknown issuee {creder.attrib["i"]}")
            elif len(self.env.trustedLeis) > 0 and creder.attrib["LEI"] not in self.env.trustedLeis:
                # only process LEI filter if LEI list has been configured
                res = False, f"LEI: {creder.attrib["LEI"]} not allowed"
            elif not (chain := self.chain_filters(creder))[0]:
                res = chain
            else:
                res = True, f"Credential passed filters for user {creder.attrib["i"]} with LEI {creder.attrib["LEI"]}"
        print(f"Cred filter status {res[0]}, {res[1]}")
        return res

    def chain_filters(self, creder) -> tuple[bool, str]:
        chain_success = False
        chain_msg = f"Unknown credential schema type {creder.schema} not supported"
        cred_type = Schema.schema_names.get(creder.schema)
        match creder.schema:
            case Schema.ECR_SCHEMA | Schema.ECR_SCHEMA_PROD | Schema.TEST_SCHEMA:
                if creder.edge.get("auth"):
                    # The edge of the ECR_AUTH should come from the same LEI
                    valid_edges = {
                        Schema.ECR_AUTH_SCHEMA1: {"LEI": creder.attrib["LEI"]},
                        Schema.ECR_AUTH_SCHEMA2: {"LEI": creder.attrib["LEI"]}
                    }
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["auth"],
                                                                 valid_edges=valid_edges)
                elif creder.edge.get("le"):
                    # The edge of the LE should come from the same LEI
                    valid_edges = {
                        Schema.LE_SCHEMA1: {"LEI": creder.attrib["LEI"]},
                        Schema.LE_SCHEMA2: {"LEI": creder.attrib["LEI"]}
                    }
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["le"], valid_edges=valid_edges)
                else:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
            case Schema.OOR_SCHEMA:
                if creder.edge.get("auth"):
                    # The edge of the OOR_AUTH should come from the same LEI
                    valid_edges = {
                        Schema.OOR_AUTH_SCHEMA: {"LEI": creder.attrib["LEI"]}
                    }
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["auth"],
                                                                 valid_edges=valid_edges)
                else:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
            case Schema.ECR_AUTH_SCHEMA1 | Schema.ECR_AUTH_SCHEMA2:
                if creder.edge.get("le"):
                    # The edge of the LE should come from the same LEI
                    valid_edges = {
                        Schema.LE_SCHEMA1: {"LEI": creder.attrib["LEI"]},
                        Schema.LE_SCHEMA2: {"LEI": creder.attrib["LEI"]}
                    }
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["le"], valid_edges=valid_edges)
                else:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
            case Schema.OOR_AUTH_SCHEMA:
                if creder.edge.get("le"):
                    # The edge of the LE should come from the same LEI
                    valid_edges = {
                        Schema.LE_SCHEMA1: {"LEI": creder.attrib["LEI"]},
                        Schema.LE_SCHEMA2: {"LEI": creder.attrib["LEI"]}
                    }
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["le"], valid_edges=valid_edges)
                else:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
            case Schema.LE_SCHEMA1 | Schema.LE_SCHEMA2:
                valid_edges = {
                    Schema.QVI_SCHEMA1: None,
                    Schema.QVI_SCHEMA2: None
                }
                if creder.edge.get("qvi"):
                    chain_success, chain_msg = self.edge_filters(cred_type, creder.edge["qvi"], valid_edges)
                else:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
            case Schema.QVI_SCHEMA1 | Schema.QVI_SCHEMA2:
                if creder.edge:
                    chain_success, chain_msg = (False, f"Unexpected {cred_type} cred edge {creder.edge}")
                else:
                    issuee_aid = creder.attrib["i"]
                    issuee_kever = self.hby.kvy.kevers[issuee_aid]
                    if not issuee_kever.delegated:
                        chain_success, chain_msg = (False, "The QVI AID must be delegated")
                    elif self.vdb.root.get(keys=(issuee_kever.delpre,)) is None:
                        chain_success, chain_msg = (False, "The QVI AID must be delegated from the Root Of Trust")
                    elif self.env.verifyRootOfTrust:
                        issuer_aid = creder.sad.get("i")
                        if self.vdb.root.get(keys=(issuer_aid,)):
                            chain_success, chain_msg = (True, "QVI")
                        else:
                            chain_success, chain_msg = (
                                False, "The issuer of the QVI credential is not a valid Root Of Trust")
                    else:
                        chain_success, chain_msg = (True, "QVI")
            # TODO add logic related to GLEIF external and internal
            # case Schema.GLEIF_EXTERNAL_SCHEMA:
            #     cred_type = "GLEIF_EXTERNAL"
            #     chain_success, chain_msg = self.edge_filters(cred_type, creder.edge, [Schema.GLEIF_INTERNAL_SCHEMA])
            # case Schema.GLEIF_INTERNAL_SCHEMA:
            #     cred_type = "GLEIF_INTERNAL"
            case _:
                print(f"{chain_msg}")

        return chain_success, chain_msg

    def edge_filters(self, cred_type: str, edge, valid_edges: dict):
        chain_msg = "Expected edge "
        chain_success = False
        chain = None
        if not edge:
            chain_msg = f"{cred_type} cred should have an edge"
            chain_success = False
        elif edge["s"] in valid_edges.keys():
            e_cred = self.reger.creds.get(keys=(edge["n"],))
            e_attr_filters = valid_edges[edge["s"]]
            if e_attr_filters:
                self.attr_filters(e_cred, e_attr_filters)
            chain = self.chain_filters(e_cred)
            chain_success = chain[0]
            if not chain_success:
                chain_msg = chain[1]
            else:
                chain_msg = chain[1] + f"->{cred_type}"
        else:
            chain_success = False
            chain_msg = f"{cred_type} should chain to schema {dict.keys()}, not {edge["s"]}"

        if not chain_success:
            chain_msg = f"{cred_type} chain validation failed, " + chain_msg

        return chain_success, chain_msg

    def attr_filters(self, cred, valid_attrs: dict):
        for key in valid_attrs.keys():
            assert cred.attrib[key] == valid_attrs[key]

    def processRevocations(self):
        """Loop over database of credential revocations.

        Successful verification of revocation removes submission authorization for the holder's AID

        """

        for (said,), dater in self.vdb.rev.getItemIter():

            # cancel revocations that have been around longer than timeout
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(seconds=self.TimeoutAuth):
                self.vdb.rev.rem(keys=(said,))
                continue

            creder = self.reger.ccrd.get(keys=(said,))
            if (
                    creder is None
            ):  # received revocation before credential.  probably an error but let it timeout
                continue

            regk = creder.status
            state = self.reger.tevers[regk].vcState(creder.said)
            if (
                    state is None
            ):  # received revocation before status.  probably an error but let it timeout
                continue

            elif state.ked["et"] in (
                    coring.Ilks.iss,
                    coring.Ilks.bis,
            ):  # haven't received revocation event yet
                continue

            elif state.ked["et"] in (coring.Ilks.rev, coring.Ilks.brv):  # revoked
                self.vdb.rev.rem(keys=(said,))
                self.vdb.revk.pin(keys=(said, dater.qb64), val=creder)

    def processEscrows(self):
        """
        Process credental presentation pipelines

        """
        self.processPresentations()
        self.processRevocations()


class AuthorizationDoer(doing.Doer):
    """Doer (coroutine) responsible for recurringly execute escrow process for credential processing"""

    def __init__(self, authn):
        """Create coroutine for processing authorizer escrows

        Parameters:
            authn (Authorizer):  Authorizer to process escrows for
        """
        self.authn = authn
        super(AuthorizationDoer, self).__init__()

    def recur(self, tyme):
        """Process all escrows once per recurrence."""
        self.authn.processEscrows()
        return False


class Monitorer(doing.Doer):
    """Class to Monitor key state of tracked identifiers and revocation state of their credentials

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
        self.hby = (hby,)
        self.hab = (hab,)
        self.vdb = vdb
        self.reger = (reger,)

        super(Monitorer, self).__init__()

    def recur(self, tymth):
        """Process active account AIDs to update on rotations

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.

        """
        for acct in self.vdb.accts.getItemIter():
            self.witq.query(src=self.hab.pre, pre=acct.aid)

            kever = self.hby.kevers[acct.aid]
            # TODO update acct to include sequence number
            # if kever.sner.num > sn:
            #     print("Identifier rotation detected")
            #     creder = self.reger.creds.get(keys=(acct.said,))
            #     match creder.schema:
            #         case Schema.ECR_SCHEMA_SAID:
            #             user = creder.subject["LEI"]
            #         case _:
            #             continue

            #     acct = Account(acct.aid, acct.said, user)
            #     self.vdb.accts.pin(keys=(acct.aid,), val=acct)
