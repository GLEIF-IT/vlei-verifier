import datetime
import os
from typing import Literal

import falcon
import json
from keri import kering
from keri.core import coring, parsing, Siger
from keri.vdr import verifying, eventing

from verifier.core.authorizing import AUTH_EXPIRE
from verifier.core.basing import (
    CRED_CRYPT_INVALID,
    CRED_CRYPT_VALID,
    CredProcessState,
    cred_age_off,
    AUTH_REVOKED,
    AUTH_PENDING,
    AUTH_SUCCESS,
    AUTH_EXPIRE,
    AUTH_FAIL, AidProcessState, AID_CRYPT_INVALID, AID_CRYPT_VALID, Account
)
from verifier.core.resolve_env import VerifierEnvironment
from verifier.core.utils import process_revocations, add_root_of_trust, add_oobi, DigerBuilder, \
    add_state_to_state_history, get_state_to_state_history, verify_signed_headers, SignatureVerificationStatus, \
    process_signature_headers, SignatureHeaderError

PresentationType = Literal["AID", "CREDENTIAL"]


def setup(app, hby, vdb, reger, local=False):
    """Set up verifying endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Database environment for the verifier
        reger (Reger): Database environment for credential registries

    """

    tvy = eventing.Tevery(reger=reger, db=hby.db, local=local)
    vry = verifying.Verifier(hby=hby, reger=reger)

    loadEnds(app, hby, vdb, tvy, vry)
    with open("./src/root_of_trust_oobis/gleif_external.json", "rb") as f:
        json_oobi_gleif = json.loads(f.read())
        aid = json_oobi_gleif.get("aid")
        vlei = bytes(json_oobi_gleif.get("vlei"), "utf8")
        oobi = json_oobi_gleif.get("oobi")
        add_root_of_trust(vlei, hby, tvy, vry, vdb, aid, oobi)


def loadEnds(app, hby, vdb, tvy, vry):
    """Load and map endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Verifier database environment
        tvy (Tevery): transaction event log event processor
        vry (Verifier): credential verification processor

    """

    healthEnd = HealthEndpoint()
    app.add_route("/health", healthEnd)
    statusEnd = StatusEndpoint()
    app.add_route("/status", statusEnd)
    credEnd = PresentationResourceEndpoint(hby, vdb, tvy, vry)
    stateHistEnd = StateHistoryResourceEndpoint(vdb)
    app.add_route("/presentations/history/{aid}", stateHistEnd)
    app.add_route("/presentations/{said}", credEnd)
    rotEnd = RootOfTrustResourceEndpoint(hby, vdb, tvy, vry)
    app.add_route("/root_of_trust/{aid}", rotEnd)
    oobiEnd = OobiResourceEndpoint(hby)
    app.add_route("/oobi", oobiEnd)
    authEnd = AuthorizationResourceEnd(hby, vdb)
    app.add_route("/authorizations/{aid}", authEnd)
    verEnd = RequestVerifierResourceEnd(hby=hby, vdb=vdb)
    app.add_route("/request/verify/{aid}", verEnd)
    sigEnd = SignatureVerifierResourceEnd(hby=hby, vdb=vdb)
    app.add_route("/signature/verify", sigEnd)

    return []


class RootOfTrustResourceEndpoint:
    """Root Of Trust resource endpoint class

    This class allows to add new Root Of Trust.

    """

    def __init__(self, hby, vdb, tvy, vry):
        """Create Root Of Trust resource endpoint instance

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment
            tvy (Tevery): transaction event log event processor
            vry (Verifier): credential verification event processor

        """
        self.hby = hby
        self.vdb = vdb
        self.tvy = tvy
        self.vry = vry

    def on_post(self, req, rep, aid):
        """Root Of Trust Resource PUT Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: AID of credential being presented

        ---
         summary: Add new Root Of Trust
         description: Add new Root Of Trust
         tags:
            - Root Of Trust
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: AID of the new Root Of Trust
         requestBody:
             required: true
             content:
                application/json+cesr:
                  schema:
                    type: application/json
                    format: text
         responses:
           202:
              description: Credential Presentation accepted

        """
        rep.content_type = "application/json"

        if req.content_type not in ("application/json",):
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(msg=f"invalid content type={req.content_type} for Root Of Trust presentation")
            ).encode("utf-8")
            return

        req_media = req.media
        ims = bytes(req_media.get("vlei"), "utf-8")
        oobi = req_media.get("oobi")

        result = add_root_of_trust(ims, self.hby, self.tvy, self.vry, self.vdb, aid, oobi)

        if result:
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    msg=f"Successfully added new Root Of Trust with AID: {aid}",
                )
            ).encode("utf-8")
        else:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(
                    msg=f"Adding new Root Of Trust with AID: {aid} FAILED",
                )
            ).encode("utf-8")


class OobiResourceEndpoint:
    """OOBI presentation resource endpoint class

    This class allows for to add new OOBI.

    """

    def __init__(self, hby):
        """Create OOBI presentation resource endpoint instance

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
        """
        self.hby = hby

    def on_post(self, req, rep):
        """Oobi Presentation Resource PUT Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
        ---
         summary: Add new OOBI
         description: Add new OOBI
         tags:
            - Oobi
         requestBody:
             required: true
             content:
                application/json:
                  schema:
                    type: application/json
                    format: json
         responses:
           202:
              description: New OOBI added

        """
        rep.content_type = "application/json"
        oobi_info = req.media
        result = add_oobi(self.hby, oobi_info.get("oobi"))

        if result:
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    msg=f"Successfully added new OOBI with url: {oobi_info.get("oobi")}",
                )
            ).encode("utf-8")
        else:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(
                    msg=f"Adding new OOBI with url: {oobi_info.get("oobi")} FAILED",
                )
            ).encode("utf-8")


class StateHistoryResourceEndpoint:
    """OOBI presentation resource endpoint class

    This class allows for to add new OOBI.

    """

    def __init__(self, vdb):
        """Get State History resource endpoint instance

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
        """
        self.vdb = vdb

    def on_get(self, req, rep, aid):
        """State History  Resource GET Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: AID of the requestor
        ---
         summary: Get State History for a given aid
         description: Get State History for a given aid
         tags:
            - State History
         requestBody:
             required: true
             content:
                application/json:
                  schema:
                    type: application/json
                    format: json
         responses:
           200:
              description: State History returned

        """
        rep.content_type = "application/json"
        state_history = get_state_to_state_history(self.vdb, aid)

        rep.status = falcon.HTTP_ACCEPTED
        rep.data = json.dumps(
            dict(
                history=state_history,
                aid=aid,
                msg=f"Successfully retrieved State History for AID: {aid}",
            )
        ).encode("utf-8")


class PresentationResourceEndpoint:
    """Credential presentation resource endpoint class

    This class allows for a PUT to a credential SAID specific endpoint to trigger credential presentation
    verification.

    """

    def __init__(self, hby, vdb, tvy, vry):
        """Create credential presentation resource endpoint instance

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment
            tvy (Tevery): transaction event log event processor
            vry (Verifier): credential verification event processor

        """
        self.hby = hby
        self.vdb = vdb
        self.tvy = tvy
        self.vry = vry

    def on_put(self, req, rep, said):
        """Credential Presentation Resource PUT Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            said: qb64 SAID of credential being presented

        ---
         summary: Present vLEI ECR credential for AID authorization to other endpoints
         description: Present vLEI ECR credential for AID authorization to other endpoints
         tags:
            - Credentials
         parameters:
           - in: path
             name: said
             schema:
                type: string
             description: qb64 SAID of credential being presented
         requestBody:
             required: true
             content:
                application/json+cesr:
                  schema:
                    type: application/json
                    format: text
         responses:
           202:
              description: Credential Presentation accepted

        """
        rep.content_type = "application/json"

        if req.content_type not in ("application/json+cesr",):
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(msg=f"invalid content type={req.content_type} for VC presentation")
            ).encode("utf-8")
            return

        ims = req.bounded_stream.read()

        if len(self.vry.cues) > 0:
            rep.status = falcon.HTTP_SERVICE_UNAVAILABLE
            rep.data = json.dumps(
                dict(
                    msg=f"Verifier is busy processing another VC presentation, try credential {said} presentation again later"
                )
            ).encode("utf-8")

        parsing.Parser().parse(ims=ims, kvy=self.hby.kvy, tvy=self.tvy, vry=self.vry)

        found = False
        presentation_type: PresentationType = "CREDENTIAL"
        saids = []

        if not self.vry.cues:
            presentation_type = "AID"
            while self.hby.kvy.cues:
                msg = self.hby.kvy.cues.popleft()
                if "serder" in msg:
                    serder = msg["serder"]
                    if serder.sad.get("i") == said:
                        found = True
            self.hby.kvy.cues.clear()

        while self.vry.cues:
            msg = self.vry.cues.popleft()
            if "creder" in msg:
                creder = msg["creder"]
                if creder.said == said:
                    found = True
                    break

        self.vry.cues.clear()
        if presentation_type == "CREDENTIAL":
            if not found:
                info = f"Presented credential {said} was NOT cryptographically valid, administrator will need to review verifier logs to determine the problem"
                print(info)
                cred_state = CredProcessState(
                    said=said, state=CRED_CRYPT_INVALID, info=info
                )
                self.vdb.iss.pin(keys=(said,), val=cred_state)
                add_state_to_state_history(self.vdb, said, cred_state)
                rep.status = falcon.HTTP_BAD_REQUEST
                rep.data = json.dumps(
                    dict(
                        msg=f"credential {said} from body of request did not cryptographically verify"
                    )
                ).encode("utf-8")
                return

            saider = coring.Saider(qb64=said)
            cred_attrs = creder.sad["a"]
            creds = None
            aid = None
            saids = None
            type = None
            if "i" in cred_attrs:
                # use issuee AID
                aid = cred_attrs["i"]
                saids = self.vry.reger.subjs.get(
                    keys=aid,
                )
                creds = self.vry.reger.cloneCreds(saids, self.hby.db)
                type = "issuee"
            else:
                # no issuee AID, use issuer
                aid = creder.sad["i"]
                saids = self.vry.reger.issus.get(
                    keys=aid,
                )
                creds = self.vry.reger.cloneCreds((saider,), self.hby.db)
                type = "issuer"

            # Here we don't process credentials that have been revoked(We don't update their state)
            # If the credential was revoked we shouldn't update it's state with the new one
            if not self.vdb.iss.get(keys=(aid,)) or (
                    self.vdb.iss.get(keys=(aid,)).state != AUTH_REVOKED or self.vdb.iss.get(keys=(aid,)).said != said):
                print(f"{aid} account cleared after successful presentation")
                # clear any previous login, now that a valid credential has been presented
                self.vdb.accts.rem(keys=(aid,))

                info = f"Credential {said} presented for {aid} is cryptographically valid"
                print(info)
                cred_state = CredProcessState(said=said, state=CRED_CRYPT_VALID, info=info)
                self.vdb.iss.pin(keys=(aid,), val=cred_state)
                self.vdb.iss.pin(keys=(said,), val=cred_state)
                add_state_to_state_history(self.vdb, aid, cred_state)
                # Here we need to check if the credential was revoked and if so we update it's state to AUTH_REVOKED
                process_revocations(self.vdb, creds, said)
                rep.status = falcon.HTTP_ACCEPTED
                rep.data = json.dumps(
                    dict(
                        creds=json.dumps(creds),
                        aid=aid,
                        msg=f"{said} for {aid} as {type} is {cred_state.state}",
                    )
                ).encode("utf-8")
            else:
                rep.status = falcon.HTTP_ACCEPTED
                rep.data = json.dumps(
                    dict(
                        creds=json.dumps(creds),
                        aid=aid,
                        msg=f"{said} for {aid} as {type} is {CRED_CRYPT_VALID}",
                    )
                ).encode("utf-8")
            return
        elif presentation_type == "AID":
            aid = said
            state = self.vdb.icp.get(keys=(said,))
            if state:
                rep.status = falcon.HTTP_ACCEPTED
                rep.data = json.dumps(
                    dict(
                        aid=aid,
                        msg=f"AID {aid} presentation status: {state.state}",
                    )
                ).encode("utf-8")
                return
            if not found:
                info = f"Presented AID {said} was NOT cryptographically valid, administrator will need to review verifier logs to determine the problem"
                print(info)
                aid_state = AidProcessState(
                    aid=aid, state=AID_CRYPT_INVALID, info=info
                )
                self.vdb.icp.pin(keys=(said,), val=aid_state)
                add_state_to_state_history(self.vdb, aid, aid_state)
                rep.status = falcon.HTTP_BAD_REQUEST
                rep.data = json.dumps(
                    dict(
                        msg=f"AID {aid} from body of request did not cryptographically verify"
                    )
                ).encode("utf-8")
                return

            info = f"AID {aid} presented is cryptographically valid"
            print(info)
            aid_state = AidProcessState(aid=aid, state=AID_CRYPT_VALID, info=info)
            self.vdb.icp.pin(keys=(aid,), val=aid_state)
            add_state_to_state_history(self.vdb, aid, aid_state)
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    aid=aid,
                    msg=f"AID {aid} presentation status: {aid_state.state}",
                )
            ).encode("utf-8")
            return

    def on_get(self, req, rep, said):
        """Loop over any credential presentations in the iss database.

        Credential presentations are placed in the iss database and this loop processes them, first checking to see
        if the credential has been cryptographically verified then applies the EBA specific business logic.

        """

        state: CredProcessState = self.vdb.iss.get(keys=(said,))
        is_aged_off, state = cred_age_off(state, 600.0)
        if state is None:
            rep.status = falcon.HTTP_NO_CONTENT
            rep.data = json.dumps(
                dict(
                    msg=f"Cred {said} is not found: state is '{state.state}', info='{state.info}'",
                )
            ).encode("utf-8")
            return
        elif is_aged_off:
            rep.status = falcon.HTTP_RESET_CONTENT
            rep.data = json.dumps(
                dict(
                    msg=f"Cred {said} has aged_off: state is '{state.state}', info='{state.info}'",
                )
            ).encode("utf-8")
            return
        else:
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    msg=f"Cred {said} state is '{state.state}', info='{state.info}'",
                )
            ).encode("utf-8")
            return


class AuthorizationResourceEnd:
    """Authroization resource endpoint

    This resource endpoint class provides a GET method for verifying if an AID has
     previously presented a valid vLEI ECR credential.

    """

    def __init__(self, hby, vdb):
        """Create authorization resource endpoint

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment
        """
        self.hby = hby
        self.vdb = vdb

    def _process_aid_auth(self, aid: str):
        acct: Account = self.vdb.accts.get(keys=(aid,))
        state: AidProcessState = self.vdb.icp.get(keys=(aid,))
        aid_presented = True
        auth_success = False
        if acct is None:
            auth_success = False
            if state is None:
                aid_presented = False
                data = dict(
                    msg=f"no presentation found for identifier {aid}"
                )
            else:
                data = dict(
                    msg=f"identifier {aid} presentation failed with status {state.state}"
                )
        else:
            auth_success = True
            data = dict(
                aid=aid,
                said=aid,
                lei=None,
                role=None,
                msg=f"AID {aid} has a valid AID login account",
            )
        return auth_success, aid_presented, data

    def _process_cred_auth(self, aid: str):
        acct: Account = self.vdb.accts.get(keys=(aid,))
        state: CredProcessState = self.vdb.iss.get(keys=(aid,))
        cred_presented = True
        auth_success = False
        if acct is None or state is None or state.state == AUTH_EXPIRE:
            auth_success = False
            if state is None:
                cred_presented = False
                data = dict(
                    msg=f"identifier {aid} has no access and no authorization being processed"
                )
            else:
                data = dict(
                    msg=f"identifier {aid} presented credentials {state.said}, w/ status {state.state}, info: {state.info}"
                )
        else:
            state: CredProcessState = self.vdb.iss.get(keys=(aid,))
            auth_success = True
            data = dict(
                aid=aid,
                said=acct.said,
                lei=acct.lei,
                role=state.role,
                msg=f"AID {aid} w/ lei {acct.lei} has valid login account",
            )

        return auth_success, cred_presented, data

    def on_get(self, req, rep, aid):
        """Authorization Resource GET Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: qb64 identifier prefix of presenter to check

        ---
         summary:
         description: Verifies is a given AID has previously submitted a valid vLEI ECR credential.
         tags:
            - Authorizations
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: qb64 AID of presenter
         responses:
           200:
              description: AID is authorized to sign requests
           404:
              description: AID has never presented any credentials
           403:
              description: AID has presented an invalid or subsequently revoked credential

        """
        rep.content_type = "application/json"
        env = VerifierEnvironment.resolve_env()
        if env.mode == "production":
            headers = req.headers
            try:
                sign, data = process_signature_headers(headers, req)
            except SignatureHeaderError as e:
                rep.status = falcon.HTTP_BAD_REQUEST
                rep.data = json.dumps(dict(msg=str(e))).encode("utf-8")
                return
            encoded_data = data.encode("utf-8")
            verification_status, verification_message = verify_signed_headers(self.hby, aid, sign, encoded_data)
            if verification_status == SignatureVerificationStatus.UNAUTHORIZED:
                rep.status = falcon.HTTP_UNAUTHORIZED
                rep.data = json.dumps(dict(msg=verification_message)).encode("utf-8")
                return
            if verification_status == SignatureVerificationStatus.BAD_SIGNATURE:
                rep.status = falcon.HTTP_BAD_REQUEST
                rep.data = json.dumps(dict(msg=verification_message)).encode("utf-8")
                return

        if aid not in self.hby.kevers:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(dict(msg=f"unknown AID: {aid}")).encode("utf-8")
            return
        aid_auth_status, aid_presented, aid_auth_data = self._process_aid_auth(aid)
        cred_auth_status, cred_presented, cred_auth_data = self._process_cred_auth(aid)
        rep.status = falcon.HTTP_OK if aid_auth_status or cred_auth_status else falcon.HTTP_UNAUTHORIZED
        response = cred_auth_data
        if not cred_auth_status and not cred_presented and aid_presented:
            response = aid_auth_data
        rep.data = json.dumps(response).encode("utf-8")


class RequestVerifierResourceEnd:
    """Request Verifier Resource endpoint class

    This class provides a POST method endpoint that validating HTTP request signatures for AIDs that have previously
    presented a valid vLEI credential.

    """

    def __init__(self, hby, vdb):
        """Create a request verifier resource endpoint class

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment

        """
        self.hby = hby
        self.vdb = vdb

    def on_post(self, req, rep, aid):
        """Request verifier resource POST method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: qb64 identifier prefix of presenter to check

        ---
         summary:
         description: Verifies the signature of request values for authorized AIDs
         tags:
            - Authorizations
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: qb64 AID of presenter
         responses:
           200:
              description: AID is authorized to sign requests
           404:
              description: AID has never presented any credentials
           403:
              description: AID has presented an invalid or subsequently revoked credential
           401:
              description: provided signature is not valid against values of the request

        """
        rep.content_type = "application/json"

        data = req.params.get("data")
        if data is None:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg="request missing data parameter")).encode(
                "utf-8"
            )
            return

        encoded_data = data.encode("utf-8")  # signature is based on encoded data

        sign = req.params.get("sig")
        if sign is None:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg="request missing sig parameter")).encode(
                "utf-8"
            )
            return

        if aid not in self.hby.kevers:
            rep.status = falcon.HTTP_NOT_FOUND
            rep.data = json.dumps(
                dict(msg=f"unknown {aid} used to sign header")
            ).encode("utf-8")
            return

        verification_status, verification_message = verify_signed_headers(self.hby, aid, sign, encoded_data)

        if verification_status == SignatureVerificationStatus.BAD_SIGNATURE:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(
                    msg=verification_message
                )
            ).encode("utf-8")
        elif verification_status == SignatureVerificationStatus.UNAUTHORIZED:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(
                dict(
                    msg=verification_message
                )
            ).encode("utf-8")
        else:
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(dict(msg=verification_message)).encode("utf-8")
        return


class SignatureVerifierResourceEnd:
    """Signature Verifier Resource endpoint class

    This class provides a POST method endpoint that validating signatures for AIDs that have previously presented
    a valid vLEI credential.

    """

    def __init__(self, hby, vdb):
        """Create a signature verifier resource endpoint class

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment

        """
        self.hby = hby
        self.vdb = vdb

    def on_post(self, req, rep):
        """Request verifier resource POST method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
         summary:
         description: Verifies the signature of request values for authorized AIDs
         tags:
            - Authorizations
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: qb64 AID of presenter
         responses:
           202:
              description: Signature valid
           404:
              description: Bad request
           401:
              description: provided signature is not valid against values of the request

        """
        rep.content_type = "application/json"

        data = req.media
        signer_aid = data.get("signer_aid")
        signature = data.get("signature")
        non_prefixed_digest = data.get("non_prefixed_digest")
        if signer_aid is None:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg="request missing signer_aid parameter", code=1)).encode(
                "utf-8"
            )
            return

        if signature is None:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg="request missing signature parameter", code=1)).encode(
                "utf-8"
            )
            return
        try:
            subAcct = self.vdb.accts.get(keys=(signer_aid,))
            if subAcct is None:
                rep.status = falcon.HTTP_UNAUTHORIZED
                rep.data = json.dumps(
                    dict(msg=f"submitter does not have a valid account", code=1)).encode(
                    "utf-8")
                return

            # Now ensure we know who this AID is and that we have their key state
            if signer_aid not in self.hby.kevers:
                rep.status = falcon.HTTP_UNAUTHORIZED
                rep.data = json.dumps(
                    dict(msg=f"signature from unknown AID {signer_aid}", code=1)).encode(
                    "utf-8")
                return

            kever = self.hby.kevers[signer_aid]
            siger = Siger(qb64=signature)
            siger.verfer = kever.verfers[siger.index]  # assign verfer
            if not siger.verfer.verify(siger.raw, bytes(non_prefixed_digest, "utf-8")):  # verify each sig
                rep.status = falcon.HTTP_UNAUTHORIZED
                rep.data = json.dumps(
                    dict(msg=f"signature {siger.index} invalid or wasn't signed by {signer_aid}",
                         code=1)).encode("utf-8")
                return


        except KeyError as e:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(dict(msg=f"Invalid signature in manifest missing '{e.args[0]}'", code=1)).encode(
                "utf-8")
            return
        except OSError:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(dict(msg=f"signature element={signature} points to invalid file", code=1)).encode(
                "utf-8")
            return

        except Exception as e:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(dict(msg=f"{e}", code=1)).encode("utf-8")
            return

        rep.status = falcon.HTTP_ACCEPTED
        rep.data = json.dumps(dict(msg="Signature Valid", code=3)).encode("utf-8")
        return


class HealthEndpoint:
    def __init__(self):
        pass

    def on_get(self, req, rep):
        rep.content_type = "application/json"
        rep.status = falcon.HTTP_OK
        rep.data = json.dumps(dict(msg="vLEI verification service is healthy")).encode(
            "utf-8"
        )
        return


class StatusEndpoint:
    def __init__(self):
        pass

    def on_get(self, req, rep):
        rep.content_type = "application/json"
        rep.status = falcon.HTTP_OK
        rep.data = json.dumps({
            "status": "OK",
            "mode": "verifier"
        }
        )
        return
