import datetime
import falcon
import json

from keri.core import coring, parsing
from keri.vdr import verifying, eventing
from verifier.core.basing import (
    CRED_CRYPT_INVALID,
    CRED_CRYPT_VALID,
    CredProcessState,
    cred_age_off, AUTH_REVOKED,
)
from verifier.core.utils import process_revocations


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
    credEnd = PresentationResourceEndpoint(hby, vdb, tvy, vry)
    app.add_route("/presentations/{said}", credEnd)
    authEnd = AuthorizationResourceEnd(hby, vdb)
    app.add_route("/authorizations/{aid}", authEnd)
    verEnd = RequestVerifierResourceEnd(hby=hby, vdb=vdb)
    app.add_route("/request/verify/{aid}", verEnd)

    return []


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
        saids = []
        while self.vry.cues:
            msg = self.vry.cues.popleft()
            if "creder" in msg:
                creder = msg["creder"]
                if creder.said == said:
                    found = True

        self.vry.cues.clear()

        if not found:
            info = f"Presented credential {said} was NOT cryptographically valid, administrator will need to review verifier logs to determine the problem"
            print(info)
            cred_state = CredProcessState(
                said=said, state=CRED_CRYPT_INVALID, info=info
            )
            self.vdb.iss.pin(keys=(said,), val=cred_state)
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
        if not self.vdb.iss.get(keys=(aid,)) or (self.vdb.iss.get(keys=(aid,)).state != AUTH_REVOKED or self.vdb.iss.get(keys=(aid,)).said != said):
            print(f"{aid} account cleared after successful presentation")
            # clear any previous login, now that a valid credential has been presented
            self.vdb.accts.rem(keys=(aid,))

            info = f"Credential {said} presented for {aid} is cryptographically valid"
            print(info)
            cred_state = CredProcessState(said=said, state=CRED_CRYPT_VALID, info=info)
            self.vdb.iss.pin(keys=(aid,), val=cred_state)
            self.vdb.iss.pin(keys=(said,), val=cred_state)
            # Here we need to check if the credential was revoked and if so we update it's state to AUTH_REVOKED
            process_revocations(self.vdb, creds, said)
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    creds=json.dumps(creds),
                    msg=f"{said} for {aid} as {type} is {cred_state.state}",
                )
            ).encode("utf-8")
        else:
            rep.status = falcon.HTTP_ACCEPTED
            rep.data = json.dumps(
                dict(
                    creds=json.dumps(creds),
                    msg=f"{said} for {aid} as {type} is {CRED_CRYPT_VALID}",
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
        acct = self.vdb.accts.get(keys=(aid,))
        if aid not in self.hby.kevers:
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(dict(msg=f"unknown AID: {aid}")).encode("utf-8")
        elif acct is None:
            rep.status = falcon.HTTP_UNAUTHORIZED
            state: CredProcessState = self.vdb.iss.get(keys=(aid,))
            if state is None:
                rep.data = json.dumps(
                    dict(
                        msg=f"identifier {aid} has no access and no authorization being processed"
                    )
                ).encode("utf-8")
            else:
                rep.data = json.dumps(
                    dict(
                        msg=f"identifier {aid} presented credentials {state.said}, w/ status {state.state}, info: {state.info}"
                    )
                ).encode("utf-8")
        else:
            body = dict(
                aid=aid,
                said=acct.said,
                lei=acct.lei,
                msg=f"AID {aid} w/ lei {acct.lei} has valid login account",
            )

            rep.status = falcon.HTTP_OK
            rep.data = json.dumps(body).encode("utf-8")
        return


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

        acct = self.vdb.accts.get(keys=(aid,))
        if acct is None:
            rep.status = falcon.HTTP_FORBIDDEN
            rep.data = json.dumps(
                dict(msg=f"identifier {aid} has no valid credential for access")
            ).encode("utf-8")
            return

        kever = self.hby.kevers[aid]
        verfers = kever.verfers
        try:
            cigar = coring.Cigar(qb64=sign)
        except Exception as ex:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(
                dict(
                    msg=f"{aid} provided invalid Cigar signature on encoded request data: {ex}"
                )
            ).encode("utf-8")
            return

        if not verfers[0].verify(sig=cigar.raw, ser=encoded_data):
            rep.status = falcon.HTTP_UNAUTHORIZED
            rep.data = json.dumps(
                dict(
                    msg=f"{aid} signature (Cigar) verification failed on encoding of request data"
                )
            ).encode("utf-8")
            return

        rep.status = falcon.HTTP_ACCEPTED
        rep.data = json.dumps(dict(msg="Signature Valid")).encode("utf-8")
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
