import json

import falcon
from keri.core import coring, parsing
from keri.vdr import verifying, eventing


def setup(app, hby, vdb, reger, local=False):
    """ Set up verifying endpoints to process vLEI credential verifications

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
    """ Load and map endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Verifier database environment
        tvy (Tevery): transaction event log event processor
        vry (Verifier): credential verification processor

    """

    healthEnd = HealthEndpoint()
    app.add_route("/health", healthEnd)
    presentEnd = PresentationResourceEndpoint(hby, vdb, tvy, vry)
    app.add_route("/presentations/{said}", presentEnd)
    presentResEnd = AuthorizationResourceEnd(hby, vdb)
    app.add_route("/authorizations/{aid}", presentResEnd)
    requestEnd = RequestVerifierResourceEnd(hby=hby, vdb=vdb)
    app.add_route("/request/verify/{aid}", requestEnd)

    return []


class PresentationResourceEndpoint:
    """ Credential presentation resource endpoint class

    This class allows for a PUT to a credential SAID specific endpoint to trigger credential presentation
    verification.

    """

    def __init__(self, hby, vdb, tvy, vry):
        """ Create credential presentation resource endpoint instance

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
        """  Credential Presentation Resource PUT Method

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

        if req.content_type not in ("application/json+cesr",):
            raise falcon.HTTPBadRequest(description=f"invalid content type={req.content_type} for VC presentation")

        ims = req.bounded_stream.read()

        self.vry.cues.clear()
        
        parsing.Parser().parse(ims=ims,
                               kvy=self.hby.kvy,
                               tvy=self.tvy,
                               vry=self.vry)

        found = False
        while self.vry.cues:
            msg = self.vry.cues.popleft()
            if "creder" in msg:
                creder = msg["creder"]
                if creder.said == said:
                    found = True
                    break

        if not found:
            raise falcon.HTTPBadRequest(description=f"credential {said} from body of request was not found")

        print(f"Credential {said} presented.")

        saider = coring.Saider(qb64=said)
        now = coring.Dater()

        self.vdb.iss.pin(keys=(saider.qb64,), val=now)

        rep.status = falcon.HTTP_ACCEPTED


class AuthorizationResourceEnd:
    """ Authroization resource endpoint

    This resource endpoint class provides a GET method for verifying if an AID has
     previously presented a valid vLEI ECR credential.

    """

    def __init__(self, hby, vdb):
        """ Create authorization resource endpoint

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment
        """
        self.hby = hby
        self.vdb = vdb

    def on_get(self, req, rep, aid):
        """  Authorization Resource GET Method

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
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown AID: {aid}")

        if (saider := self.vdb.accts.get(keys=(aid,))) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        body = dict(
            aid=aid,
            said=saider.qb64
        )

        rep.status = falcon.HTTP_OK
        rep.data = json.dumps(body).encode("utf-8")


class RequestVerifierResourceEnd:
    """ Request Verifier Resource endpoint class

    This class provides a POST method endpoint that validating HTTP request signatures for AIDs that have previously
    presented a valid vLEI credential.

    """

    def __init__(self, hby, vdb):
        """ Create a request verifier resource endpoint class

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment

        """
        self.hby = hby
        self.vdb = vdb

    def on_post(self, req, rep, aid):
        """  Request verifier resource POST method

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
        data = req.params.get("data")
        sign = req.params.get("sig")

        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown {aid} used to sign header")

        if self.vdb.accts.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        kever = self.hby.kevers[aid]
        verfers = kever.verfers
        cigar = coring.Cigar(qb64=sign)

        if not verfers[0].verify(sig=cigar.raw, ser=data.encode("utf-8")):
            raise falcon.HTTPUnauthorized(description=f"{aid} provided invalid signature on request data")

        rep.status = falcon.HTTP_ACCEPTED

class HealthEndpoint:
    def __init__(self):
        pass
    def on_get(self, req, rep):
        rep.status = falcon.HTTP_OK
        rep.data = json.dumps(dict(health="vLEI verification service is healthy")).encode("utf-8")