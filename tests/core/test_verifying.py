import falcon

import falcon.testing
from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

from verifier.core import verifying, basing


def test_setup_and_endpoints():
    salt = b'0123456789abcdef'
    salter = coring.Salter(raw=salt)

    with habbing.openHby(name="verifier", salt=salter.qb64, temp=True) as hby:
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        reger = viring.Reger(temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=reger)

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        said = "EAPHGLJL1s6N4w1Hje5po6JPHu47R9-UoJqLweAci2LV"
        vlei_contents = None
        with open('tests/data/credential/credential.cesr', 'r') as cfile:
            vlei_contents = cfile.read()
            result = client.simulate_put(f'/presentationts/{said}',
                                         json=vlei_contents,
                                         headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_OK
        result = client.simulate_get('/authorizations/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        assert result.status == falcon.HTTP_OK
        result = client.simulate_get('/request/verify/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        assert result.status == falcon.HTTP_OK
