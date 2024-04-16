from .common import *

import falcon
import falcon.testing

from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

import pytest

from verifier.core import verifying, basing

# @pytest.fixture(autouse=True)
# def setup():
#     # Your setup code goes here
#     print("Setting up")

def test_setup_and_endpoints(seeder):
    salt = b'0123456789abcdef'
    salter = coring.Salter(raw=salt)

    # with open('tests/data/credential/credential.cesr', 'r') as cfile:
        # vlei = cfile.read()
    # vlei = json.dumps(cred).encode("utf-8")
    # vlei = outputCred(hby,rgy,said)

    with habbing.openHby(name="verifier", salt=salter.qb64, temp=True) as hby, \
        habbing.openHby(name="holder", salt=salter.qb64, temp=True) as holdhby:
        
        said, cred = get_daliases_cred(seeder,holdhby)
        addDaliasesSchema(hby)    
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        # rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
        reger = viring.Reger(temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=reger)

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{said}',
                                        body=cred,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_OK
        # result = client.simulate_get('/authorizations/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        # assert result.status == falcon.HTTP_OK
        # result = client.simulate_get('/request/verify/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        # assert result.status == falcon.HTTP_OK


def get_daliases_cred(seeder, holdhby):
    salt = b'fedcba9876543210'
    salter = coring.Salter(raw=salt)

    hab = holdhby.makeHab("hHab")
    crdntler = issue_desig_aliases(
        seeder, holdhby, hab, registryName="dAliases")
    saiders = crdntler.rgy.reger.schms.get(
        keys=DES_ALIASES_SCHEMA.encode("utf-8"))
    creds = crdntler.rgy.reger.cloneCreds(saiders,hab.db)
    print(f"Generating CESR event stream data from hab")
    msgs = bytearray()
    genKelCesr(holdhby, hab.pre, msgs)
    #add designated aliases TELs and ACDCs
    genCredCesr(holdhby, crdntler.rgy.reger, hab.pre, DES_ALIASES_SCHEMA, msgs)
    scred = msgs.decode("utf-8")
    return saiders[0].qb64, scred
    # revoke_cred(hab, crdntler.rgy, crdntler.rgy.registryByName("dAliases"), creds[0])