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

    with habbing.openHby(name="verifier", salt=salter.qb64, temp=True) as hby:
        # habbing.openHby(name="holder", salt=salter.qb64, temp=True) as holdhby:
        
        crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_daliases_cred(seeder,hby)
        # addDaliasesSchema(hby)
        
        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        issAndCred.extend(acdcmsgs)
        acdc = issAndCred.decode("utf-8")
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=crdntler.rgy.reger, local=True)

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{said}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_OK
        # result = client.simulate_get('/authorizations/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        # assert result.status == falcon.HTTP_OK
        # result = client.simulate_get('/request/verify/EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk')
        # assert result.status == falcon.HTTP_OK


def get_daliases_cred(seeder, hby):
    salt = b'fedcba9876543210'
    salter = coring.Salter(raw=salt)

    hab = hby.makeHab("hHab")
    crdntler = issue_desig_aliases(
        seeder, hby, hab, registryName="dAliases")
    saiders = crdntler.rgy.reger.schms.get(
        keys=DES_ALIASES_SCHEMA.encode("utf-8"))
    creds = crdntler.rgy.reger.cloneCreds(saiders,hab.db)
    
    print(f"Generating CESR event stream data from hab")
    kmsgs = bytearray()
    genKelCesr(hby, hab.pre, kmsgs)

    #add designated aliases TELs and ACDCs
    creder, prefixer, seqner, saider = genCred(crdntler.rgy.reger, hab.pre, DES_ALIASES_SCHEMA)
    
    if creder.regi is not None:
        tmsgs = bytearray()
        genTelCesr(crdntler.rgy.reger, creder.regi, tmsgs)
        imsgs = bytearray()
        genTelCesr(crdntler.rgy.reger, creder.said, imsgs)
    acdcmsgs = bytearray()
    genAcdcCesr(hby, hab.pre, creder, prefixer, seqner, saider, acdcmsgs)

    return crdntler, saiders[0].qb64, kmsgs, tmsgs, imsgs, acdcmsgs
    # revoke_cred(hab, crdntler.rgy, crdntler.rgy.registryByName("dAliases"), creds[0])