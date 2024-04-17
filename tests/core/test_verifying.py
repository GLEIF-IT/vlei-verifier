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

def test_setup_verifying(seeder):
    salt = b'0123456789abcdef'
    salter = coring.Salter(raw=salt)

    with habbing.openHby(name="verifier", salt=salter.qb64, temp=True) as hby, \
        habbing.openHby(name="holder", salt=salter.qb64, temp=True) as holdhby:
        
        # this is not a vLEI ECR cred on purpose
        # the presentation call should still succeed
        hab, crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_daliases_cred(seeder,holdhby)
        addDaliasesSchema(hby)
        
        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        issAndCred.extend(acdcmsgs)
        acdc = issAndCred.decode("utf-8")
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=crdntler.rgy.reger)

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{said}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_202
        
        hby.kevers[hab.pre] = hab.kever
        
        # cred is not an LEI cred but is verified
        # now authorization should still fail since authorization steps
        # haven't been completed yet.
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_403
        
        result = client.simulate_post(f'/request/verify/{hab.pre}')
        assert result.status == falcon.HTTP_403


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

    return hab, crdntler, saiders[0].qb64, kmsgs, tmsgs, imsgs, acdcmsgs
    # revoke_cred(hab, crdntler.rgy, crdntler.rgy.registryByName("dAliases"), creds[0])