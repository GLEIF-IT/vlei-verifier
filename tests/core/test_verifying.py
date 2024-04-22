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
    with habbing.openHab(name="verifier1", salt=b'0123456789abcdefg', temp=True) as (hby,hab), \
        habbing.openHab(name="holder1", salt=b'123456789abcdef01', temp=True) as (holdhby, holdhab):
        seeder.seedSchema(db=holdhby.db)
        seeder.seedSchema(db=hby.db)
        
        regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="daliases")
        creder = get_da_cred(issuer=hab.pre, schema=DES_ALIASES_SCHEMA, registry=registry)
        
        # this is not a vLEI ECR cred on purpose
        # the presentation call should still succeed with
        # verifying the credential is well-formed and cryptographically correct
        hab, crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_cred(hby, hab, regery, registry, verifier, DES_ALIASES_SCHEMA,creder, seqner)
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
        # authorization should fail since authorization steps
        # haven't been completed yet.
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_403
        
        result = client.simulate_post(f'/request/verify/{hab.pre}')
        assert result.status == falcon.HTTP_403

def test_ecr(seeder):        
    with (habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab),
          habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="qvireg")
        qvicred = get_qvi_cred(issuer=hab.pre, recipient=hab.pre, schema=QVI_SCHEMA, registry=registry)
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(hby, hab, regery, registry, verifier, QVI_SCHEMA, qvicred, seqner)
        
        qviedge = get_qvi_edge(qvicred.sad["d"], QVI_SCHEMA)

        # lregery, lregistry, lverifier, lseqner = reg_and_verf(hby, hab, registryName="leireg")        
        leicred = get_lei_cred(issuer=hab.pre, recipient=hab.pre, schema=LEI_SCHEMA, registry=registry, sedge=qviedge)
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(hby, hab, regery, registry, verifier, LEI_SCHEMA, leicred, seqner)
        
        # #chained ecr auth cred
        # authedge = [
        #     ecr_auth_edge("EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g")
        # ]
        # ecr = ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=ECR_SCHEMA, registry=registry, sedge=authedge)
        # hab, crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_cred(hby, hab, regery, registry, verifier, ECR_SCHEMA,ecr, seqner)
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=lcrdntler.rgy.reger)

        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        issAndCred.extend(leimsgs)
        acdc = issAndCred.decode("utf-8")

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{lsaid}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_202
        
        hby.kevers[hab.pre] = hab.kever
        
        # cred is not an LEI cred but is verified
        # authorization should fail since authorization steps
        # haven't been completed yet.
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_202
        
        result = client.simulate_post(f'/request/verify/{hab.pre}')
        assert result.status == falcon.HTTP_202


def get_cred(hby, hab, regery, registry, verifier, schema, creder, seqner):

    crdntler = create_and_issue(hby, hab, regery, registry, verifier, schema, creder, seqner)
    saiders = crdntler.rgy.reger.schms.get(
        keys=schema.encode("utf-8"))
    creds = crdntler.rgy.reger.cloneCreds(saiders,hab.db)
    
    print(f"Generating CESR event stream data from hab")
    kmsgs = bytearray()
    genKelCesr(hby, hab.pre, kmsgs)

    #add designated aliases TELs and ACDCs
    creder, prefixer, seqner, saider = genCredAnchor(crdntler.rgy.reger, hab.pre, schema)
    
    if creder.regi is not None:
        tmsgs = bytearray()
        genTelCesr(crdntler.rgy.reger, creder.regi, tmsgs)
        imsgs = bytearray()
        genTelCesr(crdntler.rgy.reger, creder.said, imsgs)
    acdcmsgs = bytearray()
    genAcdcCesr(hby, hab.pre, creder, prefixer, seqner, saider, acdcmsgs)

    return hab, crdntler, saiders[0].qb64, kmsgs, tmsgs, imsgs, acdcmsgs
    # revoke_cred(hab, crdntler.rgy, crdntler.rgy.registryByName("dAliases"), creds[0])