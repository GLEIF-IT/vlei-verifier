from ..common import *

import falcon
import falcon.testing

from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

import pytest

from verifier.core import verifying, basing
from verifier.core.authorizing import Authorizer, Schema

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
        creder = get_da_cred(issuer=hab.pre, schema=Schema.DES_ALIASES_SCHEMA, registry=registry)
        
        # this is not a vLEI ECR cred on purpose
        # the presentation call should still succeed with
        # verifying the credential is well-formed and cryptographically correct
        hab, crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.DES_ALIASES_SCHEMA,creder, seqner)
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
        
        # hby.kevers[hab.pre] = hab.kever
        
        # cred is not an LEI cred but is verified
        # authorization should fail since authorization steps
        # haven't been completed yet.
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_403
        
        result = client.simulate_post(f'/request/verify/{hab.pre}')
        assert result.status == falcon.HTTP_403

def test_ecr(seeder):        
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        #   habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="qvireg")
        qvicred = get_qvi_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.QVI_SCHEMA, registry=registry)
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA, qvicred, seqner)
        
        qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA)

        leicred = get_lei_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.LEI_SCHEMA, registry=registry, sedge=qviedge)
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.LEI_SCHEMA, leicred, seqner)

        #chained ecr auth cred
        eaedge = get_ecr_auth_edge(lsaid,Schema.LEI_SCHEMA)
        
        eacred = get_ecr_auth_cred(aid=hab.pre, issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_AUTH_SCHEMA, registry=registry, sedge=eaedge)
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA, eacred, seqner)
        
        #chained ecr auth cred
        ecredge = get_ecr_edge(easaid,Schema.ECR_AUTH_SCHEMA)
        
        ecr = get_ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_SCHEMA, registry=registry, sedge=ecredge)
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner)
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eccrdntler.rgy.reger)

        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        issAndCred.extend(ecmsgs)
        acdc = issAndCred.decode("utf-8")

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{ecsaid}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_202
        
        hby.kevers[hab.pre] = hab.kever
        
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger, [LEI])
        auth.processPresentations()
        
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_OK

        data = 'this is the raw data'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert cig.qb64 == '0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL'
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)
        result = client.simulate_post(f'/request/verify/{hab.pre}',params={'data': data, 'sig': cig.qb64})
        assert result.status == falcon.HTTP_202

def test_ecr_missing(seeder):        
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        #   habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="qvireg")
       
        qvicred = get_qvi_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.QVI_SCHEMA, registry=registry)
        # created verifiable credential.
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA, qvicred, seqner)
        
        qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA)
       
        leicred = get_lei_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.LEI_SCHEMA, registry=registry, sedge=qviedge)
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.LEI_SCHEMA, leicred, seqner)

        #chained ecr auth cred
        eaedge = get_ecr_auth_edge(lsaid,Schema.LEI_SCHEMA)
        
        eacred = get_ecr_auth_cred(aid=hab.pre, issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_AUTH_SCHEMA, registry=registry, sedge=eaedge)
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA, eacred, seqner)
        #chained ecr auth cred
        # ecredge = get_ecr_edge(easaid,Schema.ECR_AUTH_SCHEMA)
        
        # ecr = get_ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_SCHEMA, registry=registry, sedge=ecredge)
        # hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner)
        
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eacrdntler.rgy.reger)

        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        # issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")

        # Create a test client
        client = falcon.testing.TestClient(app)
        # Define the said and the credential
        result = client.simulate_put(f'/presentations/{easaid}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json+cesr'})
        assert result.status == falcon.HTTP_400

        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        result = client.simulate_put(f'/presentations/{easaid}',
                                        body=acdc,
                                        headers={'Content-Type': 'application/json'})
        assert result.status == falcon.HTTP_400
        
        hby.kevers[hab.pre] = hab.kever
        
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger, [LEI])
        auth.processPresentations()
        
        result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert result.status == falcon.HTTP_403

        unknown_prefix = "bad-id"
        auth_result = client.simulate_get(f'/authorizations/{unknown_prefix}')
        assert auth_result.status == falcon.HTTP_404

        data = 'this is the raw data'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert cig.qb64 == '0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL'
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)

        result = client.simulate_post(f'/request/verify/{hab.pre}',params={'data': data, 'sig': cig.qb64})
        assert result.status == falcon.HTTP_403
        
        result = client.simulate_post(f'/request/verify/{unknown_prefix}',params={'data': data, 'sig': cig.qb64})
        assert result.status == falcon.HTTP_404