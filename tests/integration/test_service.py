from ..common import *

import falcon
from hio.base import doing
from hio.core import http
from keri.app import habbing, configing
import pytest
import requests
import threading
import time
import verifier.app.cli.commands.server.start as start
from verifier.core import verifying, basing
import verifier.core.authorizing as authorizing
import verifier.core.reporting as reporting

host = "localhost"
port = 7676
url = f"http://{host}:{port}"

def test_service_ecr(seeder):        
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):

        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="qvireg")
        qvicred = get_qvi_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.QVI_SCHEMA1, registry=registry, lei=LEI1)
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA1, qvicred, seqner)
        
        qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA1)

        leicred = get_lei_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.LE_SCHEMA1, registry=registry, sedge=qviedge, lei=LEI1)
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.LE_SCHEMA1, leicred, seqner)

        #chained ecr auth cred
        eaedge = get_ecr_auth_edge(lsaid,Schema.LE_SCHEMA1)
        
        eacred = get_ecr_auth_cred(aid=hab.pre, issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_AUTH_SCHEMA2, registry=registry, sedge=eaedge, lei=LEI1)
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, eacred, seqner)
        
        #chained ecr auth cred
        ecredge = get_ecr_edge(easaid,Schema.ECR_AUTH_SCHEMA2)
        
        ecr = get_ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_SCHEMA, registry=registry, sedge=ecredge, lei=LEI1)
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner)
        
        app = falcon.App(
            middleware=falcon.CORSMiddleware(
                allow_origins='*',
                allow_credentials='*',
                expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eccrdntler.rgy.reger)
        server = http.Server(port=port, app=app)
        httpServerDoer = http.ServerDoer(server=server)
        class testCf:
            @staticmethod
            def get():
                return dict(LEIs=[f"{LEI1}",f"{LEI2}"])
        authDoers = authorizing.setup(hby, vdb=vdb, reger=eccrdntler.rgy.reger, cf=testCf)

        doers = authDoers + [httpServerDoer]
        limit = 0.25
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doist.doers = doers
        doist.enter()
        # assert len(doist.deeds) == 2
        # assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
        # for doer in doers:
        #     assert doer.baser.opened
        #     assert "_test/keri/db/test" in doer.baser.path
        try:
            doist.recur()
        except Exception as e:
            raise ValueError(f"Likely you have another service running on {port}")

        issAndCred = bytearray()
        # issAndCred.extend(kmsgs)
        # issAndCred.extend(tmsgs)
        # issAndCred.extend(imsgs)
        issAndCred.extend(ecmsgs)
        acdc = issAndCred.decode("utf-8")

        exceptions = []
        thread = threading.Thread(target=presentation_request,args=(ecsaid, acdc, exceptions))
        thread.start()
        time.sleep(3)
        doist.recur()
        thread.join()
        if exceptions:
            raise exceptions[0]
        
        exceptions = []
        thread = threading.Thread(target=auth_request,args=(hab.pre, exceptions))
        thread.start()
        time.sleep(3)
        doist.recur()
        thread.join()
        if exceptions:
            raise exceptions[0]
        
        data = 'this is the raw data'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert cig.qb64 == '0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL'
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)
       
        exceptions = []
        thread = threading.Thread(target=verify_request,args=(hab.pre,raw,cig.qb64,exceptions))
        thread.start()
        time.sleep(3)
        doist.recur()
        thread.join()
        if exceptions:
            raise exceptions[0]
        
@pytest.mark.manual
# def test_service_integration(seeder):
#     with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
#
#         seeder.seedSchema(db=hby.db)
#         regery, registry, verifier, seqner = reg_and_verf(hby, hab, registryName="qvireg")
#         qvicred = get_qvi_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.QVI_SCHEMA1, registry=registry, lei="875500ELOZEL05BVXV37")
#         hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA1, qvicred, seqner)
#
#         qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA1)
#
#         leicred = get_lei_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.LE_SCHEMA1, registry=registry, sedge=qviedge, lei="875500ELOZEL05BVXV37")
#         hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(hby, hab, regery, registry, verifier, Schema.LE_SCHEMA1, leicred, seqner)
#
#         #chained ecr auth cred
#         eaedge = get_ecr_auth_edge(lsaid,Schema.LE_SCHEMA1)
#
#         eacred = get_ecr_auth_cred(aid=hab.pre, issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_AUTH_SCHEMA2, registry=registry, sedge=eaedge, lei="875500ELOZEL05BVXV37")
#         hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, eacred, seqner)
#
#         #chained ecr auth cred
#         ecredge = get_ecr_edge(easaid,Schema.ECR_AUTH_SCHEMA2)
#
#         ecr = get_ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_SCHEMA, registry=registry, sedge=ecredge, lei="875500ELOZEL05BVXV37")
#         hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner)
#
#         app = falcon.App(
#             middleware=falcon.CORSMiddleware(
#                 allow_origins='*',
#                 allow_credentials='*',
#                 expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
#         vdb = basing.VerifierBaser(name=hby.name, temp=True)
#         verifying.setup(app=app, hby=hby, vdb=vdb, reger=eccrdntler.rgy.reger)
#         server = http.Server(port=port, app=app)
#         httpServerDoer = http.ServerDoer(server=server)
#         # class testCf:
#         #     def get():
#         #         return dict(LEIs=[f"{LEI1}",f"{LEI2}"])
#         rootsCf = configing.Configer(name="verifier-config-public.json",
#                             headDirPath="/home/aidar/Desktop/git/gleif/vlei-verifier/scripts",
#                             base="",
#                             temp=False, reopen=True, clear=False)
#         authDoers = authorizing.setup(hby, vdb=vdb, reger=eccrdntler.rgy.reger, cf=rootsCf)
#
#         reportDoers = reporting.setup(app=app, hby=hby, vdb=vdb)
#
#         doers = authDoers + reportDoers + [httpServerDoer]
#         limit = 0.25
#         tock = 0.03125
#         doist = doing.Doist(limit=limit, tock=tock)
#         doist.doers = doers
#         doist.enter()
#         # assert len(doist.deeds) == 2
#         # assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
#         # for doer in doers:
#         #     assert doer.baser.opened
#         #     assert "_test/keri/db/test" in doer.baser.path
#         try:
#             doist.recur()
#         except Exception as e:
#             raise ValueError(f"Likely you have another service running on {port}")
#
#         issAndCred = bytearray()
#         # issAndCred.extend(kmsgs)
#         # issAndCred.extend(tmsgs)
#         # issAndCred.extend(imsgs)
#         issAndCred.extend(ecmsgs)
#         acdc = issAndCred.decode("utf-8")
#
#         # use this for integration testing debugging sessions
#         while True:
#             time.sleep(1)
#             doist.recur()

def presentation_request(said, acdc, exceptions):
    try:
        result = requests.put(url=f'{url}/presentations/{said}',
                            data=acdc,
                            headers={'Content-Type': 'application/json+cesr'})
        assert f"{result.status_code} {result.reason}" == falcon.HTTP_202
    except Exception as e:
        exceptions.append(e)
            
def auth_request(aid, exceptions):
    try:
        result = requests.get(url=f'{url}/authorizations/{aid}', headers={"Content-Type": "application/json"})
        # result = client.simulate_get(f'/authorizations/{hab.pre}')
        assert f"{result.status_code} {result.reason}" == falcon.HTTP_200
    except Exception as e:
        exceptions.append(e)
    
def verify_request(aid,data,sig, exceptions):
    try:
        result = requests.post(url=f'{url}/request/verify/{aid}',params={'data': data, 'sig': sig})
        assert f"{result.status_code} {result.reason}" == falcon.HTTP_202
    except Exception as e:
        exceptions.append(e)