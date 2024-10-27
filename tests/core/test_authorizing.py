from ..common import *

import falcon
import falcon.testing

from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

import pytest

from verifier.core import basing, verifying
from verifier.core.authorizing import Authorizer, Schema

def test_ecr(seeder):

    with habbing.openHab(name="sid", temp=True, salt=b"0123456789abcdef") as (hby, hab):
        vdb = basing.VerifierBaser(name=hby.name, temp=True)

        #   habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(
            hby, hab, registryName="qvireg"
        )
        qvicred = get_qvi_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.QVI_SCHEMA1,
            registry=registry,
            lei=LEI1,
        )
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA1, qvicred, seqner
        )

        qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA1)

        leicred = get_lei_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.LE_SCHEMA1,
            registry=registry,
            sedge=qviedge,
            lei=LEI1,
        )
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.LE_SCHEMA1, leicred, seqner
        )

        # chained ecr auth cred
        eaedge = get_ecr_auth_edge(lsaid, Schema.LE_SCHEMA1)

        ecr_auth_cred = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA2,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, ecr_auth_cred, seqner
        )

        # try submitting the ECR auth cred
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger, [LEI1])
        chain_success, chain_msg = auth.chain_filters(ecr_auth_cred)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH"
        success, msg = auth.cred_filters(ecr_auth_cred)
        assert not success
        assert msg == f"Can't authorize cred with ECR_AUTH schema"

        # chained ecr auth cred
        ecredge = get_ecr_edge(easaid, Schema.ECR_AUTH_SCHEMA2)

        ecr_cred = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_SCHEMA,
            registry=registry,
            sedge=ecredge,
            lei=LEI1,
        )
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred, seqner
        )

        issAndCred = bytearray()
        issAndCred.extend(ecmsgs)
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger, [LEI1])
        chain_success, chain_msg = auth.chain_filters(ecr_cred)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = auth.cred_filters(ecr_cred)
        assert passed_filters
        assert msg == f"Credential passed filters for user {hab.pre} with LEI {LEI1}"

        data = '"@method": GET\n"@path": /verify/header\n"signify-resource": EHYfRWfM6RxYbzyodJ6SwYytlmCCW2gw5V-FsoX5BgGx\n"signify-timestamp": 2024-05-01T19:54:53.571000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714593293;keyid=BOieebDzg4uaqZ2zuRAX1sTiCrD3pgGT3HtxqSEAo05b;alg=ed25519"'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
            cig.qb64
            == "0BB1Z2DS3QvIBdZJ1Q7yuZCUG-6YkVXDm7dcGbIFEIsLYEBfFXk8P_Y9FUACTlv5vCHeCet70QzVdR8fu5tLBKkP"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)