from verifier.core.resolve_env import VerifierEnvironment
from verifier.core.utils import add_root_of_trust
from ..common import *
import pdb;

import falcon
import re
import falcon.testing

from keri.app import habbing
from keri.core import coring
from keri.vdr import viring, verifying, eventing
import pytest

from verifier.core import verifying, basing
from verifier.core.authorizing import Authorizer, Schema, DEFAULT_EBA_ROLE


@pytest.fixture(autouse=True)
def setup():
    allowed_schemas = [
        getattr(Schema, x) for x in ("ECR_SCHEMA", "ECR_SCHEMA_PROD", "TEST_SCHEMA")
    ]
    allowed_ecr_roles = [
        "EBA Data Submitter",
        "EBA Data Admin"
    ]
    allowed_oor_roles = []
    verifier_mode = os.environ.get("VERIFIER_ENV", "production")
    trusted_leis = []
    verify_rot = os.getenv("VERIFY_ROOT_OF_TRUST", "False").lower() in ("true", "1")

    ve_init_params = {
        "mode": verifier_mode,
        "trustedLeis": trusted_leis if trusted_leis else [],
        "verifyRootOfTrust": verify_rot,
        "authAllowedSchemas": allowed_schemas,
        "authAllowedEcrRoles": allowed_ecr_roles,
        "authAllowedOorRoles": allowed_oor_roles
    }

    VerifierEnvironment.initialize(**ve_init_params)


def test_setup_verifying(seeder):
    with habbing.openHab(name="verifier1", salt=b"0123456789abcdefg", temp=True) as (
            hby,
            hab,
    ), habbing.openHab(name="holder1", salt=b"123456789abcdef01", temp=True) as (
            holdhby,
            holdhab,
    ):
        seeder.seedSchema(db=holdhby.db)
        seeder.seedSchema(db=hby.db)

        regery, registry, verifier, seqner = reg_and_verf(
            hby, hab, registryName="daliases"
        )
        creder = get_da_cred(
            issuer=hab.pre, schema=Schema.DES_ALIASES_SCHEMA, registry=registry
        )

        # this is not a vLEI ECR cred on purpose
        # the presentation call should still succeed with
        # verifying the credential is well-formed and cryptographically correct
        hab, crdntler, said, kmsgs, tmsgs, imsgs, acdcmsgs = get_cred(
            hby,
            hab,
            regery,
            registry,
            verifier,
            Schema.DES_ALIASES_SCHEMA,
            creder,
            seqner,
        )
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
        result = client.simulate_put(
            f"/presentations/{said}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        assert result.status == falcon.HTTP_202

        # hby.kevers[hab.pre] = hab.kever

        # cred is not an LEI cred but is verified
        # authorization should fail since authorization steps
        # haven't been completed yet.
        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_401

        data = "this is the raw data"
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)
        # result = client.simulate_post(
        #     f"/request/verify/{hab.pre}", params={"data": data, "sig": cig.qb64}
        # )
        # assert result.status == falcon.HTTP_403


def test_ecr(seeder):
    app = falcon.App()
    gleif_external_aid = "EA8N0zrLXPafG3UUZg8K6BhkU8V4nRju9BQeilL3Z4gh"
    with habbing.openHab(name="sid", temp=True, salt=b"0123456789abcdef", delpre=gleif_external_aid) as (hby, hab):
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        add_root_of_trust_test_request(hby, vdb)
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

        eacred = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA2,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, eacred, seqner
        )

        # try submitting the ECR auth cred
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eacrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        # ecr auth cred is verified to be a valid credential
        assert result.status == falcon.HTTP_202
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger)
        auth.processPresentations()
        # ecr auth cred is not authorized
        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_401

        # chained ecr auth cred
        ecredge = get_ecr_edge(easaid, Schema.ECR_AUTH_SCHEMA2)

        ecr = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_SCHEMA,
            registry=registry,
            sedge=ecredge,
            lei=LEI1,
            role=DEFAULT_EBA_ROLE
        )
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner
        )

        issAndCred = bytearray()
        issAndCred.extend(ecmsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eccrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{ecsaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        assert result.status == falcon.HTTP_202
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger)
        auth.processPresentations()

        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_OK
        assert result.json['aid'] == hab.pre
        assert result.json['said'] == ecsaid
        assert result.json['lei'] == LEI1
        assert result.json['msg'] == f"AID {hab.pre} w/ lei {LEI1} has valid login account"

        data = "this is the raw data"
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
                cig.qb64
                == "0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)
        result = client.simulate_post(
            f"/request/verify/{hab.pre}", params={"data": data, "sig": cig.qb64}
        )
        assert result.status == falcon.HTTP_202

        data = '"@method": GET\n"@path": /verify/header\n"signify-resource": EHYfRWfM6RxYbzyodJ6SwYytlmCCW2gw5V-FsoX5BgGx\n"signify-timestamp": 2024-05-01T19:54:53.571000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714593293;keyid=BOieebDzg4uaqZ2zuRAX1sTiCrD3pgGT3HtxqSEAo05b;alg=ed25519"'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
                cig.qb64
                == "0BB1Z2DS3QvIBdZJ1Q7yuZCUG-6YkVXDm7dcGbIFEIsLYEBfFXk8P_Y9FUACTlv5vCHeCet70QzVdR8fu5tLBKkP"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)

        # try submitting the ECR auth cred now that we're already authorized
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eacrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        # ecr auth cred is verified to be a valid credential
        assert result.status == falcon.HTTP_202
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger)
        auth.processPresentations()
        # ecr auth cred is not authorized
        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_401


def test_ecr_missing(seeder):
    gleif_external_aid = "EA8N0zrLXPafG3UUZg8K6BhkU8V4nRju9BQeilL3Z4gh"
    with habbing.openHab(name="sid", temp=True, salt=b"0123456789abcdef", delpre=gleif_external_aid) as (hby, hab):
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
        # created verifiable credential.
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

        eacred = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA2,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, eacred, seqner
        )
        # chained ecr auth cred
        # ecredge = get_ecr_edge(easaid,Schema.ECR_AUTH_SCHEMA2)

        # ecr = get_ecr_cred(issuer=hab.pre, recipient=hab.pre, schema=Schema.ECR_SCHEMA, registry=registry, sedge=ecredge)
        # hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr, seqner)

        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        add_root_of_trust_test_request(hby, vdb)
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
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        assert result.status == falcon.HTTP_400

        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json"},
        )
        assert result.status == falcon.HTTP_400

        hby.kevers[hab.pre] = hab.kever

        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger)
        auth.processPresentations()

        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_401

        unknown_prefix = "bad-id"
        auth_result = client.simulate_get(f"/authorizations/{unknown_prefix}")
        assert auth_result.status == falcon.HTTP_401

        data = "this is the raw data"
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
                cig.qb64
                == "0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)

        # result = client.simulate_post(
        #     f"/request/verify/{hab.pre}", params={"data": data, "sig": cig.qb64}
        # )
        # assert result.status == falcon.HTTP_403

        result = client.simulate_post(
            f"/request/verify/{unknown_prefix}", params={"data": data, "sig": cig.qb64}
        )
        assert result.status == falcon.HTTP_404


def test_add_root_of_trust(seeder):
    with habbing.openHab(name="sid", temp=True, salt=b"0123456789abcdef") as (hby, hab):
        #   habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)

        app = falcon.App()
        reger = viring.Reger(name=hby.name, temp=hby.temp)
        vdb = basing.VerifierBaser(name=hby.name)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=reger)
        with open("./src/root_of_trust_oobis/test_root_of_trust.json", "rb") as f:
            json_oobi_gleif = json.loads(f.read())
            aid = json_oobi_gleif.get("aid")
            vlei = json_oobi_gleif.get("vlei")
            oobi = json_oobi_gleif.get("oobi")
            client = falcon.testing.TestClient(app)
            result = client.simulate_post(
                f"/root_of_trust/{aid}",
                json={
                    "vlei": vlei,
                    "oobi": oobi
                },
                headers={"Content-Type": "application/json"},
            )
            assert result.status == falcon.HTTP_202


def test_ecr_newschema(seeder):
    app = falcon.App()
    gleif_external_aid = "EA8N0zrLXPafG3UUZg8K6BhkU8V4nRju9BQeilL3Z4gh"
    with habbing.openHab(name="sid", temp=True, salt=b"0123456789abcdef", delpre=gleif_external_aid) as (hby, hab):
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        add_root_of_trust_test_request(hby, vdb)
        #   habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        seeder.seedSchema(db=hby.db)
        regery, registry, verifier, seqner = reg_and_verf(
            hby, hab, registryName="qvireg"
        )
        qvicred = get_qvi_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.QVI_SCHEMA2,
            registry=registry,
            lei=LEI1,
        )
        hab, qcrdntler, qsaid, qkmsgs, qtmsgs, qimsgs, qvimsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.QVI_SCHEMA2, qvicred, seqner
        )

        qviedge = get_qvi_edge(qvicred.sad["d"], Schema.QVI_SCHEMA2)

        leicred = get_lei_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.LE_SCHEMA2,
            registry=registry,
            sedge=qviedge,
            lei=LEI1,
        )
        hab, lcrdntler, lsaid, lkmsgs, ltmsgs, limsgs, leimsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.LE_SCHEMA2, leicred, seqner
        )

        # chained ecr auth cred
        eaedge = get_ecr_auth_edge(lsaid, Schema.LE_SCHEMA2)

        eacred = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA1,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA1, eacred, seqner
        )

        # try submitting the ECR auth cred
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eacrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        # ecr auth cred is verified to be a valid credential
        assert result.status == falcon.HTTP_202
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger)
        auth.processPresentations()
        # ecr auth cred is not authorized
        result = client.simulate_get(f"/authorizations/{hab.pre}")
        # assert result.status == falcon.HTTP_OK

        # chained ecr auth cred
        ecredge = get_ecr_edge(easaid, Schema.ECR_AUTH_SCHEMA1)
        print(ecredge)
        ecr = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.TEST_SCHEMA,
            registry=registry,
            sedge=ecredge,
            lei=LEI1,
        )
        print(ecr.said)
        print(ecr.issuer)
        print(ecr.edge)
        print("ecr")
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.TEST_SCHEMA, ecr, seqner
        )

        issAndCred = bytearray()
        issAndCred.extend(ecmsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eccrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{ecsaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        assert result.status == falcon.HTTP_202
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger)
        auth.processPresentations()

        result = client.simulate_get(f"/authorizations/{hab.pre}")
        assert result.status == falcon.HTTP_OK
        assert result.json['aid'] == hab.pre
        assert result.json['said'] == ecsaid
        assert result.json['lei'] == LEI1
        assert result.json['msg'] == f"AID {hab.pre} w/ lei {LEI1} has valid login account"

        data = "this is the raw data"
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
                cig.qb64
                == "0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)
        result = client.simulate_post(
            f"/request/verify/{hab.pre}", params={"data": data, "sig": cig.qb64}
        )
        assert result.status == falcon.HTTP_202

        data = '"@method": GET\n"@path": /verify/header\n"signify-resource": EHYfRWfM6RxYbzyodJ6SwYytlmCCW2gw5V-FsoX5BgGx\n"signify-timestamp": 2024-05-01T19:54:53.571000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714593293;keyid=BOieebDzg4uaqZ2zuRAX1sTiCrD3pgGT3HtxqSEAo05b;alg=ed25519"'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
                cig.qb64
                == "0BB1Z2DS3QvIBdZJ1Q7yuZCUG-6YkVXDm7dcGbIFEIsLYEBfFXk8P_Y9FUACTlv5vCHeCet70QzVdR8fu5tLBKkP"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)

        # try submitting the ECR auth cred now that we're already authorized
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        client = falcon.testing.TestClient(app)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=eacrdntler.rgy.reger)
        result = client.simulate_put(
            f"/presentations/{easaid}",
            body=acdc,
            headers={"Content-Type": "application/json+cesr"},
        )
        match = re.search(r'"d":"([^"]+)"', acdc)
        cred_value = match.group(1)

        # ecr auth cred is verified to be a valid credential
        assert result.status == falcon.HTTP_202

        assert result.json.get('msg') == f"{cred_value} for {hab.pre} as issuee is Credential cryptographically valid"
