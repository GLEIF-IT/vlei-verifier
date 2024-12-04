from ..common import *

import falcon
import falcon.testing

from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

import pytest

from verifier.core import basing, verifying
from verifier.core.authorizing import Authorizer, Schema, DEFAULT_EBA_ROLE

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
            role=DEFAULT_EBA_ROLE
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, ecr_auth_cred, seqner
        )

        # try submitting the ECR auth cred
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger, [LEI1], {DEFAULT_EBA_ROLE})
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
            role=DEFAULT_EBA_ROLE
        )
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred, seqner
        )

        issAndCred = bytearray()
        issAndCred.extend(ecmsgs)
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger, [LEI1], {DEFAULT_EBA_ROLE})
        chain_success, chain_msg = auth.chain_filters(ecr_cred)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = auth.cred_filters(ecr_cred)
        assert passed_filters
        assert msg == f"Credential passed filters for user {hab.pre} with LEI {LEI1}"


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
            role="EBA_DATA_ADMIN"
        )
        hab, eacrdntler, easaid, eakmsgs, eatmsgs, eaimsgs, eamsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, ecr_auth_cred, seqner
        )

        # try submitting the ECR auth cred
        issAndCred = bytearray()
        issAndCred.extend(eamsgs)
        acdc = issAndCred.decode("utf-8")
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eacrdntler.rgy.reger, [LEI1], {"EBA_DATA_ADMIN"})
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
            role="EBA_DATA_ADMIN"
        )
        hab, eccrdntler, ecsaid, eckmsgs, ectmsgs, ecimsgs, ecmsgs = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred, seqner
        )

        issAndCred = bytearray()
        issAndCred.extend(ecmsgs)
        hby.kevers[hab.pre] = hab.kever
        auth = Authorizer(hby, vdb, eccrdntler.rgy.reger, [LEI1], {"EBA_DATA_ADMIN"})
        chain_success, chain_msg = auth.chain_filters(ecr_cred)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = auth.cred_filters(ecr_cred)
        assert passed_filters
        assert msg == f"Credential passed filters for user {hab.pre} with LEI {LEI1}"

        # Verify that the same credential fails with default role authorizer
        auth_default = Authorizer(hby, vdb, eccrdntler.rgy.reger, [LEI1], {DEFAULT_EBA_ROLE})
        chain_success, chain_msg = auth_default.chain_filters(ecr_cred)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = auth_default.cred_filters(ecr_cred)
        assert not passed_filters
        assert "is not a valid submitter role" in msg

        # Test with multiple roles
        # Authorizer that accepts both default role and "EBA_DATA_ADMIN"
        multi_role_auth = Authorizer(hby, vdb, eacrdntler.rgy.reger, [LEI1], {DEFAULT_EBA_ROLE, "EBA_DATA_ADMIN"})

        # Test credential with default role
        ecr_auth_cred_default = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA2,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
            role=DEFAULT_EBA_ROLE
        )
        hab, eacrdntler_default, easaid_default, eakmsgs_default, eatmsgs_default, eaimsgs_default, eamsgs_default = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, ecr_auth_cred_default, seqner
        )

        # Test credential with EBA_DATA_ADMIN role
        ecr_auth_cred_admin = get_ecr_auth_cred(
            aid=hab.pre,
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_AUTH_SCHEMA2,
            registry=registry,
            sedge=eaedge,
            lei=LEI1,
            role="EBA_DATA_ADMIN"
        )
        hab, eacrdntler_admin, easaid_admin, eakmsgs_admin, eatmsgs_admin, eaimsgs_admin, eamsgs_admin = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_AUTH_SCHEMA2, ecr_auth_cred_admin, seqner
        )

        # Verify both credentials with multi-role authorizer
        # Check default role credential
        chain_success, chain_msg = multi_role_auth.chain_filters(ecr_auth_cred_default)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH"
        success, msg = multi_role_auth.cred_filters(ecr_auth_cred_default)
        assert not success  # Should still fail because it's ECR_AUTH schema
        assert msg == f"Can't authorize cred with ECR_AUTH schema"

        # Check admin role credential
        chain_success, chain_msg = multi_role_auth.chain_filters(ecr_auth_cred_admin)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH"
        success, msg = multi_role_auth.cred_filters(ecr_auth_cred_admin)
        assert not success  # Should still fail because it's ECR_AUTH schema
        assert msg == f"Can't authorize cred with ECR_AUTH schema"

        # Now test ECR credentials with both roles
        ecredge_default = get_ecr_edge(easaid_default, Schema.ECR_AUTH_SCHEMA2)
        ecredge_admin = get_ecr_edge(easaid_admin, Schema.ECR_AUTH_SCHEMA2)

        # Create and test ECR credential with default role
        ecr_cred_default = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_SCHEMA,
            registry=registry,
            sedge=ecredge_default,
            lei=LEI1,
            role=DEFAULT_EBA_ROLE
        )
        hab, eccrdntler_default, ecsaid_default, eckmsgs_default, ectmsgs_default, ecimsgs_default, ecmsgs_default = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred_default, seqner
        )

        # Create and test ECR credential with admin role
        ecr_cred_admin = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_SCHEMA,
            registry=registry,
            sedge=ecredge_admin,
            lei=LEI1,
            role="EBA_DATA_ADMIN"
        )
        hab, eccrdntler_admin, ecsaid_admin, eckmsgs_admin, ectmsgs_admin, ecimsgs_admin, ecmsgs_admin = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred_admin, seqner
        )

        # Test both ECR credentials with multi-role authorizer
        # Test default role ECR credential
        chain_success, chain_msg = multi_role_auth.chain_filters(ecr_cred_default)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = multi_role_auth.cred_filters(ecr_cred_default)
        assert passed_filters
        assert msg == f"Credential passed filters for user {hab.pre} with LEI {LEI1}"

        # Test admin role ECR credential
        chain_success, chain_msg = multi_role_auth.chain_filters(ecr_cred_admin)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = multi_role_auth.cred_filters(ecr_cred_admin)
        assert passed_filters
        assert msg == f"Credential passed filters for user {hab.pre} with LEI {LEI1}"

        # Test ECR with invalid role
        ecr_cred_invalid = get_ecr_cred(
            issuer=hab.pre,
            recipient=hab.pre,
            schema=Schema.ECR_SCHEMA,
            registry=registry,
            sedge=ecredge,
            lei=LEI1,
            role="INVALID_ROLE"  # Using an invalid role
        )
        hab, eccrdntler_invalid, ecsaid_invalid, eckmsgs_invalid, ectmsgs_invalid, ecimsgs_invalid, ecmsgs_invalid = get_cred(
            hby, hab, regery, registry, verifier, Schema.ECR_SCHEMA, ecr_cred_invalid, seqner
        )

        auth = Authorizer(hby, vdb, eccrdntler_invalid.rgy.reger, [LEI1], {DEFAULT_EBA_ROLE, "EBA Data Admin"})
        chain_success, chain_msg = auth.chain_filters(ecr_cred_invalid)
        assert chain_success
        assert chain_msg == f"QVI->LE->ECR_AUTH->ECR"
        passed_filters, msg = auth.cred_filters(ecr_cred_invalid)
        assert not passed_filters  # Should fail because of invalid role
        assert "is not a valid submitter role" in msg

        data = '"@method": GET\n"@path": /verify/header\n"signify-resource": EHYfRWfM6RxYbzyodJ6SwYytlmCCW2gw5V-FsoX5BgGx\n"signify-timestamp": 2024-05-01T19:54:53.571000+00:00\n"@signature-params: (@method @path signify-resource signify-timestamp);created=1714593293;keyid=BOieebDzg4uaqZ2zuRAX1sTiCrD3pgGT3HtxqSEAo05b;alg=ed25519"'
        raw = data.encode("utf-8")
        cig = hab.sign(ser=raw, indexed=False)[0]
        assert (
            cig.qb64
            == "0BB1Z2DS3QvIBdZJ1Q7yuZCUG-6YkVXDm7dcGbIFEIsLYEBfFXk8P_Y9FUACTlv5vCHeCet70QzVdR8fu5tLBKkP"
        )
        assert hby.kevers[hab.pre].verfers[0].verify(sig=cig.raw, ser=raw)