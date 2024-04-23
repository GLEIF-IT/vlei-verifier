"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""
import os
import shutil
import multicommand

import pytest
from hio.base import doing

from verifier.core.authorizing import Schema

from keri import kering
from keri.core import scheming, coring, routing, eventing, parsing
from keri.db import basing
from keri.help import helping
from keri import help

from keri.app.cli import commands

WitnessUrls = {
    "wan:tcp": "tcp://127.0.0.1:5632/",
    "wan:http": "http://127.0.0.1:5642/",
    "wes:tcp": "tcp://127.0.0.1:5634/",
    "wes:http": "http://127.0.0.1:5644/",
    "wil:tcp": "tcp://127.0.0.1:5633/",
    "wil:http": "http://127.0.0.1:5643/",
}

LEI = "254900OPPU84GM83MG36"

@pytest.fixture()
def mockHelpingNowUTC(monkeypatch):
    """
    Replace nowUTC universally with fixed value for testing
    """

    def mockNowUTC():
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return helping.fromIso8601("2021-01-01T00:00:00.000000+00:00")

    monkeypatch.setattr(helping, "nowUTC", mockNowUTC)


@pytest.fixture()
def mockHelpingNowIso8601(monkeypatch):
    """
    Replace nowIso8601 universally with fixed value for testing
    """

    def mockNowIso8601():
        """
        Use predetermined value for now (current time)
        '2021-01-01T00:00:00.000000+00:00'
        """
        return "2021-06-27T21:26:21.233257+00:00"

    monkeypatch.setattr(helping, "nowIso8601", mockNowIso8601)


@pytest.fixture()
def mockCoringRandomNonce(monkeypatch):
    """Replay randomNonce with fixed falue for testing"""

    def mockRandomNonce():
        return "A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"

    monkeypatch.setattr(coring, "randomNonce", mockRandomNonce)


@pytest.fixture
def seeder():
    return DbSeed


class DbSeed:
    @staticmethod
    def seedWitEnds(db, witHabs, protocols=None):
        """Add endpoint and location records for well known test witnesses

        Args:
            db (Baser): database to add records
            witHabs (list): list of witness Habs for whom to create Ends
            protocols (list) array of str protocol names to load URLs for.
        Returns:

        """

        rtr = routing.Router()
        rvy = routing.Revery(db=db, rtr=rtr)
        kvy = eventing.Kevery(db=db, lax=False, local=True, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        psr = parsing.Parser(framed=True, kvy=kvy, rvy=rvy)

        if protocols is None:
            protocols = [kering.Schemes.tcp, kering.Schemes.http]

        for scheme in protocols:
            msgs = bytearray()
            for hab in witHabs:
                url = WitnessUrls[f"{hab.name}:{scheme}"]
                msgs.extend(
                    hab.makeEndRole(
                        eid=hab.pre,
                        role=kering.Roles.controller,
                        stamp=help.nowIso8601(),
                    )
                )

                msgs.extend(
                    hab.makeLocScheme(url=url, scheme=scheme, stamp=help.nowIso8601())
                )
                psr.parse(ims=msgs)

    @staticmethod
    def seedWatcherEnds(db, protocols=None):
        """Add endpoint and location records for well known test watchers

        Args:
            db (Baser): database to add records
            protocols (list) array of str protocol names to load URLs for.
        Returns:

        """
        if protocols is None:
            protocols = [kering.Schemes.tcp, kering.Schemes.http]

        watEndKeys = (
            "BGYNONqsgWKDQuKyCNanZ-7DyT0oeb6ectMZ1WGyT7o8",
            "controller",
            "BGYNONqsgWKDQuKyCNanZ-7DyT0oeb6ectMZ1WGyT7o8",
        )
        ender = basing.EndpointRecord(allowed=True)  # create new record
        db.ends.pin(keys=watEndKeys, val=ender)  # overwrite

        if kering.Schemes.tcp in protocols:
            locer = basing.LocationRecord(
                url="tcp://127.0.0.1:5634/"
            )  # create new record
            watLocKeys = (
                "BGYNONqsgWKDQuKyCNanZ-7DyT0oeb6ectMZ1WGyT7o8",
                kering.Schemes.tcp,
            )
            db.locs.pin(keys=watLocKeys, val=locer)  # overwrite

        if kering.Schemes.http in protocols:
            httplocer = basing.LocationRecord(
                url="http://127.0.0.1:5644/"
            )  # create new record
            watHttpLocKeys = (
                "BGYNONqsgWKDQuKyCNanZ-7DyT0oeb6ectMZ1WGyT7o8",
                kering.Schemes.http,
            )
            db.locs.pin(keys=watHttpLocKeys, val=httplocer)  # overwrite

    @staticmethod
    def seedSchema(db):
        # EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Optional Issuee",
            "description": "A credential with an optional issuee",
            "credentialType": "UntargetedAttestation",
            "properties": {
                "v": {"type": "string"},
                "d": {"type": "string"},
                "i": {"type": "string"},
                "ri": {"description": "credential status registry", "type": "string"},
                "s": {"description": "schema SAID", "type": "string"},
                "a": {
                    "properties": {
                        "d": {"type": "string"},
                        "i": {"type": "string"},
                        "dt": {"format": "date-time", "type": "string"},
                        "claim": {"type": "string"},
                    },
                    "additionalProperties": False,
                    "required": ["dt", "claim"],
                    "type": "object",
                },
                "e": {"description": "edges block", "type": "object"},
                "r": {"type": "object", "description": "rules block"},
            },
            "additionalProperties": False,
            "required": ["i", "ri", "s", "d", "e", "r"],
            "type": "object",
        }

        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        db.schema.pin(schemer.said, schemer)

        # OLD: "E1MCiPag0EWlqeJGzDA9xxr1bUSUR4fZXtqHDrwdXgbk"
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Legal Entity vLEI Credential",
            "description": "A vLEI Credential issued by a Qualified vLEI issuer to a Legal Entity",
            "credentialType": "LegalEntityvLEICredential",
            "properties": {
                "v": {"type": "string"},
                "d": {"type": "string"},
                "i": {"type": "string"},
                "ri": {"description": "credential status registry", "type": "string"},
                "s": {"description": "schema SAID", "type": "string"},
                "a": {
                    "description": "data block",
                    "properties": {
                        "d": {"type": "string"},
                        "i": {"type": "string"},
                        "dt": {
                            "description": "issuance date " "time",
                            "format": "date-time",
                            "type": "string",
                        },
                        "LEI": {"type": "string"},
                    },
                    "additionalProperties": False,
                    "required": ["i", "dt", "LEI"],
                    "type": "object",
                },
                "e": {"description": "edges block", "type": "object"},
                "r": {"type": "object", "description": "rules block"},
            },
            "additionalProperties": False,
            "required": ["i", "ri", "s", "d", "e", "r"],
            "type": "object",
        }

        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: "ENTAoj2oNBFpaniRswwPcca9W1ElEeH2V7ahw68HV4G5
        db.schema.pin(schemer.said, schemer)

        # OLD: "ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI"
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "GLEIF vLEI Credential",
            "description": "The vLEI Credential issued to GLEIF",
            "credentialType": "GLEIFvLEICredential",
            "type": "object",
            "properties": {
                "v": {"type": "string"},
                "d": {"type": "string"},
                "i": {"type": "string"},
                "ri": {"description": "credential status registry", "type": "string"},
                "s": {"description": "schema SAID", "type": "string"},
                "a": {
                    "description": "data block",
                    "properties": {
                        "d": {"type": "string"},
                        "i": {"type": "string"},
                        "dt": {
                            "description": "issuance date " "time",
                            "format": "date-time",
                            "type": "string",
                        },
                        "LEI": {"type": "string"},
                    },
                    "additionalProperties": False,
                    "required": ["d", "dt", "LEI"],
                    "type": "object",
                },
                "e": {"type": "object"},
            },
            "additionalProperties": False,
            "required": ["d", "i", "ri"],
        }
        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC
        db.schema.pin(schemer.said, schemer)

        # OLD: EPz3ZvjQ_8ZwRKzfA5xzbMW8v8ZWLZhvOn2Kw1Nkqo_Q
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Legal Entity vLEI Credential",
            "description": "A vLEI Credential issued by a Qualified vLEI issuer to a Legal Entity",
            "type": "object",
            "credentialType": "LegalEntityvLEICredential",
            "version": "1.0.0",
            "properties": {
                "v": {
                "description": "Version",
                "type": "string"
                },
                "d": {
                "description": "Credential SAID",
                "type": "string"
                },
                "u": {
                "description": "One time use nonce",
                "type": "string"
                },
                "i": {
                "description": "QVI Issuer AID",
                "type": "string"
                },
                "ri": {
                "description": "Credential status registry",
                "type": "string"
                },
                "s": {
                "description": "Schema SAID",
                "type": "string"
                },
                "a": {
                "oneOf": [
                    {
                    "description": "Attributes block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EJ6bFDLrv50bHmIDg-MSummpvYWsPa9CFygPUZyHoESj",
                    "description": "Attributes block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Attributes block SAID",
                        "type": "string"
                        },
                        "i": {
                        "description": "LE Issuer AID",
                        "type": "string"
                        },
                        "dt": {
                        "description": "issuance date time",
                        "type": "string",
                        "format": "date-time"
                        },
                        "LEI": {
                        "description": "LE Issuer AID",
                        "type": "string",
                        "format": "ISO 17442"
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "i",
                        "dt",
                        "LEI"
                    ]
                    }
                ]
                },
                "e": {
                "oneOf": [
                    {
                    "description": "Edges block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EDh9sp5cPk0-yo5sFMo6WJS1HMBYIOYCwJrnPvNaH1vI",
                    "description": "Edges block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Edges block SAID",
                        "type": "string"
                        },
                        "qvi": {
                        "description": "QVI node",
                        "type": "object",
                        "properties": {
                            "n": {
                            "description": "Issuer credential SAID",
                            "type": "string"
                            },
                            "s": {
                            "description": "SAID of required schema of the credential pointed to by this node",
                            "type": "string",
                            "const": "EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs"
                            }
                        },
                        "additionalProperties": False,
                        "required": [
                            "n",
                            "s"
                        ]
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "qvi"
                    ]
                    }
                ]
                },
                "r": {
                "oneOf": [
                    {
                    "description": "Rules block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "ECllqarpkZrSIWCb97XlMpEZZH3q4kc--FQ9mbkFMb_5",
                    "description": "Rules block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Rules block SAID",
                        "type": "string"
                        },
                        "usageDisclaimer": {
                        "description": "Usage Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
                            }
                        }
                        },
                        "issuanceDisclaimer": {
                        "description": "Issuance Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
                            }
                        }
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "usageDisclaimer",
                        "issuanceDisclaimer"
                    ]
                    }
                ]
                }
            },
            "additionalProperties": False,
            "required": [
                "i",
                "ri",
                "s",
                "d",
                "e",
                "r"
            ]
        }
        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EHyKQS68x_oWy8_vNmYubA5Y0Tse4XMPFggMfoPoERaM
        assert schemer.said == Schema.LEI_SCHEMA
        db.schema.pin(schemer.said, schemer)

        # OLD: EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Qualified vLEI Issuer Credential",
            "description": "A vLEI Credential issued by GLEIF to Qualified vLEI Issuers which allows the Qualified "
            "vLEI Issuers to issue, verify and revoke Legal Entity vLEI Credentials and Legal "
            "Entity Official Organizational Role vLEI Credentials",
            "credentialType": "QualifiedvLEIIssuervLEICredential",
            "properties": {
                "v": {"type": "string"},
                "d": {"type": "string"},
                "i": {"type": "string"},
                "ri": {"description": "credential status registry", "type": "string"},
                "s": {"description": "schema SAID", "type": "string"},
                "a": {
                    "description": "data block",
                    "properties": {
                        "d": {"type": "string"},
                        "i": {"type": "string"},
                        "dt": {
                            "description": "issuance date " "time",
                            "format": "date-time",
                            "type": "string",
                        },
                        "LEI": {"type": "string"},
                        "gracePeriod": {"default": 90, "type": "integer"},
                    },
                    "additionalProperties": False,
                    "required": ["i", "dt", "LEI"],
                    "type": "object",
                },
                "e": {"type": "object"},
            },
            "additionalProperties": False,
            "required": ["i", "ri", "s", "d"],
            "type": "object",
        }

        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs
        assert schemer.said == Schema.QVI_SCHEMA
        db.schema.pin(schemer.said, schemer)

        sad = {
            "$id": "EHbxC6vD0mU49geUxIfcQtTxP2tAqay7QCz3CVzfSdHz",
            "description": "Rules block",
            "type": "object",
            "properties": {
                "d": {"description": "Rules block SAID", "type": "string"},
                "aliasDesignation": {
                    "description": "Alias designation",
                    "type": "object",
                    "properties": {
                        "l": {
                            "type": "string",
                            "const": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID.",
                        }
                    },
                },
                "usageDisclaimer": {
                    "description": "Usage Disclaimer",
                    "type": "object",
                    "properties": {
                        "l": {
                            "description": "Limitation of designation scope",
                            "type": "string",
                            "const": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID.",
                        }
                    },
                },
                "issuanceDisclaimer": {
                    "description": "Issuance Disclaimer",
                    "type": "object",
                    "properties": {
                        "l": {
                            "description": "Accuracy of information",
                            "type": "string",
                            "const": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified.",
                        }
                    },
                },
                "termsOfUse": {
                    "description": "Terms of use",
                    "type": "object",
                    "properties": {
                        "l": {
                            "type": "string",
                            "const": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller.",
                        }
                    },
                },
            },
            "additionalProperties": False,
            "required": [
                "d",
                "aliasDesignation",
                "usageDisclaimer",
                "issuanceDisclaimer",
                "termsOfUse",
            ],
        }

        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        db.schema.pin(schemer.said, schemer)

        sad = {
            "$id": "EBMVc1eOhOaA7MdwAlAX3KcvJRTpFrc7_xcB_XveYAEE",
            "description": "Attributes block",
            "type": "object",
            "properties": {
                "d": {"description": "Attributes block SAID", "type": "string"},
                "dt": {
                    "description": "Designation date time",
                    "type": "string",
                    "format": "date-time",
                },
                "ids": {
                    "description": "List of namespaced/controlled AID aliases designated by the AID controller",
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": False,
            "required": ["d", "dt", "ids"],
        }
        
        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        db.schema.pin(schemer.said, schemer)

        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Designated Aliases Public Attestation",
            "description": "A public attestation listing the designated aliases of an AID controller.",
            "type": "object",
            "credentialType": "DesignatedAliasesPublicAttestation",
            "version": "1.0.0",
            "properties": {
                "v": {"description": "Version", "type": "string"},
                "d": {"description": "Attestation SAID", "type": "string"},
                "i": {"description": "Controller AID", "type": "string"},
                "ri": {"description": "Attestation status registry", "type": "string"},
                "s": {
                    "description": "schema section",
                    "oneOf": [
                        {"description": "schema section SAID", "type": "string"},
                        {"description": "schema detail", "type": "object"},
                    ],
                },
                "a": {
                    "oneOf": [
                        {"description": "Attributes block SAID", "type": "string"},
                        {
                            "$id": "EBMVc1eOhOaA7MdwAlAX3KcvJRTpFrc7_xcB_XveYAEE",
                            "description": "Attributes block",
                            "type": "object",
                            "properties": {
                                "d": {
                                    "description": "Attributes block SAID",
                                    "type": "string",
                                },
                                "dt": {
                                    "description": "Designation date time",
                                    "type": "string",
                                    "format": "date-time",
                                },
                                "ids": {
                                    "description": "List of namespaced/controlled AID aliases designated by the AID controller",
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "additionalProperties": False,
                            "required": ["d", "dt", "ids"],
                        },
                    ]
                },
                "r": {
                    "oneOf": [
                        {"description": "Rules block SAID", "type": "string"},
                        {
                            "$id": "EHbxC6vD0mU49geUxIfcQtTxP2tAqay7QCz3CVzfSdHz",
                            "description": "Rules block",
                            "type": "object",
                            "properties": {
                                "d": {
                                    "description": "Rules block SAID",
                                    "type": "string",
                                },
                                "aliasDesignation": {
                                    "description": "Alias designation",
                                    "type": "object",
                                    "properties": {
                                        "l": {
                                            "type": "string",
                                            "const": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID.",
                                        }
                                    },
                                },
                                "usageDisclaimer": {
                                    "description": "Usage Disclaimer",
                                    "type": "object",
                                    "properties": {
                                        "l": {
                                            "description": "Limitation of designation scope",
                                            "type": "string",
                                            "const": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID.",
                                        }
                                    },
                                },
                                "issuanceDisclaimer": {
                                    "description": "Issuance Disclaimer",
                                    "type": "object",
                                    "properties": {
                                        "l": {
                                            "description": "Accuracy of information",
                                            "type": "string",
                                            "const": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified.",
                                        }
                                    },
                                },
                                "termsOfUse": {
                                    "description": "Terms of use",
                                    "type": "object",
                                    "properties": {
                                        "l": {
                                            "type": "string",
                                            "const": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller.",
                                        }
                                    },
                                },
                            },
                            "additionalProperties": False,
                            "required": [
                                "d",
                                "aliasDesignation",
                                "usageDisclaimer",
                                "issuanceDisclaimer",
                                "termsOfUse",
                            ],
                        },
                    ]
                },
            },
            "additionalProperties": False,
            "required": ["v", "d", "i", "ri", "s", "a", "r"],
        }

        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5
        assert schemer.said == Schema.DES_ALIASES_SCHEMA
        db.schema.pin(schemer.said, schemer)
        
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Legal Entity Engagement Context Role vLEI Credential",
            "description": "A vLEI Role Credential issued to representatives of a Legal Entity in other than official roles but in functional or other context of engagement",
            "type": "object",
            "credentialType": "LegalEntityEngagementContextRolevLEICredential",
            "version": "1.0.0",
            "properties": {
                "v": {
                "description": "Version",
                "type": "string"
                },
                "d": {
                "description": "Credential SAID",
                "type": "string"
                },
                "u": {
                "description": "A salty nonce",
                "type": "string"
                },
                "i": {
                "description": "QVI or LE Issuer AID",
                "type": "string"
                },
                "ri": {
                "description": "Credential status registry",
                "type": "string"
                },
                "s": {
                "description": "Schema SAID",
                "type": "string"
                },
                "a": {
                "oneOf": [
                    {
                    "description": "Attributes block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EDv4wiOMHE125CXu-EuOd0YRXz-AgpLilJfjoODFqtHD",
                    "description": "Attributes block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Attributes block SAID",
                        "type": "string"
                        },
                        "u": {
                        "description": "A salty nonce",
                        "type": "string"
                        },
                        "i": {
                        "description": "Person Issuee AID",
                        "type": "string"
                        },
                        "dt": {
                        "description": "Issuance date time",
                        "type": "string",
                        "format": "date-time"
                        },
                        "LEI": {
                        "description": "LEI of the Legal Entity",
                        "type": "string",
                        "format": "ISO 17442"
                        },
                        "personLegalName": {
                        "description": "Recipient name as provided during identity assurance",
                        "type": "string"
                        },
                        "engagementContextRole": {
                        "description": "Role description i.e. 'Head of Standards'",
                        "type": "string"
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "i",
                        "dt",
                        "LEI",
                        "personLegalName",
                        "engagementContextRole"
                    ]
                    }
                ]
                },
                "e": {
                "oneOf": [
                    {
                    "description": "Edges block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EEM9OvWMEmAfAY0BV2kXatSc8WM13QW1B5y33E8z4f33",
                    "description": "Edges block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Edges block SAID",
                        "type": "string"
                        },
                        "auth": {
                        "description": "Chain to Auth vLEI credential from legal entity",
                        "type": "object",
                        "properties": {
                            "n": {
                            "description": "SAID of the ACDC to which the edge connects",
                            "type": "string"
                            },
                            "s": {
                            "description": "SAID of required schema of the credential pointed to by this node",
                            "type": "string",
                            "const": f"{Schema.ECR_AUTH_SCHEMA}"
                            },
                            "o": {
                            "description": "Operator indicating this node is the issuer",
                            "type": "string",
                            "const": "I2I"
                            }
                        },
                        "additionalProperties": False,
                        "required": [
                            "n",
                            "s",
                            "o"
                        ]
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "auth"
                    ]
                    },
                    {
                    "$id": "EHeZGaLBhCc_-sAcyAEgFFeCkxgnqCubPOBuEvoh9jHX",
                    "description": "Edges block for issuance from Legal Entity",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "SAID of edges block",
                        "type": "string"
                        },
                        "le": {
                        "description": "Chain to legal entity vLEI credential",
                        "type": "object",
                        "properties": {
                            "n": {
                            "description": "SAID of the ACDC to which the edge connects",
                            "type": "string"
                            },
                            "s": {
                            "description": "SAID of required schema of the credential pointed to by this node",
                            "type": "string",
                            "const": "EHyKQS68x_oWy8_vNmYubA5Y0Tse4XMPFggMfoPoERaM"
                            }
                        },
                        "additionalProperties": False,
                        "required": [
                            "n",
                            "s"
                        ]
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "le"
                    ]
                    }
                ]
                },
                "r": {
                "oneOf": [
                    {
                    "description": "Rules block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EEBm6OIpem19B8BzxWXOAuzKTtYeutGpXMLW9o3pAuRe",
                    "description": "Rules block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Rules block SAID",
                        "type": "string"
                        },
                        "usageDisclaimer": {
                        "description": "Usage Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
                            }
                        }
                        },
                        "issuanceDisclaimer": {
                        "description": "Issuance Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
                            }
                        }
                        },
                        "privacyDisclaimer": {
                        "description": "Privacy Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification."
                            }
                        }
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "usageDisclaimer",
                        "issuanceDisclaimer",
                        "privacyDisclaimer"
                    ]
                    }
                ]
                }
            },
            "additionalProperties": False,
            "required": [
                "v",
                "u",
                "i",
                "ri",
                "s",
                "d",
                "r",
                "a",
                "e"
            ]
        }
        
        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EPhh9YQUM1vuIpjvxFCb9pS7lq3YjQRRWtQ4xUiEcPNV
        assert schemer.said == Schema.ECR_SCHEMA
        db.schema.pin(schemer.said, schemer)
        
        sad = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "ECR Authorization vLEI Credential",
            "description": "A vLEI Authorization Credential issued by a Legal Entity to a QVI for the authorization of ECR credentials",
            "type": "object",
            "credentialType": "ECRAuthorizationvLEICredential",
            "version": "1.0.0",
            "properties": {
                "v": {
                "description": "Version",
                "type": "string"
                },
                "d": {
                "description": "Credential SAID",
                "type": "string"
                },
                "u": {
                "description": "One time use nonce",
                "type": "string"
                },
                "i": {
                "description": "LE Issuer AID",
                "type": "string"
                },
                "ri": {
                "description": "Credential status registry",
                "type": "string"
                },
                "s": {
                "description": "Schema SAID",
                "type": "string"
                },
                "a": {
                "oneOf": [
                    {
                    "description": "Attributes block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EBMwtCJt7LUfA9u0jmZ1cAoCavZFIBmZBmlufYeX4gdy",
                    "description": "Attributes block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Attributes block SAID",
                        "type": "string"
                        },
                        "i": {
                        "description": "QVI Issuee AID",
                        "type": "string"
                        },
                        "dt": {
                        "description": "Issuance date time",
                        "type": "string",
                        "format": "date-time"
                        },
                        "AID": {
                        "description": "AID of the intended recipient of the ECR credential",
                        "type": "string"
                        },
                        "LEI": {
                        "description": "LEI of the requesting Legal Entity",
                        "type": "string",
                        "format": "ISO 17442"
                        },
                        "personLegalName": {
                        "description": "Requested recipient name as provided during identity assurance",
                        "type": "string"
                        },
                        "engagementContextRole": {
                        "description": "Requested role description i.e. 'Head of Standards'",
                        "type": "string"
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "i",
                        "dt",
                        "AID",
                        "LEI",
                        "personLegalName",
                        "engagementContextRole"
                    ]
                    }
                ]
                },
                "e": {
                "oneOf": [
                    {
                    "description": "Edges block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "EB6E1GJvVen5NqkKb2TG5jqX66vYOL3md-xkXQqQBySX",
                    "description": "Edges block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Edges block SAID",
                        "type": "string"
                        },
                        "le": {
                        "description": "Chain to legal entity vLEI credential",
                        "type": "object",
                        "properties": {
                            "n": {
                            "description": "QVI Issuer credential SAID",
                            "type": "string"
                            },
                            "s": {
                            "description": "SAID of required schema of the credential pointed to by this node",
                            "type": "string",
                            "const": "EHyKQS68x_oWy8_vNmYubA5Y0Tse4XMPFggMfoPoERaM"
                            }
                        },
                        "additionalProperties": False,
                        "required": [
                            "n",
                            "s"
                        ]
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "le"
                    ]
                    }
                ]
                },
                "r": {
                "oneOf": [
                    {
                    "description": "Rules block SAID",
                    "type": "string"
                    },
                    {
                    "$id": "ELLuSgEW2h8n5fHKLvZc9uTtxzqXQqlWR7MiwEt7AcmM",
                    "description": "Rules block",
                    "type": "object",
                    "properties": {
                        "d": {
                        "description": "Rules block SAID",
                        "type": "string"
                        },
                        "usageDisclaimer": {
                        "description": "Usage Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
                            }
                        }
                        },
                        "issuanceDisclaimer": {
                        "description": "Issuance Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
                            }
                        }
                        },
                        "privacyDisclaimer": {
                        "description": "Privacy Disclaimer",
                        "type": "object",
                        "properties": {
                            "l": {
                            "description": "Associated legal language",
                            "type": "string",
                            "const": "Privacy Considerations are applicable to QVI ECR AUTH vLEI Credentials.  It is the sole responsibility of QVIs as Issuees of QVI ECR AUTH vLEI Credentials to present these Credentials in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification.  https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification."
                            }
                        }
                        }
                    },
                    "additionalProperties": False,
                    "required": [
                        "d",
                        "usageDisclaimer",
                        "issuanceDisclaimer",
                        "privacyDisclaimer"
                    ]
                    }
                ]
                }
            },
            "additionalProperties": False,
            "required": [
                "i",
                "ri",
                "s",
                "d",
                "e",
                "r"
            ]
            }
            
        _, sad = coring.Saider.saidify(sad, label=coring.Saids.dollar)
        schemer = scheming.Schemer(sed=sad)
        # NEW: EJOkgTilEMjPgrEr0yZDS_MScnI0pBb75tO54lvXugOy
        assert schemer.said == Schema.ECR_AUTH_SCHEMA
        db.schema.pin(schemer.said, schemer)

class Helpers:
    @staticmethod
    def remove_test_dirs(name):
        if os.path.exists(f"/usr/local/var/keri/db/{name}"):
            shutil.rmtree(f"/usr/local/var/keri/db/{name}")
        if os.path.exists(f"/usr/local/var/keri/ks/{name}"):
            shutil.rmtree(f"/usr/local/var/keri/ks/{name}")
        if os.path.exists(f"/usr/local/var/keri/reg/{name}"):
            shutil.rmtree(f"/usr/local/var/keri/reg/{name}")
        if os.path.exists(f"/usr/local/var/keri/cf/{name}.json"):
            os.remove(f"/usr/local/var/keri/cf/{name}.json")
        if os.path.exists(f"/usr/local/var/keri/cf/{name}"):
            shutil.rmtree(f"/usr/local/var/keri/cf/{name}")
        if os.path.exists(f"~/.keri/db/{name}"):
            shutil.rmtree(f"~/.keri/db/{name}")
        if os.path.exists(f"~/.keri/ks/{name}"):
            shutil.rmtree(f"~/.keri/ks/{name}")
        if os.path.exists(f"~/.keri/reg/{name}"):
            shutil.rmtree(f"~/.keri/reg/{name}")
        if os.path.exists(f"~/.keri/cf/{name}.json"):
            os.remove(f"~/.keri/cf/{name}.json")
        if os.path.exists(f"~/.keri/cf/{name}"):
            shutil.rmtree(f"~/.keri/cf/{name}")


@pytest.fixture
def helpers():
    return Helpers


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running a single command-line command by initializing
    the doers for that command and executing them until they complete.

    """

    def __init__(self, command, **kwa):
        self.command = command
        super(CommandDoer, self).__init__(doers=[doing.doify(self.cmdDo)], **kwa)

    def cmdDo(self, tymth, tock=0.0):
        """Execute single command from .command by parsing and executing the resulting doers"""

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock

        parser = multicommand.create_parser(commands)
        args = parser.parse_args(self.command)
        assert args.handler is not None
        doers = args.handler(args)

        self.extend(doers)

        while True:
            done = True
            for doer in doers:
                if not doer.done:
                    done = False

            if done:
                break
            yield self.tock

        return True
