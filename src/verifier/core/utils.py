import json

from keri import kering
from keri.core import MtrDex, coring, parsing
import keri.help.helping as help
from keri.db import basing
from verifier.core.basing import AUTH_REVOKED, CredProcessState, RootOfTrust


class DigerBuilder:
    @staticmethod
    def sha256(dig):
        try:
            non_pref_dig = DigerBuilder.get_non_prefixed_digest(dig)  # Temporarily remove prefix
            non_pref_dig = bytes.fromhex(non_pref_dig)
            diger = DigerBuilder.build_diger(non_pref_dig, MtrDex.SHA2_256)
            return diger
        except Exception as e:
            raise e

    @staticmethod
    def get_non_prefixed_digest(dig):
        try:
            prefix, digest = dig.split("-", 1)
        except ValueError:
            raise kering.ValidationError(f"Digest ({dig}) must start with prefix")
        return digest

    @staticmethod
    def build_diger(raw, code):
        diger = coring.Diger(raw=raw, code=code)
        return diger


def process_revocations(vdb, creds, said):
    for cred in creds:
        if cred.get("sad", {}).get("d") == said:
            if cred.get("status", {}).get("et") == 'rev':
                aid = cred.get("sad").get("a").get("i")
                rev_state = CredProcessState(said=said, info="Credential was revoked", state=AUTH_REVOKED)
                vdb.iss.pin(keys=(aid,), val=rev_state)
                vdb.iss.pin(keys=(said,), val=rev_state)


def add_root_of_trust(ims, hby, tvy, vry, vdb, aid, oobi):
    parsing.Parser().parse(ims=ims, kvy=hby.kvy, tvy=tvy, vry=vry)
    found = False
    while hby.kvy.cues:
        msg = hby.kvy.cues.popleft()
        if "serder" in msg:
            serder = msg["serder"]
            if serder.sad.get("i") == aid:
                found = True
    if oobi:
        add_oobi(hby, oobi)
    if found:
        root_of_trust = RootOfTrust(aid=aid)
        vdb.root.pin(keys=(aid,), val=root_of_trust)
        return True
    else:
        return False

def add_oobi(hby, oobi):
    try:
        obr = basing.OobiRecord(date=help.toIso8601())
        hby.db.oobis.pin(keys=(oobi,), val=obr)
        return True
    except Exception as e:
        return False


