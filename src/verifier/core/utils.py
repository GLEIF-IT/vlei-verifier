import json
import time
from typing import List

from keri import kering
from keri.core import MtrDex, coring, parsing
import keri.help.helping as help
from keri.db import basing
from verifier.core.basing import AUTH_REVOKED, CredProcessState, RootOfTrust, AidProcessState, StateHistory
from enum import Enum
from keri.end import ending


class SignatureHeaderError(Exception):
    """Raised when there is an error processing signature headers"""
    pass

class SignatureVerificationStatus(Enum):
    SUCCESS = "SIGNATURE_VERIFICATION_SUCCESSFUL"
    UNAUTHORIZED = "SIGNATURE_VERIFICATION_FAILED_UNAUTHORIZED" 
    BAD_SIGNATURE = "SIGNATURE_VERIFICATION_FAILED_BAD_SIGNATURE"

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


def add_state_to_state_history(vdb, aid: str, state: CredProcessState | AidProcessState):
    history_object: StateHistory = vdb.hst.get(keys=(aid,))
    update_time = time.time()
    if history_object:
        history_object.state_history.append(state)
        history_object.last_update = update_time
        vdb.hst.pin(keys=(aid,), val=history_object)
    else:
        state_history: List[CredProcessState | AidProcessState] = [state]
        history_object: StateHistory = StateHistory(aid, update_time, state_history)
        vdb.hst.pin(keys=(aid,), val=history_object)

    return history_object


def get_state_to_state_history(vdb, aid: str):
    history_object: StateHistory = vdb.hst.get(keys=(aid,))
    if history_object:
        return history_object.state_history
    else:
        return []



def process_signature_headers(headers, req):
    """Process signature headers and return signature and encoded data
    
    Args:
        headers: Request headers dictionary
        req: Request object
        
    Returns:
        tuple: (signature, encoded_data)
        
    Raises:
        SignatureHeaderError: If required headers are missing or invalid
    """
    if (
            "SIGNATURE-INPUT" not in headers
            or "SIGNATURE" not in headers
            or "SIGNIFY-RESOURCE" not in headers
            or "SIGNIFY-TIMESTAMP" not in headers
    ):
        raise SignatureHeaderError(
            json.dumps({"msg": "Incorrect Headers"}), 401
        )

    siginput = headers["SIGNATURE-INPUT"]
    signature = headers["SIGNATURE"]
    resource = headers["SIGNIFY-RESOURCE"]

    inputs = ending.desiginput(siginput.encode("utf-8"))
    inputs = [i for i in inputs if i.name == "signify"]

    if not inputs:
        raise SignatureHeaderError(
            json.dumps({"msg": "Incorrect Headers"}), 401
        )

    for inputage in inputs:
        items = []
        for field in inputage.fields:
            if field.startswith("@"):
                if field == "@method":
                    items.append(f'"{field}": {req.method}')
                elif field == "@path":
                    items.append(f'"{field}": {req.path}')

            else:
                key = field.upper()
                field = field.lower()
                if key not in headers:
                    continue

                value = ending.normalize(headers[key])
                items.append(f'"{field}": {value}')

        values = [f"({' '.join(inputage.fields)})", f"created={inputage.created}"]
        if inputage.expires is not None:
            values.append(f"expires={inputage.expires}")
        if inputage.nonce is not None:
            values.append(f"nonce={inputage.nonce}")
        if inputage.keyid is not None:
            values.append(f"keyid={inputage.keyid}")
        if inputage.context is not None:
            values.append(f"context={inputage.context}")
        if inputage.alg is not None:
            values.append(f"alg={inputage.alg}")

        params = ";".join(values)

        items.append(f'"@signature-params: {params}"')
        ser = "\n".join(items)

        signages = ending.designature(signature)
        cig = signages[0].markers[inputage.name]

        sig = cig.qb64
        return sig, ser



def verify_signed_headers(hby, aid, signature, encoded_data) -> tuple[SignatureVerificationStatus, str]:
    """Verify a signed request header using the AID's current key state

    Parameters:
        hby (Habery): Habery environment containing key state
        aid (str): AID to verify signature against
        signature (str): qb64 encoded signature
        encoded_data (bytes): data that was signed

    Returns:
        tuple[str, str]: Status code and message indicating success or failure
    """
    try:
        kever = hby.kevers[aid]
    except KeyError:
        return SignatureVerificationStatus.UNAUTHORIZED, f"unknown {aid} used to sign header"

    verfers = kever.verfers
    if not verfers:
        return SignatureVerificationStatus.UNAUTHORIZED, f"No verification keys found for {aid}"

    try:
        cigar = coring.Cigar(qb64=signature)
    except Exception as e:
        return SignatureVerificationStatus.BAD_SIGNATURE, f"{aid} provided invalid Cigar signature on encoded request data"

    try:
        if not verfers[0].verify(sig=cigar.raw, ser=encoded_data):
            return SignatureVerificationStatus.UNAUTHORIZED, f"{aid} signature (Cigar) verification failed on encoding of request data"
    except Exception as e:
        return SignatureVerificationStatus.UNAUTHORIZED, f"Error verifying signature"

    return SignatureVerificationStatus.SUCCESS, "Signature valid"