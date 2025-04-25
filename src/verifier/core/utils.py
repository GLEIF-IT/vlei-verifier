import json
import time
import re
from typing import List, Dict, Any, Optional

from keri import kering
from keri.core import MtrDex, coring, parsing
import keri.help.helping as help
from keri.db import basing
from verifier.core.basing import AUTH_REVOKED, CredProcessState, RootOfTrust, AidProcessState, StateHistory
from enum import Enum
from keri.end import ending


class SignatureHeaderError(Exception):
    """Exception raised when there is an error processing signature headers.
    
    This exception is used to indicate that required signature headers are missing or invalid
    in a request. It includes a JSON-formatted error message and an HTTP status code.
    """
    pass


class SignatureVerificationStatus(Enum):
    """Enumeration of possible signature verification statuses.
    
    This enum defines the possible outcomes of a signature verification process:
    - SUCCESS: The signature was successfully verified
    - UNAUTHORIZED: The signature verification failed due to unauthorized access
    - BAD_SIGNATURE: The signature verification failed due to an invalid signature
    """
    SUCCESS = "SIGNATURE_VERIFICATION_SUCCESSFUL"
    UNAUTHORIZED = "SIGNATURE_VERIFICATION_FAILED_UNAUTHORIZED" 
    BAD_SIGNATURE = "SIGNATURE_VERIFICATION_FAILED_BAD_SIGNATURE"


class DigerBuilder:
    """Utility class for building Diger objects from various input formats.
    
    This class provides static methods to create Diger objects from different input formats,
    handling prefix removal and proper encoding.
    """
    
    @staticmethod
    def sha256(dig):
        """Create a SHA-256 Diger from a prefixed digest string.
        
        Args:
            dig (str): A prefixed digest string (e.g., "SHA2-256-<hex>")
            
        Returns:
            coring.Diger: A Diger object representing the SHA-256 digest
            
        Raises:
            Exception: If the digest cannot be processed
        """
        try:
            non_pref_dig = DigerBuilder.get_non_prefixed_digest(dig)  # Temporarily remove prefix
            non_pref_dig = bytes.fromhex(non_pref_dig)
            diger = DigerBuilder.build_diger(non_pref_dig, MtrDex.SHA2_256)
            return diger
        except Exception as e:
            raise e

    @staticmethod
    def get_non_prefixed_digest(dig):
        """Extract the digest part from a prefixed digest string.
        
        Args:
            dig (str): A prefixed digest string (e.g., "SHA2-256-<hex>")
            
        Returns:
            str: The hex-encoded digest without the prefix
            
        Raises:
            kering.ValidationError: If the digest does not contain a prefix
        """
        try:
            prefix, digest = dig.split("-", 1)
        except ValueError:
            raise kering.ValidationError(f"Digest ({dig}) must start with prefix")
        return digest

    @staticmethod
    def build_diger(raw, code):
        """Build a Diger object from raw bytes and a code.
        
        Args:
            raw (bytes): The raw digest bytes
            code (str): The code indicating the digest algorithm
            
        Returns:
            coring.Diger: A Diger object representing the digest
        """
        diger = coring.Diger(raw=raw, code=code)
        return diger


def process_revocations(vdb, creds, said):
    """Process credential revocations and update the database.
    
    This function checks if a credential has been revoked and updates the database
    accordingly. It sets the credential state to AUTH_REVOKED if a revocation is found.
    
    Args:
        vdb (VerifierBaser): The verifier database
        creds (list): List of KERI ACDCs (Authentic Chained Data Containers) to check for revocations
        said (str): The SAID of the credential to check
    """
    for cred in creds:
        if cred.get("sad", {}).get("d") == said:
            if cred.get("status", {}).get("et") == 'rev':
                aid = cred.get("sad").get("a").get("i")
                cur_state = vdb.iss.get(keys=(aid,))
                rev_state = CredProcessState(aid=cur_state.aid, said=said, info="Credential was revoked", state=AUTH_REVOKED, witness_url=cur_state.witness_url)
                vdb.iss.pin(keys=(aid,), val=rev_state)
                vdb.iss.pin(keys=(said,), val=rev_state)
                vdb.accts.rem(keys=(aid,))
                add_state_to_state_history(vdb, aid, rev_state)

def process_revocations_from_event_log(vdb, said, events):
    """Process revocations from an event log.
    
    This function processes revocations from an event log and updates the verifier database
    accordingly. It verifies the signature of each event and updates the credential state
    to AUTH_REVOKED if a revocation is found.
    
    Args:
        vdb (VerifierBaser): The verifier database
        said (str): The SAID of the credential to check
        events (list): List of events to process
    """
    for event in events:
        event_json = event.get("json", {})
        event_signature = event.get("signature", {})
        if event_json.get("t") == "rev" and event_json.get("i") == said:
            # TODO: Verify the signature
            cur_state: CredProcessState = vdb.iss.get(keys=(said,))
            aid = cur_state.aid
            if aid:
                cur_state: CredProcessState = vdb.iss.get(keys=(aid,))
            rev_state = CredProcessState(aid=aid, said=said, info="Credential was revoked", state=AUTH_REVOKED, witness_url=cur_state.witness_url)
            vdb.iss.pin(keys=(aid,), val=rev_state)
            vdb.iss.pin(keys=(said,), val=rev_state)
            vdb.accts.rem(keys=(aid,))
            add_state_to_state_history(vdb, aid, rev_state)


def add_root_of_trust(ims, hby, tvy, vry, vdb, aid, oobi):
    """Add a root of trust to the verifier database.
    
    This function parses the provided message, checks if the AID is found,
    and adds it as a root of trust if found. It also adds the OOBI if provided.
    
    Args:
        ims (bytes): The message to parse
        hby (Habery): The KERI habery
        tvy (Tevery): The KERI tevery
        vry (Verifier): The KERI verifier
        vdb (VerifierBaser): The verifier database
        aid (str): The AID to add as a root of trust
        oobi (str): The OOBI to add (optional)
        
    Returns:
        bool: True if the root of trust was added, False otherwise
    """
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
    """Add an OOBI (Out-of-Band Introduction) to the KERI habery.
    
    Args:
        hby (Habery): The KERI habery
        oobi (str): The OOBI to add
        
    Returns:
        bool: True if the OOBI was added, False otherwise
    """
    try:
        obr = basing.OobiRecord(date=help.toIso8601())
        hby.db.oobis.pin(keys=(oobi,), val=obr)
        return True
    except Exception as e:
        return False


def add_state_to_state_history(vdb, aid: str, state: CredProcessState | AidProcessState):
    """Add a state to the state history for an AID.
    
    This function adds a state to the state history for an AID. If the AID
    already has a state history, the state is appended to it. Otherwise, a new
    state history is created.
    
    Args:
        vdb (VerifierBaser): The verifier database
        aid (str): The AID to add the state to
        state (CredProcessState | AidProcessState): The state to add
        
    Returns:
        StateHistory: The updated state history
    """
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
    """Get the state history for an AID.
    
    Args:
        vdb (VerifierBaser): The verifier database
        aid (str): The AID to get the state history for
        
    Returns:
        list: The state history for the AID, or an empty list if no history exists
    """
    history_object: StateHistory = vdb.hst.get(keys=(aid,))
    if history_object:
        return history_object.state_history
    else:
        return []


def process_signature_headers(headers, req):
    """Process signature headers and return signature and encoded data.
    
    This function extracts and processes signature headers from a request,
    returning the signature and the encoded data that was signed.
    
    Args:
        headers (dict): Request headers dictionary
        req (Request): Request object
        
    Returns:
        tuple: (signature, encoded_data) where signature is the qb64-encoded signature
               and encoded_data is the data that was signed
        
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
    """Verify a signed request header using the AID's current key state.
    
    This function verifies a signature against an AID's current key state,
    returning a status and message indicating success or failure.
    
    Args:
        hby (Habery): Habery environment containing key state
        aid (str): AID to verify signature against
        signature (str): qb64 encoded signature
        encoded_data (bytes): data that was signed
        
    Returns:
        tuple[SignatureVerificationStatus, str]: Status code and message indicating success or failure
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


def parse_cesr(cesr: str) -> Optional[List[Dict[str, Any]]]:
    """Parse a CESR (Composable Event Streaming Representation) string into a list of JSON objects with signatures.
    
    This function extracts signatures from a CESR string and converts the remaining JSON parts into a list of objects.
    Each object in the result contains the corresponding signature and JSON data.
    
    Args:
        cesr (str): The CESR string to parse
        
    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries containing 'signature' and 'json' keys,
                                        or None if the CESR string is invalid
    """
    # Extract signatures using regex
    signature_regex = r'(?<=})(-.*?)(?={|$)'
    signatures = re.findall(signature_regex, cesr)
    
    # Replace signatures with commas to create a valid JSON array
    json_string = f"[{re.sub(signature_regex, ',', cesr).strip()}]"
    # Remove trailing comma if present
    json_string = re.sub(r',(?=[^,]*$)', '', json_string)
    
    try:
        parsed_json = json.loads(json_string)
    except json.JSONDecodeError as error:
        print(f"Invalid JSON: {error}")
        return None
    
    # Combine JSON objects with their signatures
    parsed_cesr = []
    for i, json_item in enumerate(parsed_json):
        if i < len(signatures):
            parsed_cesr.append({
                "signature": signatures[i],
                "json": json_item
            })
    
    return parsed_cesr