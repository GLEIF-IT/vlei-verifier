import requests

from hio.base import doing
from verifier.core.basing import CredProcessState, AUTH_REVOKED
from verifier.core.resolve_env import VerifierEnvironment
from verifier.core.utils import add_state_to_state_history, process_revocations_from_event_log, parse_cesr
from keri.vdr import verifying, eventing


class CredentialRevocationChecker(doing.Doer):
    """Doer (coroutine) responsible for checking credential revocation status from witnesses."""
    
    def __init__(self, hby, vdb, reger, interval: float = 5.0):
        """Initialize the credential revocation checker.
        
        Parameters:
            hby: KERI Habery instance
            vdb: VerifierBaser instance
            reger: Credential registry instance
            interval: Check interval in seconds (default: 60.0)
        """
        self.hby = hby
        self.vdb = vdb
        self.reger = reger
        self.interval = interval
        self.lastCheck = 0.0
        self.vry = verifying.Verifier(hby=hby, reger=reger)
        self.tvy = eventing.Tevery(reger=reger, db=hby.db, local=False)
        super(CredentialRevocationChecker, self).__init__()
            
    def recur(self, tyme):
        """Process all credential revocations once per recurrence."""
        if tyme - self.lastCheck >= self.interval:
            self._check_revocations()
            self.lastCheck = tyme
        return False
            
    def _check_revocations(self):
        """Check revocation status for all credentials in the database."""
        # Get all credentials from the database
        for (aid,), state in self.vdb.iss.getItemIter():
            if state.state == AUTH_REVOKED:
                continue
            env = VerifierEnvironment.resolve_env()

            # If witness URL is provided, check with the witness
            if state.witness_url:
                try:
                    witness_response = requests.get(f"{state.witness_url}/query?typ=tel&vcid={state.said}")
                    if witness_response.status_code == 200:
                        witness_creds = witness_response.text
                        parsed_cesr = parse_cesr(witness_creds)
                        if parsed_cesr: 
                            process_revocations_from_event_log(self.vdb, state.said, parsed_cesr)
                        else:
                            print(f"No CESR found for credential {state.said}")
                            # Remove credential and associated data from database in production mode
                            # This ensures we don't keep invalid credentials
                            if env.mode == "production":
                                self.vdb.iss.rem(keys=(aid,))  
                                self.vdb.iss.rem(keys=(state.said,))  
                                self.vdb.acct.rem(keys=(aid,))  
                    continue
                except Exception as e:
                    print(f"Error checking witness for credential {state.said}: {e}")
            else:
                print(f"No witness URL provided for credential {state.said}")
                # Remove credential and associated data from database in production mode
                # This ensures we don't keep invalid credentials
                if env.mode == "production":
                    self.vdb.iss.rem(keys=(aid,))
                    self.vdb.iss.rem(keys=(state.said,))
                    self.vdb.acct.rem(keys=(aid,))


            

