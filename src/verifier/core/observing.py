import logging

import requests
from keri.core import parsing
from keri.vdr import verifying, eventing
from hio.base import doing

from verifier.core.basing import CredProcessState, AUTH_REVOKED, OBSERVER_REVOCATION_CHECK_FAILED, CRED_CRYPT_INVALID
from verifier.core.resolve_env import VerifierEnvironment
from verifier.core.utils import (
    add_state_to_state_history,
    parse_cesr,
    process_revocations_from_event_log,
    validate_witness_url,
)

logger = logging.getLogger(__name__)

_SKIP_REV_CHECK_STATES = frozenset({
    AUTH_REVOKED,
    CRED_CRYPT_INVALID,
    OBSERVER_REVOCATION_CHECK_FAILED,
})


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

    def _mark_as_revocation_check_failed(self, said: str, reason: str):
        cur_state: CredProcessState = self.vdb.iss.get(keys=(said,))
        aid = cur_state.aid
        if aid:
            cur_state: CredProcessState = self.vdb.iss.get(keys=(aid,))
        rev_state = CredProcessState(aid=aid, said=said, info=reason, state=OBSERVER_REVOCATION_CHECK_FAILED,
                                     witness_url=cur_state.witness_url)
        if aid and self.vdb.iss.get(keys=(aid,)):
            self.vdb.iss.pin(keys=(aid,), val=rev_state)
            self.vdb.accts.rem(keys=(aid,))
            add_state_to_state_history(self.vdb, aid, rev_state)
        self.vdb.iss.pin(keys=(said,), val=rev_state)

    def _check_revocations(self):
        """Check revocation status for all credentials in the database."""
        env = VerifierEnvironment.resolve_env()
        if env.revocationCheck is False:
            return

        # Get all credentials from the database
        for (aid,), state in self.vdb.iss.getItemIter():
            if state.state in _SKIP_REV_CHECK_STATES:
                continue

            # If witness URL is provided, check with the witness
            if state.witness_url:
                witness_ok, witness_msg = validate_witness_url(
                    state.witness_url, env.witnessUrlAllowlist, env.mode
                )
                if not witness_ok:
                    self._mark_as_revocation_check_failed(state.said, witness_msg)
                    continue
                try:
                    witness_response = requests.get(
                        f"{state.witness_url}/query?typ=tel&vcid={state.said}",
                        timeout=30,
                    )
                    if witness_response.status_code == 200:
                        witness_creds = witness_response.text
                        parsed_cesr = parse_cesr(witness_creds)
                        if parsed_cesr:
                            process_revocations_from_event_log(self.vdb, state.said, parsed_cesr)
                        else:
                            reason = f"No valid OOBI found for credential {state.said}"
                            print(reason)
                            self._mark_as_revocation_check_failed(state.said, reason)
                    continue
                except requests.exceptions.ConnectionError:
                    reason = (
                        f"Error checking witness for credential {state.said}: "
                        f"Witness {state.witness_url} is unavailable"
                    )
                    logger.warning(reason)
                    self._mark_as_revocation_check_failed(state.said, reason)
                except Exception:
                    reason = f"Error checking witness for credential {state.said}: unexpected error"
                    logger.exception(reason)
                    self._mark_as_revocation_check_failed(state.said, reason)

            else:
                reason = f"No witness URL provided for credential {state.said}"
                logger.info(reason)
                self._mark_as_revocation_check_failed(state.said, reason)

