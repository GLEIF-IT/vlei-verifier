# -*- encoding: utf-8 -*-
"""
verifier.app.cli.commands.server module

Verification service main command line handler.  Starts service using the provided parameters

"""
import argparse
import datetime
import json
import logging
import os
import re
import sys

import falcon
from hio.core import http
from keri import help
from keri.app import keeping, configing, habbing, oobiing
from keri.app.cli.common import existing
from keri.vdr import viring
from verifier.core import verifying, authorizing, basing, reporting
from verifier.core import constants
from verifier.core.constants import Schema
from verifier.core.resolve_env import VerifierEnvironment
from verifier.core.observing import CredentialRevocationChecker


parser = argparse.ArgumentParser(description='Launch vLEI Verification Service')
parser.set_defaults(handler=lambda args: launch(args),
                    transferable=True)
parser.add_argument('-p', '--http',
                    action='store',
                    default=7676,
                    help="Port on which to listen for verification requests")
parser.add_argument('-n', '--name',
                    action='store',
                    default="vdb",
                    help="Name of controller. Default is vdb.")
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--config-dir",
                    "-c",
                    dest="configDir",
                    help="directory override for configuration data",
                    default=None)
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default="dkr",
                    help="configuration filename override")

#
dev_only_endpoints = list(filter(None, os.environ.get('DEV_ONLY_ENDPOINTS', "").split(",")))


def silence_external_console_logs():
    """Prevent noisy dependency logs from reaching stdout/stderr."""
    for logger_name in ("keri", "hio"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False


class EnvironmentMiddleware:
    def process_request(self, req, resp):
        current_env = os.environ.get('VERIFIER_ENV', 'production')
        # Restrict access to specific endpoint in non-production environments
        if any(re.match(pattern, req.path) for pattern in dev_only_endpoints) and current_env == 'production':
            raise falcon.HTTPForbidden(
                title="Access Denied",
                description=f"This endpoint is not accessible in the {current_env} environment."
            )

class RequestResponseLoggerMiddleware:
    """Logs request metadata; response bodies are omitted unless explicitly enabled."""

    def __init__(self):
        self._log_bodies = os.getenv("VERIFIER_LOG_RESPONSE_BODIES", "false").lower() in (
            "true",
            "1",
        )

    def process_request(self, req, resp):
        timestamp = datetime.datetime.now().isoformat()
        logging.getLogger("verifier.http").info(
            "[%s] Incoming %s %s", timestamp, req.method, req.path
        )

    def process_response(self, req, resp, resource, req_succeeded):
        timestamp = datetime.datetime.now().isoformat()
        logger = logging.getLogger("verifier.http")
        logger.info(
            "[%s] Completed %s %s status=%s",
            timestamp,
            req.method,
            req.path,
            resp.status,
        )
        if self._log_bodies:
            body = resp.data if resp.data else resp.text
            logger.info("[%s] Response body: %s", timestamp, body)



def launch(args):
    """ Launch the verification service.

    Parameters:
        args (Namespace): command line namespace object containing the parsed command line arguments

    Returns:

    """

    name = args.name
    base = args.base
    bran = args.bran
    httpPort = args.http

    configFile = args.configFile
    configDir = args.configDir

    ks = keeping.Keeper(name=name,
                        base=base,
                        temp=False,
                        reopen=True)

    aeid = ks.gbls.get('aeid')

    cf = configing.Configer(name=configFile,
                            base=base,
                            headDirPath=configDir,
                            temp=False,
                            reopen=True,
                            clear=False)

    # Ensure verifier logs go to console by default. Without a handler, INFO logs
    # from e.g. RequestResponseLoggerMiddleware may not show up anywhere.
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=logging.INFO,
            stream=sys.stdout,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

    help.ogler.level = logging.INFO
    logging.getLogger("verifier").setLevel(logging.INFO)
    logging.getLogger("verifier.http").setLevel(logging.INFO)

    silence_external_console_logs()
    config = cf.get()
    allowed_schemas = [
        getattr(Schema, x) for x in config.get("allowedSchemas", []) if getattr(Schema, x, None)
    ]
    """Verifier Mode Configuration

    The verifier can run in two modes:

    'production' mode (default):
    - Enforces signed header verification for /authorizations requests 
    - /root_of_trust endpoint is disabled for security
    - Recommended for production deployments

    'test' mode:
    - Disables signed header verification for /authorizations requests
    - Enables /root_of_trust endpoint to dynamically add new roots of trust 
    - Only recommended for testing and development

    Mode can be set via VERIFIER_MODE environment variable:
    export VERIFIER_MODE=test|production
    """
    verifier_mode = os.environ.get("VERIFIER_MODE", "production")
    verify_rot = os.getenv("VERIFY_ROOT_OF_TRUST", "True").lower() in ("true", "1")
    trusted_leis = config.get("trustedLeis", [])
    revocation_check = config.get("revocationCheck", False)
    max_presentation_size = config.get("maxPresentationSize", 0)
    witness_allowlist = list(config.get("witnessUrlAllowlist", []))
    env_witness_allowlist = os.getenv("WITNESS_URL_ALLOWLIST", "")
    if env_witness_allowlist:
        witness_allowlist.extend(
            entry.strip() for entry in env_witness_allowlist.split(",") if entry.strip()
        )
    
    ve_init_params = {
        "maxPresentationSize": max_presentation_size,
        "configuration": cf,
        "mode": verifier_mode,
        "trustedLeis": trusted_leis if trusted_leis else [],
        "verifyRootOfTrust": verify_rot,
        "revocationCheck": revocation_check,
        "witnessUrlAllowlist": witness_allowlist
    }

    print("ALLOWED", allowed_schemas)
    if allowed_schemas:
        ve_init_params["authAllowedSchemas"] = allowed_schemas

    ve = VerifierEnvironment.initialize(**ve_init_params)
    hby = habbing.Habery(name=name, base=base, bran=bran, cf=cf, temp=True)

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    obl = oobiing.Oobiery(hby=hby)

    reger = viring.Reger(name=hby.name, temp=hby.temp)
    vdb = basing.VerifierBaser(name=hby.name, temp=True)
    cors_middleware = falcon.CORSMiddleware(
        allow_origins='*',
        allow_credentials='*',
        expose_headers=['cesr-attachment', 'cesr-date', 'content-type']
    )

    environment_middleware = EnvironmentMiddleware()
    request_response_logger_middleware = RequestResponseLoggerMiddleware()
    app = falcon.App(
        middleware=[cors_middleware, environment_middleware, request_response_logger_middleware])

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    verifying.setup(app, hby=hby, vdb=vdb, reger=reger)
    reportDoers = reporting.setup(app=app, hby=hby, vdb=vdb)
    authDoers = authorizing.setup(hby, vdb=vdb, reger=reger)

    # Initialize the credential revocation checker doer if revocationCheck is True
    if ve.revocationCheck is True:
        revocation_checker = CredentialRevocationChecker(hby=hby, vdb=vdb, reger=reger)
        doers = obl.doers + authDoers + reportDoers + [hbyDoer, httpServerDoer, revocation_checker]
    else:
        doers = obl.doers + authDoers + reportDoers + [hbyDoer, httpServerDoer]

    print(f"vLEI Verification Service running and listening on: {httpPort}")
    return doers
