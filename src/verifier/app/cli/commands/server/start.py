# -*- encoding: utf-8 -*-
"""
verifier.app.cli.commands.server module

Verification service main command line handler.  Starts service using the provided parameters

"""
import argparse
import os
import re

import falcon
from hio.core import http
from keri import help
from keri.app import keeping, configing, habbing, oobiing
from keri.app.cli.common import existing
from keri.vdr import viring
import logging
from verifier.core import verifying, authorizing, basing, reporting
from verifier.core.constants import Schema
from verifier.core.resolve_env import VerifierEnvironment
import datetime
import json


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
    def process_request(self, req, resp):
        # Log the request details
        timestamp = datetime.datetime.now().isoformat()
        method = req.method
        path = req.path

        print(f"[{timestamp}] Incoming Request: {method} {path}")

    def process_response(self, req, resp, resource, req_succeeded):
        timestamp = datetime.datetime.now().isoformat()
        method = req.method
        path = req.path
        status = resp.status
        body = resp.data if resp.data else resp.text

        # Convert body to a JSON string if applicable
        body_str = body

        print(f"[{timestamp}] Completed Request: {method} {path}")
        print(f"[{timestamp}] Response Status: {status}")
        print(f"[{timestamp}] Response Body:\n{body_str}\n")



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

    help.ogler.level = logging.DEBUG
    config = cf.get()
    allowed_schemas = [
        getattr(Schema, x) for x in config.get("allowedSchemas", []) if getattr(Schema, x, None)
    ]
    verifier_mode = os.environ.get("VERIFIER_ENV", "production")
    trusted_leis = config.get("trustedLeis", [])
    verify_rot = os.getenv("VERIFY_ROOT_OF_TRUST", "True").lower() in ("true", "1")

    ve_init_params = {
        "configuration": cf,
        "mode": verifier_mode,
        "trustedLeis": trusted_leis if trusted_leis else [],
        "verifyRootOfTrust": verify_rot,
    }

    print("ALLOWED", allowed_schemas)
    if allowed_schemas:
        ve_init_params["authAllowedSchemas"] = allowed_schemas

    ve = VerifierEnvironment.initialize(**ve_init_params)
    if aeid is None:
        hby = habbing.Habery(name=name, base=base, bran=bran, cf=cf)
    else:
        hby = existing.setupHby(name=name, base=base, bran=bran)

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    obl = oobiing.Oobiery(hby=hby)

    reger = viring.Reger(name=hby.name, temp=hby.temp)
    vdb = basing.VerifierBaser(name=hby.name)
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

    doers = obl.doers + authDoers + reportDoers + [hbyDoer, httpServerDoer]

    print(f"vLEI Verification Service running and listening on: {httpPort}")
    return doers
