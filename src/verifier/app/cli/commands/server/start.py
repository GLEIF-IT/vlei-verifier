# -*- encoding: utf-8 -*-
"""
verifier.app.cli.commands.server module

Verification service main command line handler.  Starts service using the provided parameters

"""
import argparse

import falcon
from hio.core import http
from keri import help
from keri.app import keeping, configing, habbing, oobiing
from keri.app.cli.common import existing
from keri.vdr import viring
import logging
from verifier.core import verifying, authorizing, basing, reporting

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

    if aeid is None:
        hby = habbing.Habery(name=name, base=base, bran=bran, cf=cf)
    else:
        hby = existing.setupHby(name=name, base=base, bran=bran)

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    obl = oobiing.Oobiery(hby=hby)

    reger = viring.Reger(name=hby.name, temp=hby.temp)
    vdb = basing.VerifierBaser(name=hby.name)

    app = falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins='*',
            allow_credentials='*',
            expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    verifying.setup(app, hby=hby, vdb=vdb, reger=reger)
    reportDoers = reporting.setup(app=app, hby=hby, vdb=vdb)
    authDoers = authorizing.setup(hby, vdb=vdb, reger=reger, cf=cf)

    doers = obl.doers + authDoers + reportDoers + [hbyDoer, httpServerDoer]

    print(f"vLEI Verification Service running and listening on: {httpPort}")
    return doers
