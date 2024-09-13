import json
import os
import tempfile
import zipfile
from collections import namedtuple
from dataclasses import asdict
from fileinput import filename
from hashlib import sha256

import falcon
from hio.base import doing
from keri import kering
from keri.core import coring, Siger, MtrDex

from verifier.core.basing import ReportStats
from verifier.core.utils import DigerBuilder

# Report Statuses.
Reportage = namedtuple("Reportage", "accepted verified failed")

# Referencable report status enumeration
ReportStatus = Reportage(accepted="accepted", verified="verified", failed="failed")


def setup(app, hby, vdb):
    """  Set up module endpoints and dependencies

    Parameters:
        app (App): falcon HTTP web app
        hby (Habery): identifier database environment
        vdb (VerifierBaser): verifier database environment

    Returns:
        list: Doers (coroutines) required for this module

    """
    filer = Filer(vdb=vdb)
    rverfer = ReportVerifier(hby=hby, vdb=vdb, filer=filer)

    loadEnds(app, hby, vdb, filer)

    return [rverfer]


def loadEnds(app, hby, vdb, filer):
    """ Load and map endpoint objects to routes for this module

    Parameters:
        app (App): falcon HTTP web app
        hby (Habery): identifier database environment
        vdb (VerifierBaser): verifier database environment
        filer (Filer): report status filer

    """
    reportEnd = ReportResourceEnd(hby, vdb, filer)
    app.add_route("/reports/{aid}/{dig}", reportEnd)


class Filer:
    """ Report status filer

    Business object for creating and maintaining report status updates for uploaded XBRL-CSV report packages.

    """

    def __init__(self, vdb):
        """  Create report status filer instance

        Parameters:
            vdb (VerifierBaser): verification database environment
        """
        self.vdb = vdb

    def create(self, aid, dig, filename, typ, stream):
        """ Create a new file upload with initial Accepted status.

        This method creates the report upload status object and queues it for report verification processing

        Parameters:
            aid (str): qb64 AID of uploader
            dig (str): qb64 digest of report content
            filename (str): filename reported from multipart/form filename field
            typ (str): content-type of file upload
            stream (File): file like stream object to load the report data from

        """
        self.vdb.delTopVal(db=self.vdb.imgs, key=dig.encode("utf-8"))
        stats = ReportStats(
            submitter=aid,
            filename=filename,
            status=ReportStatus.accepted,
            contentType=typ,
            size=0
        )

        idx = 0

        diger = DigerBuilder.sha256(dig)
        report = b''
        while True:
            chunk = stream.read(4096)
            report += chunk
            if not chunk:
                break
            key = f"{diger.qb64}.{idx}".encode("utf-8")
            self.vdb.setVal(db=self.vdb.imgs, key=key, val=chunk)
            idx += 1
            stats.size += len(chunk)

        if not diger.verify(report):
            raise kering.ValidationError(f"Report digets({dig} verification failed)")

        with tempfile.TemporaryFile("w+b") as tf:
            tf.write(report)
            tf.seek(0)
            with tempfile.TemporaryDirectory() as tempdirname:
                z = zipfile.ZipFile(tf)
                z.extractall(path=tempdirname)
                manifest = None
                for root, dirs, _ in os.walk(tempdirname):
                    if "META-INF" not in dirs:
                        continue
                    metaDir = os.path.join(root, 'META-INF')
                    name = os.path.join(root, 'META-INF', 'reports.json')
                    if not os.path.exists(name):
                        continue
                    f = open(name, 'r')
                    manifest = json.load(f)
                    if "documentInfo" not in manifest:
                        raise kering.ValidationError("Invalid manifest file in report package, missing "
                                                     "'documentInfo")
                if manifest is None:
                    raise kering.ValidationError("No manifest in file, invalid signed report package")

                docInfo = manifest["documentInfo"]
                if "signatures" not in docInfo:
                    raise kering.ValidationError("No signatures found in manifest file")

                signatures = docInfo["signatures"]
                for signature in signatures:
                    try:
                        fullpath = os.path.normpath(os.path.join(metaDir, signature["file"]))
                        f = open(fullpath, 'rb')
                        file_object = f.read()
                        f.close()
                        tmp_diger = DigerBuilder.sha256(signature["digest"])
                        if not tmp_diger.verify(file_object):
                            raise kering.ValidationError(f"Invalid digest for file {fullpath}")
                    except KeyError as e:
                        raise kering.ValidationError(f"Invalid digest, manifest digest missing '{e.args[0]}'")
                    except OSError:
                        raise kering.ValidationError(f"signature element={signature} point to invalid file")
                    except Exception as e:
                        raise kering.ValidationError(f"{e}")

        self.vdb.rpts.add(keys=(aid,), val=diger)
        self.vdb.stts.add(keys=(stats.status,), val=diger)
        self.vdb.stats.pin(keys=(diger.qb64,), val=stats)

    def get(self, dig):
        """ Return report stats for given report.

         Parameters:
            dig (str): qb64 digest of report content

         Returns:
             ReportStats:  Report stats for report with digest dig or None

         """
        diger = DigerBuilder.sha256(dig)
        return self.vdb.stats.get(keys=(diger.qb64,))

    def getData(self, dig):
        """ Generator that yields image data in 4k chunks for identifier

        Parameters:
            dig (str): qb64 digest of report to load

        """
        idx = 0
        while True:
            key = f"{dig}.{idx}".encode("utf-8")
            chunk = self.vdb.getVal(db=self.vdb.imgs, key=key)
            if not chunk:
                break
            yield bytes(chunk)
            idx += 1

    def getAcceptedIter(self):
        """ Generator that yields Diger values for all reports currently in Accepted status

        """
        for diger in self.vdb.stts.getIter(keys=(ReportStatus.accepted,)):
            yield diger

    def update(self, diger, status, msg=None):
        """ Set new report status for report identifier

        Parameters:
            diger (Diger): Diger object of digest for report
            status (str): new report status for report with digest dig
            msg (str): optional status message for report

        """
        if (stats := self.vdb.stats.get(keys=(diger.qb64,))) is None:
            return False

        self.vdb.stts.rem(keys=(stats.status,), val=diger)

        stats.status = status
        if msg is not None:
            stats.message = msg

        self.vdb.stts.add(keys=(stats.status,), val=diger)
        self.vdb.stats.pin(keys=(diger.qb64,), val=stats)


class ReportResourceEnd:
    """ Report resource endpoint capable of creating and retrieving report instances

    This endpoint accepts multipart/form stream uploads of report zip files but only returns report status objects
    on GET

    """

    def __init__(self, hby, vdb, filer):
        """ Create new report resource endpoint instance

        Parameters:
            hby (Habery): identifier database environment
            vdb (VerifierBaser): verifier database environment
            filer (Filer): report status filer

        """
        self.hby = hby
        self.vdb = vdb
        self.filer = filer

    def on_get(self, _, rep, aid, dig):
        """  Report Resource GET Method

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: qb64 identifier prefix of submitter
            dig: qb64 Digest of report contents

        ---
         summary: Retriever file upload status.
         description: Returns current status for previous submitted file identified by AID and DIG.
         tags:
            - Reports
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: qb64 AID of submitter
           - in: path
             name: dig
             schema:
                type: string
             description: qb64 hash digest of report contents
         responses:
           200:
              description: Report successfully uploaded

        """
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown AID: {aid}")

        if self.vdb.accts.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        stats = self.filer.get(dig)
        if stats is None:
            raise falcon.HTTPNotFound(description=f"report {dig} not found")

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(asdict(stats)).encode("utf-8")

    def on_post(self, req, rep, aid, dig):
        """  Report Resource POST Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: qb64 identifier prefix of uploader
            dig: qb64 Digest of report contents

        ---
         summary: Uploads an image to associate with identfier.
         description: Uploads an image to associate with identfier.
         tags:
            - Reports
         parameters:
           - in: path
             name: aid
             schema:
                type: string
             description: identifier prefix to associate image to
         requestBody:
             required: true
             content:
                multipart/form:
                  schema:
                    type: application/zip
                    format: binary
         responses:
           202:
              description: Reprot submission accepted

        """
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown AID: {aid}")

        if self.vdb.accts.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        form = req.get_media()
        upload = False
        for part in form:
            if part.name == "upload":
                try:
                    self.filer.create(aid=aid, dig=dig, filename=part.secure_filename, typ=part.content_type,
                                    stream=part.stream)
                    upload = True
                except Exception as e:
                    raise falcon.HTTPBadRequest(description=f"{str(e)}")

        if not upload:
            raise falcon.HTTPBadRequest(description=f"upload file content type must be multipart/form-data")

        rep.status = falcon.HTTP_202
        rep.data = json.dumps(dict(msg=f"Upload {dig} received from {aid}")).encode("utf-8")


class ReportVerifier(doing.Doer):
    """ Doer (coroutine) capable of processing submitted report files

    This coroutine recurs on the database up Accepted file uploads and processes them with the following steps:

       1. Extracts content of zip file from database into temporary directory.
       2. Ensures the zip file is a properly structured report package.
       3. Finds all digital signatures specified in the report package manifest file.
       4. Verifies the signatures for each file against the contents of the file.
       5. Validates that the submitter has signed all files in the report package.

    """

    def __init__(self, hby, vdb, filer, **kwargs):
        """  Create report verifier instance to process report submissions

        Parameters:
            hby (Habery): identifier database environment
            vdb (VerifierBaser): verifier database environment
            filer (Filer): report status filer
            **kwargs (dict): additional keyword arguments passed to the Doer super class

        """
        self.hby = hby
        self.vdb = vdb
        self.filer = filer

        super(ReportVerifier, self).__init__(**kwargs)

    def recur(self, tyme):
        """ Loop on all accepted report uploads in each iteration.

        Parameters:
            tyme (float): relative cycle time

        """
        for diger in self.filer.getAcceptedIter():
            try:
                stats = self.vdb.stats.get(keys=(diger.qb64,))
                print(f"Processing {stats.filename}:\n "
                      f"\tType={stats.contentType}\n"
                      f"\tSize={stats.size}")
                with tempfile.TemporaryFile("w+b") as tf:

                    for chunk in self.filer.getData(diger.qb64):
                        tf.write(chunk)

                    tf.seek(0)

                    with tempfile.TemporaryDirectory() as tempdirname:
                        z = zipfile.ZipFile(tf)
                        z.extractall(path=tempdirname)

                        files = []
                        manifest = None
                        for root, dirs, _ in os.walk(tempdirname):
                            if "META-INF" not in dirs:
                                continue

                            metaDir = os.path.join(root, 'META-INF')
                            name = os.path.join(root, 'META-INF', 'reports.json')
                            if not os.path.exists(name):
                                continue

                            f = open(name, 'r')
                            manifest = json.load(f)
                            if "documentInfo" not in manifest:
                                raise kering.ValidationError("Invalid manifest file in report package, missing "
                                                             "'documentInfo")
                            files = os.listdir(root)

                        if manifest is None:
                            raise kering.ValidationError("No manifest in file, invalid signed report package")

                        docInfo = manifest["documentInfo"]

                        if "signatures" not in docInfo:
                            raise kering.ValidationError("No signatures found in manifest file")

                        signatures = docInfo["signatures"]
                        signed = []
                        verfed = []
                        for signature in signatures:
                            try:
                                aid = signature["aid"]

                                # First check to ensure signature is from submitter, otherwise skip
                                if aid != stats.submitter:
                                    print(f"signature from {aid} does not match submitter {stats.submitter}")

                                # Now ensure we know who this AID is and that we have their key state
                                if aid not in self.hby.kevers:
                                    raise kering.ValidationError(f"signature from unknown AID {aid}")

                                dig = signature["digest"]
                                non_prefixed_dig = DigerBuilder.get_non_prefixed_digest(dig)
                                file_name = signature["file"]
                                fullpath = os.path.normpath(os.path.join(metaDir, file_name))
                                signed.append(os.path.basename(fullpath))


                                kever = self.hby.kevers[aid]
                                sigers = [Siger(qb64=sig) for sig in signature["sigs"]]
                                if len(sigers) == 0:
                                    raise kering.ValidationError(f"missing signatures on {file_name}")

                                for siger in sigers:
                                    siger.verfer = kever.verfers[siger.index]  # assign verfer
                                    if not siger.verfer.verify(siger.raw, bytes(non_prefixed_dig, "utf-8")):  # verify each sig
                                        raise kering.ValidationError(f"signature {siger.index} invalid for {file_name}")

                                verfed.append(os.path.basename(fullpath))

                            except KeyError as e:
                                raise kering.ValidationError(f"Invalid signature in manifest missing '{e.args[0]}'")
                            except OSError:
                                raise kering.ValidationError(f"signature element={signature} point to invalid file")

                            except Exception as e:
                                raise kering.ValidationError(f"{e}")


                        diff = set(files) - set(verfed)
                        if len(diff) == 0:
                            msg = f"All {len(files)} files in report package have been signed by " \
                                  f"submitter ({stats.submitter})."
                            self.filer.update(diger, ReportStatus.verified, msg)
                            print(msg)
                        else:
                            msg = f"{len(diff)} files from report package missing valid signed {diff}, {signed}"
                            self.filer.update(diger, ReportStatus.failed, msg)
                            print(msg)


            except (kering.ValidationError, zipfile.BadZipFile) as e:
                self.filer.update(diger, ReportStatus.failed, e.args[0])
                print(e.args[0])
