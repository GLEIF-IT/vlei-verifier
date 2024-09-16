import json
import logging
import os
from pathlib import Path
import re
import tempfile
import zipfile
from collections import namedtuple
from dataclasses import asdict
from fileinput import filename
from hashlib import sha256

import falcon
from keri import help
from hio.base import doing
from keri import kering
from keri.core import coring, Siger, MtrDex

from verifier.core.basing import ReportStats
from verifier.core.utils import DigerBuilder

# help.ogler.level = logging.getLevelName("DEBUG")
# logger = help.ogler.getLogger()
logger = help.ogler.getLogger("ReportVerifier", level=logging.DEBUG)

# Report Statuses.
Reportage = namedtuple("Reportage", "accepted verified failed")

# Referencable report status enumeration
ReportStatus = Reportage(accepted="accepted", verified="verified", failed="failed")

AID = "aid"
DIGEST = "digest"
DOC_INFO = "documentInfo"
FILE = "file"
META_INF_DIR = "META-INF"
REPORTS_JSON = "reports.json"
SIGNATURES = "signatures"
SIGS = "sigs"


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
        logger.info("Report status filer initialized")

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
                signatures, metaDir = FileProcessor.getSignaturesFromZip(zipFile=z, extractDir=tempdirname)
                for signature in signatures:
                    try:
                        # Use the new function to find the file
                        fullPath = FileProcessor.find_file_in_dir(metaDir, signature[FILE])
                        if(not fullPath):
                            fullPath = FileProcessor.find_file_in_zip_files(tempdirname, signature[FILE])
                        
                        if not fullPath:
                            raise kering.ValidationError(f"Didn't find {signature[FILE]} above {metaDir} or in zips")
                        
                        f = open(fullPath, 'rb')
                        file_object = f.read()
                        f.close()

                        dig = signature[DIGEST]

                        tmp_diger = DigerBuilder.sha256(dig)
                        if not tmp_diger.verify(file_object):
                            raise kering.ValidationError(f"Invalid digest for file {fullPath}")
                        logger.info(f"File {fullPath} w/ digest {dig} has valid digest")
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
                logger.info(f"Processing {stats.filename}:\n "
                      f"\tType={stats.contentType}\n"
                      f"\tSize={stats.size}")
                
                with tempfile.TemporaryFile("w+b") as tf:
                    for chunk in self.filer.getData(diger.qb64):
                        tf.write(chunk)

                    tf.seek(0)
                    with tempfile.TemporaryDirectory() as tempdirname:
                        z = zipfile.ZipFile(tf)

                        signatures, metaDir = FileProcessor.getSignaturesFromZip(zipFile=z, extractDir=tempdirname)
                        
                        files = []
                        reports_dir = FileProcessor.find_reports_directory(tempdirname)
                        if reports_dir:
                            files = FileProcessor.list_files_in_directory(reports_dir)
                            logger.info(f"Files in reports directory: {files}")
                        else:
                            logger.info("No reports directory found.")
                            raise kering.ValidationError("No reports directory found during signature processing")
                            
                        signed = []
                        verfed = []

                        for signature in signatures:
                            logger.info(f"processing signature {signature}")
                            try:
                                aid = signature[AID]

                                # First check to ensure signature is from submitter, otherwise skip
                                if aid != stats.submitter:
                                    logger.info(f"signature from {aid} does not match submitter {stats.submitter}")

                                # Now ensure we know who this AID is and that we have their key state
                                if aid not in self.hby.kevers:
                                    raise kering.ValidationError(f"signature from unknown AID {aid}")

                                dig = signature[DIGEST]
                                non_prefixed_dig = DigerBuilder.get_non_prefixed_digest(dig)
                                file_name = signature[FILE]

                                fullPath = FileProcessor.find_file_in_dir(metaDir, file_name)
                                if not fullPath:
                                    fullPath = FileProcessor.find_file_in_zip_files(tempdirname, signature[FILE])
                                if not fullPath:
                                    raise kering.ValidationError(f"Didn't find {signature[FILE]} above {metaDir} or in zips")
                                
                                signed.append(os.path.basename(fullPath))

                                kever = self.hby.kevers[aid]
                                sigers = [Siger(qb64=sig) for sig in signature[SIGS]]
                                if len(sigers) == 0:
                                    raise kering.ValidationError(f"missing signatures on {file_name}")

                                for siger in sigers:
                                    siger.verfer = kever.verfers[siger.index]  # assign verfer
                                    if not siger.verfer.verify(siger.raw, bytes(non_prefixed_dig, "utf-8")):  # verify each sig
                                        raise kering.ValidationError(f"signature {siger.index} invalid for {file_name}")

                                verfed.append(os.path.basename(fullPath))

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
                            logger.info(msg)
                        else:
                            msg = f"{len(diff)} files from report package missing valid signature {diff}"
                            self.filer.update(diger, ReportStatus.failed, msg)
                            logger.info(msg)


            except (kering.ValidationError, zipfile.BadZipFile) as e:
                self.filer.update(diger, ReportStatus.failed, e.args[0])
                logger.info(e.args[0])
                
class FileProcessor:

    @staticmethod
    def find_reports_directory(start_dir):
        """
        Recursively find the 'reports' directory starting from start_dir.

        Parameters:
            start_dir (str): The directory to start the search from.

        Returns:
            str: The path to the 'reports' directory if found, else None.
        """
        for root, dirs, files in os.walk(start_dir):
            if 'reports' in dirs:
                return os.path.join(root, 'reports')
            
        # If not found, search within zip files in start_dir
        for root, dirs, files in os.walk(start_dir):
            for file in files:
                if file.endswith('.zip'):
                    zip_path = os.path.join(root, file)
                    with zipfile.ZipFile(zip_path, 'r') as zip_file:
                        for zip_info in zip_file.infolist():
                            if zip_info.is_dir() and Path(zip_info.filename).name == 'reports':
                                zip_file.extractall(root)
                                return FileProcessor.find_reports_directory(root)
        return None
    
    @staticmethod
    def find_file_in_zip_files(zipsDir, file_name):
        """
        Check if the file exists inside a zip file in metaDir.
        If found inside a zip file, extract it to metaDir.

        Parameters:
            zipsDir (str): The directory to search for the file.
            file_name (str): The name of the file to search for.

        Returns:
            str: The full path to the file if found.

        Raises:
            kering.ValidationError: If the file is not found in metaDir or any zip files.
        """
        logger.info(f"Finding file {file_name} in zip files...")
        
        # Extract the base file name and directory from the file_name
        base_file_name = os.path.basename(file_name)
        file_dir = Path(file_name).parent.name

        # Create a regular expression pattern to match the target file path
        target_pattern = re.compile(rf'(.*/)?{re.escape(file_dir)}/?{re.escape(base_file_name)}')

        zip_files = [f for f in os.listdir(zipsDir) if f.endswith('.zip')]
        file_found = False
        for zip_file in zip_files:
            with zipfile.ZipFile(os.path.join(zipsDir, zip_file), 'r') as z:
                zip_contents = z.namelist()
                for zip_content in zip_contents:
                    if target_pattern.match(zip_content):
                        z.extract(zip_content, zipsDir)
                        repPath = os.path.join(zipsDir, zip_content)
                        if os.path.exists(repPath):
                            logger.info(f"File {file_name} found in zip, extracted to {repPath}")
                            file_found = True
                            return repPath

        if not file_found:
            raise kering.ValidationError(f"File {file_name} not found in any zip files")

        return None
    
    @staticmethod
    def find_file_in_dir(dir, file_name):
        """
        Check if the file exists directly in metaDir or inside a zip file in metaDir.
        If found inside a zip file, extract it to metaDir.

        Parameters:
            metaDir (str): The directory to search for the file.
            file_name (str): The name of the file to search for.

        Returns:
            str: The full path to the file if found.

        Raises:
            kering.ValidationError: If the file is not found in metaDir or any zip files.
        """
        fullPath = os.path.normpath(os.path.join(dir, file_name))

        # Check if the file exists directly in metaDir
        if os.path.exists(fullPath):
            logger.info(f"File {fullPath} found in {dir}")
            return fullPath
        else:
            logger.info(f"File {fullPath} not found in {dir}")
            return None
        
    @staticmethod
    def list_files_in_zip_excluding_report_json(zip_file_path):
        """
        List all files in a zip file excluding 'report.json' files.

        Parameters:
            zip_file_path (str): The path to the zip file.

        Returns:
            list: A list of file names in the zip file excluding 'report.json' files.
        """
        if not os.path.exists(zip_file_path):
            raise FileNotFoundError(f"The zip file {zip_file_path} does not exist.")

        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            all_files = zip_file.namelist()
            filtered_files = [file for file in all_files if os.path.basename(file) != 'report.json']
        
        return filtered_files
    
    @staticmethod
    def list_files_excluding_report_json(directory_path):
        """
        List all files in a directory excluding 'report.json' files.

        Parameters:
            directory_path (str): The path to the directory.

        Returns:
            list: A list of file names in the directory excluding 'report.json' files.
        """
        if not os.path.isdir(directory_path):
            raise NotADirectoryError(f"The path {directory_path} is not a directory.")

        all_files = os.listdir(directory_path)
        filtered_files = [file for file in all_files if file != 'report.json']
        
        return filtered_files
    
    @staticmethod
    def list_files_in_directory(directory_path):
        """
        List all files in a directory excluding 'report.json' files.

        Parameters:
            directory_path (str): The path to the directory.

        Returns:
            list: A list of file names in the directory excluding 'report.json' files.
        """
        if not os.path.isdir(directory_path):
            raise NotADirectoryError(f"The path {directory_path} is not a directory.")

        all_files = os.listdir(directory_path)
        filtered_files = [file for file in all_files if file != 'report.json']
        
        return filtered_files
    
    @staticmethod    
    def getSignaturesFromZip(zipFile: zipfile.ZipFile, extractDir):

        zipFile.extractall(path=extractDir)
        manifest = None
        metaDir = None
        for root, dirs, _ in os.walk(extractDir):
            if "META-INF" not in dirs:
                continue
            metaDir = os.path.join(root, META_INF_DIR)
            name = os.path.join(root, META_INF_DIR, REPORTS_JSON)
            if not os.path.exists(name):
                continue
            f = open(name, 'r')
            manifest = json.load(f)
            if DOC_INFO not in manifest:
                raise kering.ValidationError("Invalid manifest file in report package, missing "
                                                f"{DOC_INFO}")
        if manifest is None:
            raise kering.ValidationError("No manifest in file, invalid signed report package")

        docInfo = manifest[DOC_INFO]
        if SIGNATURES not in docInfo:
            raise kering.ValidationError("No signatures found in manifest file")

        signatures = docInfo[SIGNATURES]
        
        return signatures, metaDir
