import json
import logging
import os
from pathlib import Path
import re
import tempfile
import traceback
import zipfile
from dataclasses import asdict

import falcon
from keri import help
from hio.base import doing
from keri import kering
from keri.core import Siger

from verifier.core.basing import delete_upload_status, ReportStats, ReportStatus, save_upload_status, UploadStatus
from verifier.core.utils import DigerBuilder

# help.ogler.level = logging.getLevelName("DEBUG")
# logger = help.ogler.getLogger()
logger = help.ogler.getLogger("ReportVerifier", level=logging.DEBUG)

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

    def create(self, aid: str, dig: str, lei: str, filename: str, typ: str, stream):
        """ Create a new file upload with initial Accepted status.

        This method creates the report upload status object and queues it for report verification processing

        Parameters:
            aid (str): qb64 AID of uploader
            dig (str): qb64 digest of report content
            filename (str): filename reported from multipart/form filename field
            typ (str): content-type of file upload
            stream (File): file like stream object to load the report data from

        """
        self.vdb.delTopVal(db=self.vdb.imgs, top=dig.encode("utf-8"))
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
            raise kering.ValidationError(f"Report digest {dig} verification failed")

        with tempfile.TemporaryFile("w+b") as tf:
            tf.write(report)
            tf.seek(0)
            with tempfile.TemporaryDirectory() as tempDir:
                z = zipfile.ZipFile(tf)
                signatures, metaDir = FileProcessor.getSignaturesFromZip(zipFile=z, extractDir=tempDir)
                for signature in signatures:
                    try:
                        fullPath = FileProcessor.find_file(signature[FILE], tempDir)
                        
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
        save_upload_status(self.vdb, stats.status, diger.qb64)
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

    def getAccepted(self):
        """ Generator that yields SAID values for all reports currently in Accepted status

        """
        statuses = self.vdb.stts.get(keys=(ReportStatus.accepted,))
        if statuses:
            return statuses.saids
        else:
            return []

    def update(self, said, prevStatus, newStatus, msg=None):
        """ Set new report status for report identifier

        Parameters:
            diger (Diger): Diger object of digest for report
            status (str): new report status for report with digest dig
            msg (str): optional status message for report

        """
        if (stats := self.vdb.stats.get(keys=(said,))) is None:
            return False

        stats.status = newStatus
        if msg is not None:
            stats.message = msg

        delete_upload_status(self.vdb, prevStatus, said)
        save_upload_status(self.vdb, newStatus, said)
        self.vdb.stats.pin(keys=(said,), val=stats)


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

        acct = self.vdb.accts.get(keys=(aid,))
        if acct is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        stats = self.filer.get(dig)
        if stats is None:
            raise falcon.HTTPNotFound(description=f"report {dig} not found")

        sacct = self.vdb.accts.get(keys=(stats.submitter,))
        if (acct.lei != sacct.lei):
            raise falcon.HTTPNotFound(description=f"report {dig} LEI {sacct.lei} not available to this user LEI {acct.lei}")

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

        acct = self.vdb.accts.get(keys=(aid,))
        if acct is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        form = req.get_media()
        upload = False
        for part in form:
            if part.name == "upload":
                try:
                    logger.info(f"Upload passed AID checks, Creating filer  {part.filename}:\n "
                      f"\tType={part.content_type}\n")
                    self.filer.create(aid=aid, dig=dig, lei=acct.lei, filename=part.secure_filename, typ=part.content_type,
                                    stream=part.stream)
                    upload = True
                except Exception as e:
                    traceback.print_exc()
                    raise falcon.HTTPBadRequest(description=f"{str(e)}")

        if not upload:
            raise falcon.HTTPBadRequest(description=f"upload file content type must be multipart/form-data: {str(form)}")

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
        changes = []
        saids = self.filer.getAccepted()
        if len(saids) > 0:
            said = saids.pop()
            try:
                stats = self.vdb.stats.get(keys=(said,))
                logger.info(f"Processing {stats.filename}:\n "
                    f"\tType={stats.contentType}\n"
                    f"\tSize={stats.size}")
            
                with tempfile.TemporaryFile("w+b") as tf:
                    for chunk in self.filer.getData(said):
                        tf.write(chunk)

                    tf.seek(0)
                    with tempfile.TemporaryDirectory() as tempDir:
                        z = zipfile.ZipFile(tf)

                        signatures, metaDir = FileProcessor.getSignaturesFromZip(zipFile=z, extractDir=tempDir)
                        
                        files = []
                        simple_file_listing = FileProcessor.determine_file_listing_type(signatures)                        
                        if not simple_file_listing:
                            # complex file listing
                            reports_dir = FileProcessor.find_reports_directory(tempDir)
                            if reports_dir:
                                files = FileProcessor.list_files_in_directory(reports_dir)
                                logger.info(f"Files in reports directory: {files}")
                            else:
                                logger.info("No reports directory found.")
                                raise kering.ValidationError("No reports directory found during signature processing")
                        else:
                            #simple file listing
                            for signature in signatures:
                                files.append(signature[FILE])
                            
                        signed = []
                        verfed = []
                        for signature in signatures:
                            logger.info(f"processing signature {signature}")
                            try:
                                sigAid = signature[AID]
                                sigAcct = self.vdb.accts.get(keys=(sigAid,))
                                if sigAcct == None:
                                    raise kering.ValidationError("signature from AID that is not a known submitter")

                                subAcct = self.vdb.accts.get(keys=(stats.submitter,))
                                if subAcct == None:
                                    raise kering.ValidationError(f"submitter does not have a valid account")
                                
                                if sigAcct.lei != subAcct.lei:
                                    raise kering.ValidationError(f"submitter LEI {subAcct.lei} is not the same as signer LEI {sigAcct.lei}")

                                # Now ensure we know who this AID is and that we have their key state
                                if sigAid not in self.hby.kevers:
                                    raise kering.ValidationError(f"signature from unknown AID {sigAid}")
                                
                                if sigAid != stats.submitter:
                                    logger.info(f"signature from {sigAid} does not match submitter {stats.submitter}")

                                dig = signature[DIGEST]
                                non_prefixed_dig = DigerBuilder.get_non_prefixed_digest(dig)
                                file_name = signature[FILE]

                                fullPath = FileProcessor.find_file(file_name, tempDir)
                                
                                signed.append(os.path.basename(fullPath))

                                kever = self.hby.kevers[sigAid]
                                sigers = [Siger(qb64=sig) for sig in signature[SIGS]]
                                if len(sigers) == 0:
                                    raise kering.ValidationError(f"missing signatures on {file_name}")

                                for siger in sigers:
                                    siger.verfer = kever.verfers[siger.index]  # assign verfer
                                    if not siger.verfer.verify(siger.raw, bytes(non_prefixed_dig, "utf-8")):  # verify each sig
                                        raise kering.ValidationError(f"signature {siger.index} invalid for {file_name} or wasn't signed by {sigAid}")

                                verfed.append(os.path.basename(fullPath))

                            except KeyError as e:
                                raise kering.ValidationError(f"Invalid signature in manifest missing '{e.args[0]}'")
                            except OSError:
                                raise kering.ValidationError(f"signature element={signature} points to invalid file")

                            except Exception as e:
                                raise kering.ValidationError(f"{e}")


                        diff = set(files) - set(verfed)
                        if len(diff) == 0:
                            msg = f"All {len(files)} files in report package, submitted by {stats.submitter}, have been signed by " \
                                    f"known AIDs from the LEI {subAcct.lei}."
                            changes.append((said, ReportStatus.verified, msg))
                            logger.info(f"Added verified status message {msg}")
                        else:
                            msg = f"{len(diff)} files from report package missing valid signature {diff}"
                            changes.append((said, ReportStatus.failed, msg))
                            logger.info(f"Added failed status message {msg}")

            except (kering.ValidationError, zipfile.BadZipFile) as e:
                msg = e.args[0]
                changes.append((said, ReportStatus.failed, msg))
                logger.info(f"Added failed status message {msg}")
                
        for said, status, msg in changes:
            self.filer.update(said, ReportStatus.accepted, status, msg)
            logger.info(f"Changed {said} {status} status message {msg}")
                
class FileProcessor:
    
    @staticmethod
    def determine_file_listing_type(signatures) -> bool:
        """
        Determine the type of file listing in the signatures.

        Parameters:
            signatures (list): A list of signature objects.

        Returns:
            bool: True if the file listing is simple, else False.
        """
        for signature in signatures:
            if signature[FILE] == os.path.basename(signature[FILE]):
                return True
            else:
                return False
        return False

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
    def find_file(fileName: str, tempDir: str) -> str:
        fullPath = FileProcessor.find_file_in_dir(tempDir, fileName)
        if not fullPath:
            fullPath = FileProcessor.find_file_in_zip_files(tempDir, fileName)
        if not fullPath:
            raise kering.ValidationError(f"Didn't find {fileName} in {tempDir}, nor in zips")
        
        return fullPath
    
    @staticmethod
    def find_file_in_zip_files(zipsDir, file_name):
        """
        Check if the file exists inside a zip in zipsDir.
        If found inside a zip file, extract it.

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

        logger.info(f"File {file_name} not found in any zip files")
        return None
    
    @staticmethod
    def find_file_in_dir(dir, file_name) -> str:
        """
        Check if the file exists directly in dir or in a specified subdirectory.

        Parameters:
            dir (str): The parent directory to search for the file.
            file_name (str): The name of the file to search for, which may include a subdirectory.

        Returns:
            str: The full path to the file if found.

        Raises:
            kering.ValidationError: If the file is not found in dir or any subdirectories.
        """
        # Split the file_name into directory and file components
        file_dir, file_base_name = os.path.split(file_name)

        if(file_dir == '' and os.path.isfile(os.path.join(dir, file_name))):
            fullPath = os.path.normpath(os.path.join(dir, file_base_name))
            logger.info(f"File {fullPath} found in {dir}")
            return fullPath

        # Recursively search through the directory and subdirectories
        for root, dirs, files in os.walk(dir):
            # Check if the current root matches the specified file_dir
            if os.path.basename(root) == file_dir and file_base_name in files:
                fullPath = os.path.normpath(os.path.join(root, file_base_name))
                logger.info(f"File {fullPath} found in {root}")
                return fullPath

        logger.info(f"File {file_name} not found in {dir}")
        return None
            
    @staticmethod
    def list_files_in_zip(zip_file_path):
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
