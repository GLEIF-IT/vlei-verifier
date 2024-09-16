import unittest
import zipfile
import json
import os
import tempfile

from verifier.core.reporting import DOC_INFO, FileProcessor

class TestFileProcessor(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.zip1_name = os.path.join(self.temp_dir.name, "test_reports.zip")
        self.create_test_zip(self.zip1_name)
    
    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()
    
    def create_test_zip(self, zip1_name):
        # Create a temporary directory structure
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create META-INF directory
            meta_inf_dir = os.path.join(temp_dir, "META-INF")
            os.makedirs(meta_inf_dir)
            
            # Create reports.json file with some JSON content
            meta_reports_json_path = os.path.join(meta_inf_dir, "reports.json")
            with open(meta_reports_json_path, "w") as f:
                json.dump({DOC_INFO: {"signatures": []}}, f)
            
            # Create reports directory
            reports_dir = os.path.join(temp_dir, "reports")
            os.makedirs(reports_dir)
            
            reports_json_path = os.path.join(reports_dir, "report.json")
            with open(reports_json_path, "w") as f:
                json.dump({"key": "value"}, f)
            
            # Create several files in the reports directory
            for i in range(3):
                file_path = os.path.join(reports_dir, f"report_{i}.txt")
                with open(file_path, "w") as f:
                    f.write(f"This is report {i}")
            
            # Create a zip file and add the directories and files
            with zipfile.ZipFile(zip1_name, "w") as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
    
    def test_file_processor(self):
        with zipfile.ZipFile(self.zip1_name, "r") as z:
            # Use the zip file in your tests
            with tempfile.TemporaryDirectory() as temp_dir:
                z.extractall(temp_dir)
                
                metaDir = os.path.join(temp_dir, "META-INF")
                repFromMeta = FileProcessor.find_file_in_dir(metaDir, "reports.json")
                assert repFromMeta == os.path.join(metaDir, "reports.json")
                repFromZip = FileProcessor.find_file_in_zip_files(os.path.dirname(self.zip1_name), "../reports/report.json")
                assert repFromZip == os.path.join(os.path.dirname(self.zip1_name), "reports", "report.json")
                repDir = FileProcessor.find_reports_directory(temp_dir)
                assert repDir == os.path.join(temp_dir, "reports")
                signatures, metaDir = FileProcessor.getSignaturesFromZip(zipFile=z, extractDir=temp_dir)
                assert len(signatures) == 0
                filesInDir = FileProcessor.list_files_in_directory(temp_dir)
                assert set(filesInDir) == {os.path.basename(metaDir),os.path.basename(repDir)}
                fileInZip = FileProcessor.list_files_in_zip(self.zip1_name)
                assert set(fileInZip) == {'META-INF/reports.json', 'reports/report_2.txt', 'reports/report_1.txt', 'reports/report_0.txt'}

if __name__ == "__main__":
    unittest.main()