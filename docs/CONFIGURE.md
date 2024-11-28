### Added Configuration of ECR_Roles ###

1. Added ECR_Roles to verifier-config-public.json
"ECR_Roles": []

2. Loaded configuration for ECR_Roles in authorizing.py
if "ECR_Roles" not in data:
        raise kering.ConfigurationError(
            "invalid configuration, no ECR_Roles available to accept"
        )
    
    ecr_roles = data.get("ECR_Roles")
    if not None and not isinstance(leis, list):
        raise kering.ConfigurationError(
            "invalid configuration, invalid ECR_Roles in configuration"
        )

3. Then updated the Authorizer constructor to be able to handle set of ecr roles

authorizer = Authorizer(hby, vdb, reger, leis, ecr_roles)

def __init__(self, hby, vdb, reger, leis, ecr_roles):
        """
        Create a Authenticator capable of persistent processing of messages and performing
        web hook calls.

        Parameters:
            hby (Habery): identifier database environment
            vdb (VerifierBaser): communication escrow database environment
            reger (Reger): credential registry and database
            leis (list): list of str LEIs to accept credential presentations from
            ecr_roles (list): list of str ecr_roles to accept

        """
        self.hby = hby
        self.vdb = vdb
        self.reger = reger
        self.leis = leis
        self.ecr_roles = ecr_roles

4) Updated cred_filters() in the Authorizer class so that it doesn't check for the hardcoded EBA role

elif len(self.ecr_roles) > 0 and creder.attrib["engagementContextRole"] not in (self.ecr_roles):
                res = False, f"{creder.attrib["engagementContextRole"]} is not a valid submitter role"

5) Created 2 sample ECR_Role constants in common.py

ECR_ROLE1 = "EBA Data Submitter"
ECR_ROLE2 = "EBA Data Admin"

6) Modfied the testCf class in test-service.py to return a dictionary that contains both ECR_Role constants like it does for the LEIs

class testCf:
            @staticmethod
            def get():
                return dict(LEIs=[f"{LEI1}",f"{LEI2}"], ECR_Roles=[f"{ECR_ROLE1}",f"{ECR_ROLE2}"])
        authDoers = authorizing.setup(hby, vdb=vdb, reger=eccrdntler.rgy.reger, cf=testCf)