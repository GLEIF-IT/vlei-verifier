from keri import kering
from keri.core import MtrDex, coring


class DigerBuilder:
    @staticmethod
    def sha256(dig):
        try:
            non_pref_dig = DigerBuilder._get_non_prefixed_digest(dig)  # Temporarily remove prefix
            non_pref_dig = bytes.fromhex(non_pref_dig)
            diger = coring.Diger(raw=non_pref_dig, code=MtrDex.SHA2_256)
            return diger
        except Exception as e:
            raise e

    @staticmethod
    def _get_non_prefixed_digest(dig):
        try:
            prefix, digest = dig.split("_", 1)
        except ValueError:
            raise kering.ValidationError(f"Digest ({dig}) must start with prefix")
        except Exception:
            raise kering.ValidationError(f"Invalid digest {dig}")
        return digest
