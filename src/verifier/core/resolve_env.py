import os
from dataclasses import dataclass, field
from typing import List, Tuple

from keri.app import configing

from verifier.core.constants import Schema, EBA_DATA_ADMIN_ROLE, EBA_DATA_SUBMITTER_ROLE


@dataclass(frozen=True)
class VerifierEnvironment:
    configuration: configing.Configer = None
    trustedLeis: List[str] = field(default_factory=list)
    mode: str = "production"
    verifyRootOfTrust: bool = True
    authAllowedSchemas: List = field(default_factory=lambda: [])

    _instance: "VerifierEnvironment" = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(VerifierEnvironment, cls).__new__(cls)
            object.__setattr__(cls._instance, '_initialized', False)
        return cls._instance

    def __post_init__(self):
        if getattr(self, '_initialized', False):
            raise RuntimeError("VerifierEnvironment is a singleton and cannot be re-initialized.")
        object.__setattr__(self, '_initialized', True)

    @classmethod
    def initialize(cls, **kwargs):
        """
        Initialize the singleton instance with custom arguments. Can only be called once.
        """
        if cls._instance is None:
            instance = cls(**kwargs)
            cls._instance = instance
            return instance
        else:
            return cls._instance

    @classmethod
    def resolve_env(cls):
        """
        Get the existing instance of VerifierEnvironment. If not initialized, create with defaults.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
