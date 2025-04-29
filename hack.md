# vLEI Verifier Technical Documentation

## Overview
The vLEI Verifier is a service that verifies vLEI credentials. It implements a robust verification system that handles cryptographic verification, authorization, and state management.

## Core Components

### 1. Cryptographic Verification (`/presentations` Endpoint)

The verification process in the `/presentations` endpoint follows these steps:

1. **Request Validation**
   - Accepts CESR format
   - Requires a witness URL (mandatory in production)
   - Validates content type as `application/json+cesr`

2. **Credential Processing**
   ```python
   parsing.Parser().parse(ims=ims, kvy=self.hby.kvy, tvy=self.tvy, vry=self.vry)
   ```
   - Parses the incoming CESR message
   - Verifies cryptographic signatures
   - Validates credential structure

3. **State Management**
   - Credentials can be in states:
     - `CRED_CRYPT_INVALID`: Cryptographic verification failed
     - `CRED_CRYPT_VALID`: Cryptographic verification passed
     - `AUTH_PENDING`: Awaiting authorization
     - `AUTH_SUCCESS`: Fully authorized
     - `AUTH_REVOKED`: Credential has been revoked
     - `AUTH_FAIL`: Credential unauthorized

4. **Witness Integration**
   - Witness URL is stored with credential state
   - Used for revocation checks
   - Mandatory in production environment

### 2. Authorization System (`authorizing.py`)

The authorization system implements a multi-layer verification process:

1. **Credential Filters**
   ```python
   def cred_filters(self, creder) -> tuple[bool, str]:
   ```
   - Validates credential schema
   - Checks credential type
   - Verifies issuer authorization

2. **Chain Filters**
   ```python
   def chain_filters(self, creder) -> tuple[bool, str]:
   ```
   - Validates credential chain
   - Verifies issuer hierarchy
   - Checks credential dependencies

3. **Edge Filters**
   ```python
   def edge_filters(self, cred_type: str, edge, valid_edges: dict):
   ```
   - Validates credential edges
   - Verifies relationships between credentials

4. **Attribute Filters**
   ```python
   def attr_filters(self, cred, valid_attrs: dict):
   ```
   - Validates credential attributes
   - Verifies attribute values
   - Checks attribute constraints

### 3. State Management (`basing.py`)

The state management system provides persistent storage and state tracking:

1. **Credential States**
   ```python
   @dataclass
   class CredProcessState:
       said: Optional[str] = None
       aid: Optional[str] = None
       state: Optional[str] = None
       info: Optional[str] = None
       role: Optional[str] = None
       witness_url: Optional[str] = None
       date: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
   ```
   - Tracks credential processing state
   - Stores verification metadata
   - Maintains witness URL information

2. **State History**
   ```python
   @dataclass
   class StateHistory:
       aid: Optional[str] = None
       last_update: float = field(default_factory=lambda: time.time())
       state_history: List[CredProcessState | AidProcessState] = field(default_factory=lambda: [])
   ```
   - Maintains historical state changes
   - Tracks credential lifecycle
   - Supports audit trails

3. **Database Management**
   ```python
   class VerifierBaser(dbing.LMDBer):
   ```
   - Provides persistent storage
   - Manages credential states
   - Handles state transitions

## Usage Notes

1. **Production Requirements**
   - Witness URL is mandatory
   - All cryptographic verifications must pass
   - Authorization must be complete

2. **State Transitions**
   - States are immutable
   - History is preserved
   - Transitions are logged

3. **Error Handling**
   - Invalid credentials are rejected
   - Failed verifications are logged
   - State changes are tracked

## Implementation Details

### 1. Cryptographic Verification Flow

The verification process starts in the `PresentationResourceEndpoint.on_put` method:

**File:** `src/verifier/core/verifying.py`  
**Class:** `PresentationResourceEndpoint`  
**Method:** `on_put`  
**Lines:** ~280-400

The key steps are:
1. Parse the CESR message using KERI's parser
2. Check if the credential was found and valid
3. Update the credential state in the database
4. Store the witness URL for future revocation checks

### 2. Authorization Flow

The authorization process is handled by the `Authorizer` class:

**File:** `src/verifier/core/authorizing.py`  
**Class:** `Authorizer`  
**Method:** `processPresentations`  
**Lines:** ~70-150

The authorization process:
1. Iterates through credentials in the database
2. Applies credential filters to validate schema and type
3. Applies chain filters to validate issuer hierarchy
4. Updates credential state based on filter results

### 3. State Management Flow

State management is handled by the `VerifierBaser` class:

**File:** `src/verifier/core/basing.py`  
**Class:** `VerifierBaser`  
**Lines:** ~169-220

State transitions are managed through:
1. Pinning new states to the database
2. Updating state history
3. Tracking state changes over time

### 4. Revocation Checking Flow

The revocation checking process is handled by the `CredentialRevocationChecker` class:

**File:** `src/verifier/core/observing.py`  
**Class:** `CredentialRevocationChecker`  
**Method:** `_check_revocations`  
**Lines:** ~35-63

The revocation checking process:
1. Iterates through credentials in the database
2. Checks with the witness for credential status
3. Processes revocation information
4. Updates credential state if revoked 
