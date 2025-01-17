# Changelog

## [v0.0.4] - 2024-12-25

### Added

-   **Delegation Validation for QVI AIDs:**
    -   The Verifier now enforces **delegation validation** for QVI AIDs.
    -   The **QVI AID** must be **delegated by GLEIF** or **GLEIF External**, which must be set as the **Root of Trust**.
    -   If the QVI AID is not properly delegated, the Verifier will reject the request with:
        -   `401 Unauthorized: The QVI AID must be delegated.`
        -   `401 Unauthorized: The QVI AID must be delegated from the Root Of Trust.` (if delegated but not from the Root of Trust)
-   **Request and Response Logging Middleware:**
    
    -   Implemented middleware that logs detailed request and response information:
        
         -   **Request:** Logs timestamp, HTTP method, and endpoint path.
            
         -   **Response:** Logs timestamp, status code, and response body.
            
    -   This feature improves debugging and system observability.

### Summary

This update strengthens the security and trustworthiness of credential validation by requiring proper delegation of QVI AIDs from the Root of Trust (GLEIF or GLEIF External). Unauthorized or improperly delegated AIDs are now explicitly rejected.

## [v0.0.3] - 2024-12-18

### Added
- **Configurable Parameters**: The Verifier now supports the following configuration options:
  - `iurls`: OOBI URLs.
  - `durls`: Schema OOBI URLs.
  - `trustedLeis`: A list of trusted LE identifiers.
  - `allowedEcrRoles`: Roles permitted for ECR credential authorization.
  - `allowedOorRoles`: Roles permitted for OOR credential authorization.
  - `allowedSchemas`: A list of schemas allowed for authorization.

- **Environment Variables**:
  - `VERIFIER_ENV`: Sets the environment mode (e.g., `dev` or `production`). Defaults to `production`. In `production` mode, the `/root_of_trust` endpoint is disabled.
  - `VERIFY_ROOT_OF_TRUST`: Enables or disables root of trust validation logic. Defaults to `True`.
  - `KERI_BASER_MAP_SIZE`: Defines the maximum size of the LMDB database. Defaults to `104857600` (100 MB).
  - `FILER_CHUNK_SIZE`: Defines the size of the chunks used for file processing. This allows fine-tuning of memory usage when handling large files.

- **Automatic LMDB Cleanup**: 
  - Processed reports are now automatically removed from the LMDB database after verification, preventing database size issues.

### Fixed
- Resolved an issue where uploading multiple reports caused the Verifier to crash with the error:  
  `lmdb.MapFullError: mdb_put: MDB_MAP_FULL: Environment mapsize limit reached`.

### Example Command
To run the Verifier service, specify the configuration file as follows:
```bash
verifier server start --config-dir scripts --config-file verifier-config-public.json
```

### Summary

This release improves the usability and reliability of the Verifier service by introducing support for configurable parameters, environment variables, and automatic cleanup of processed reports in the LMDB database.
