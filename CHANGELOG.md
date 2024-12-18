# Changelog

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
verifier server start --config-dir scripts --config-file verifier-config-rootsid.json
```

### Summary

This release improves the usability and reliability of the Verifier service by introducing support for configurable parameters, environment variables, and automatic cleanup of processed reports in the LMDB database.