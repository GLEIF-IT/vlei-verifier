# vlei-verifier
A service to verify cryptographic signatures and credentials created by AIDs and ACDCs using [KERI](https://keri.one).

## Architecture

### Verifier (this service)
The verifier uses [keripy](https://github.com/WebOfTRust/keripy) for verifying the requests:

To initiate this service, run the following commands from the root directory of this repository.
First create the database environment for the service with:

```
kli init --name vdb --nopasscode --config-dir scripts --config-file verifier-config-rootsid.json
```

This requires a running vLEI server and KERI witness network.

The service can be launched from the command-line with:

```
verifier server start --config-dir scripts --config-file verifier-config-rootsid.json
```

* Note there are multiple config files depending on the environment you are running in.

Or from docker-compose with:

```
docker-compose build --no-cache
docker-compose down
docker-compose up deps
```

### API

#### Initial Authentication:
Clients that wish to authenticate with this service should present a credential to the PUT `/presentations/{said}` API and
then poll the GET `/authorizations/{aid}` until they get something other than a 404 or until they time out.

#### Registering an AID as a Valid Report Submitter:
For an AID to be registered as a valid report submitter it must use the `/presentations/{said}` API to present a valid
vLEI ECR credential in the body of a PUT request with a content type of `application/json+cesr`.  The `said` in the URL
is the SAID of the credential being presented in the body.  This API will return a 202 response code to indicate that 
the credential presentation has been accepted but with no indication of the validity of the presentation.

#### Checking for Authorized AIDs:
To check whether an AID has already submitted a valid vLEI ECR credential, a client will use the `/authorizations/{aid}`
API where the `aid` must be the holder of an already successfully submitted vLEI ECR credential.   If the AID in the URL
has never submitted a credential, this API will return a 404.  If the AID has submitted an invalid credential, this API 
will return a 401.  If the AID has submitted a valid credential that is currently not revoked, this API will return a 200
with a body that contains the AID and the SAID of the credential.

## Peer projects
### Webapp
The web app (UI front-end) uses Signify/KERIA for selecting identifiers and credentials:

See: [reg-poc-webapp](https://github.com/GLEIF-IT/reg-poc-webapp)

### Server
The server provides the business layer and abstracts the underlying verification, but for the most part acts as a pass-through that provides the ability to:
* Log in using a vLEI ECR
* Upload signed files
* Check the status of an upload

See: [reg-poc-server](https://github.com/GLEIF-IT/reg-poc-server)

