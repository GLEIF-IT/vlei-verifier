# vlei-verifier

A service to verify cryptographic signatures and credentials created by AIDs and ACDCs using [KERI](https://keri.one).

## Architecture

### Verifier (this service)

The verifier uses [keripy](https://github.com/WebOfTRust/keripy) for verifying the requests.

This requires a running vLEI server and KERI witness network.

The service can be launched from the command-line with:

```
verifier server start --config-dir scripts --config-file verifier-config-public.json
```

* Note there are multiple config files depending on the environment you are running in.
  For example config files, see [here](https://github.com/GLEIF-IT/vlei-verifier/tree/main/scripts/keri/cf). You can use
  these config files as they are or configure one as needed.

Or from docker-compose with:

```
docker-compose build --no-cache
docker-compose down
docker-compose up deps
```

### API

#### Initial Authentication:

Clients that wish to authenticate with this service should present a credential to the PUT `/presentations/{said}` API
and
then poll the GET `/authorizations/{aid}` until they get something other than a 404 or until they time out.

#### Registering an AID as a Valid Report Submitter:

For an AID to be registered as a valid report submitter it must use the `/presentations/{said}` API to present a valid
vLEI ECR credential in the body of a PUT request with a content type of `application/json+cesr`. The `said` in the URL
is the SAID of the credential being presented in the body. This API will return a 202 response code to indicate that
the credential presentation has been accepted but with no indication of the validity of the presentation.

#### Checking for Authorized AIDs:

To check whether an AID has already submitted a valid vLEI ECR credential, a client will use the `/authorizations/{aid}`
API where the `aid` must be the holder of an already successfully submitted vLEI ECR credential. If the AID in the URL
has never submitted a credential, this API will return a 404. If the AID has submitted an invalid credential, this API
will return a 401. If the AID has submitted a valid credential that is currently not revoked, this API will return a 200
with a body that contains the AID and the SAID of the credential.

#### Root Of Trust verification:

By default, the verification of the Root Of Trust is disabled. In order to enable it set the env variable '
VERIFY_ROOT_OF_TRUST=True'.
The default root of trust is the GLEIF
external(https://github.com/WebOfTrust/WebOfTrust.github.io/blob/main/.well-known/keri/oobi/EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2/index.json)
If you are running Keria locally, you will need to add your own Root Of Trust. To do that you need to set the env
variable 'VERIFIER_ENV=development'. And then
send the POST request to the localhost:7676/root_of_trust/{AID-of-the-root-of-trust} with application/json+cesr format
data containing the CESR of the new Root Of Trust.

# Configuration:

## Running the Verifier Service

To run the Verifier service, you need to specify a configuration file by providing the following arguments:  
`--config-dir=scripts --config-file='your_config_file'`

---

## Configuration Files

The Verifier uses configuration files to define trusted LEIs, allowed roles and schemas. These files are located in:  
**`scripts/keri/cf`**

## Configurable Parameters

You can customize the service behavior using these configuration options:

- **`iurls`**: - OOBI URLs
- **`durls`**: - Schema OOBI URLs
- **`trustedLeis`**: A list of trusted LE identifiers.
- **`allowedSchemas`**: A list of schemas allowed for authorization.

### Default Configuration

The default configuration file, **`verifier-config-public.json`**, is located in the **`scripts/keri/cf`** directory. By
default:

- **`trustedLeis`** and **`allowedSchemas`** are empty.
    - This means Schema and Role checks will fail, and any credential authorization will be rejected.
- You must populate **`allowedSchemas`** or use a pre-configured file from *
  *`scripts/keri/cf/examples`**.
- You can also use **`verifier-config-test.json`** which has values set for the allowedSchemas.

### Example Configurations

The **`scripts/keri/cf/examples`** directory contains sample configuration files that you can use or modify as needed.
You can also create custom configuration files based on your requirements.

### Root of Trust Configuration

By default, the **Root of Trust** is set to the **Production Gleif External**:  
`EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS`

If your credentials are **not** chained to this root, follow these steps to configure your custom root of trust:

#### Setup Instructions

1. **Send a POST request** to:  
   `POST /root_of_trust/{aid}`

2. **Request Body Format:**  
   ```json
   {
     "oobi": "{oobi}",
     "vlei": "{vlei}"
   }
   ```
   - `aid`: Your custom **Root of Trust AID**  
   - `oobi`: Your **Root of Trust OOBI (Out-of-Band Introduction)**  
   - `vlei`: Your **Root of Trust Credential**  

#### Example (Using Production Gleif External)

1. **Retrieve OOBI and VLEI:**  
   Send a `GET` request to:  
   ```
   http://65.21.253.212:5623/oobi/EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS/controller
   ```

2. **Extract the following values:**  
   - **AID:**  
     ```
     EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS
     ```
   - **OOBI:**  
     ```
     http://65.21.253.212:5623/oobi/EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS/controller
     ```
   - **VLEI:**  
     *(Response body from the GET request)*

3. **Submit the POST request:**  
   ```bash
   curl -X POST http://your-verifier-host/root_of_trust/EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS \
   -H "Content-Type: application/json" \
   -d '{
         "oobi": "http://65.21.253.212:5623/oobi/EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS/controller",
         "vlei": "{VLEI_RESPONSE}"
       }'
   ```

####  Notes
- **Ensure** the AID, OOBI, and VLEI values are correct and trusted.  
- Custom roots of trust must be configured before processing related credentials.





---

## Example

```bash
verifier server start --config-dir=scripts --config-file='verifier-config-public.json'
```

## Verifier Endpoints:

### POST /presentations/{said}

    This endpoint performs cryptographic verification of the Credential(provided in a CESR format in request body).

### GET /authorizations/{aid}

    Using the AID from the request responds with the actual authorization status for the AID.

### GET /request/verify

    This endpoint performs Signed Headers verification

# Peer projects

### Webapp

The web app (UI front-end) uses Signify/KERIA for selecting identifiers and credentials:

See: [reg-pilot-webapp](https://github.com/GLEIF-IT/reg-pilot-webapp)

### Server

The server provides the business layer and abstracts the underlying verification, but for the most part acts as a
pass-through that provides the ability to:

* Log in using a vLEI ECR
* Upload signed files
* Check the status of an upload

See: [reg-pilot-server](https://github.com/GLEIF-IT/reg-poc-server)

