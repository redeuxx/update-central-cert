# Update Aruba Central Certificate

This script uploads a certificate to Aruba Central.

## Installation

1. Clone the repository.
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
3. Rename `.env.example` to `.env` and fill in the required fields.


## Configuration

Create a file named `.env` in the root of the project and add the following variables:

```
# --- Cluster base (use apigw, not app) ---
BASE_URL=https://apigw-uswest4.central.arubanetworks.com

# Auth (choose ONE path)
# A) Fixed token (simpler, but it expires)
ACCESS_TOKEN=eyJhbGciOixxxxxxxxxxx

# B) OAuth auto-refresh. Uncomment lines below if you use this.
# CLIENT_ID=xxxxxxxxxxxx
# CLIENT_SECRET=yyyyyyyyyyyy
# REFRESH_TOKEN=zzzzzzzzzzzz

# Certificate
# Windows: wrap in quotes or use forward slashes
CERTIFICATE_PATH="C:/Users/you/certs/site.pfx"
CERTIFICATE_NAME=site_cert
CERTIFICATE_PASSPHRASE=123456

# Behavior
REPLACE=false            # true = replace by name via non_msp endpoint
CENTRAL_CID=             # optional (MSP/fallback POST only)
REQUEST_TIMEOUT=45
LOG_LEVEL=INFO           # console level; log files are always DEBUG
```

## Usage

Run the script:
   ```
   python upload_cert.py
   ```

## Logging

Error logs are written to `log/error.log`. Entries older than two years are discarded.
