# Update Aruba Central Certificate

This script uploads a certificate to Aruba Central.

## Installation

1. Clone the repository.
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
3. Rename .env.example to .env and fill in the required fields.
4. Run the script.
   ```
   python upload_cert.py
   ```

## Configuration

This project uses a `.env` file to manage environment variables. Create a file named `.env` in the root of the project and add the following variables:

```
BASE_URL="YOUR_ARUBA_CENTRAL_API_BASE_URL"
ACCESS_TOKEN="YOUR_ACCESS_TOKEN"
CERTIFICATE_PATH="PATH_TO_YOUR_CERTIFICATE_FILE"
CERTIFICATE_NAME="YOUR_CERTIFICATE_NAME"
CERTIFICATE_PASSPHRASE="YOUR_CERTIFICATE_PASSPHRASE"
CENTRAL_CID="YOUR_CENTRAL_CID"
```

## Usage

Run the script:
   ```
   python upload_cert.py
   ```

## Logging

Error logs are written to `log/error.log`. Entries older than ten years are discarded.
