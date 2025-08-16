import os
import sys
import base64
import json
import logging
from pathlib import Path

import requests
from dotenv import load_dotenv

# ---------- Logging ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.DEBUG),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("central-cert-upload")

# ENV
ENV_PATH = os.getenv("ENV_PATH") or ".env"
load_dotenv(ENV_PATH, override=True)
BASE_URL      = os.getenv("BASE_URL", "").rstrip("/")
ACCESS_TOKEN  = os.getenv("ACCESS_TOKEN", "")
CENTRAL_CID   = os.getenv("CENTRAL_CID", "")
CERT_PATH     = os.getenv("CERTIFICATE_PATH", "")
CERT_NAME     = os.getenv("CERTIFICATE_NAME", "")
CERT_PW       = os.getenv("CERTIFICATE_PASSPHRASE", "")
CERT_FORMAT   = os.getenv("CERTIFICATE_FORMAT", "")
CERT_TYPE     = os.getenv("CERTIFICATE_TYPE", "")


# Basic validation
missing = [k for k, v in {
    "BASE_URL": BASE_URL,
    "ACCESS_TOKEN": ACCESS_TOKEN,
    "CERTIFICATE_PATH": CERT_PATH,
    "CERTIFICATE_NAME": CERT_NAME,
    "CERTIFICATE_FORMAT": CERT_FORMAT,
    "CERTIFICATE_TYPE": CERT_TYPE,
}.items() if not v]
if missing:
    log.error(f"Missing required .env value(s): {', '.join(missing)}")
    sys.exit(1)

# Normalize Windows paths like C:\Users\name\file.pfx
CERT_PATH = str(Path(CERT_PATH).expanduser())

# ---------- Read & encode ----------
try:
    pfx_bytes = Path(CERT_PATH).read_bytes()
except FileNotFoundError:
    log.error(f"Certificate file not found: {CERT_PATH}")
    sys.exit(1)
except Exception as e:
    log.exception(f"Failed reading certificate: {e}")
    sys.exit(1)

cert_data_b64 = base64.b64encode(pfx_bytes).decode("ascii")

# Aruba Central expects the passphrase Base64-encoded, too.
# If you have an empty passphrase, leave CERTIFICATE_PASSPHRASE blank.
passphrase_b64 = base64.b64encode(CERT_PW.encode("utf-8")).decode("ascii") if CERT_PW else ""

payload = {
    "cert_name":   CERT_NAME,
    "cert_type":   CERT_TYPE,   # ENUM: SERVER_CERT, CA_CERT, CRL, INTERMEDIATE_CA, OCSP_RESPONDER_CERT, OCSP_SIGNER_CERT, PUBLIC_CERT
    "cert_format": CERT_FORMAT,        # ENUM: PKCS12, PEM, DER (Central expects upper-case)
    "cert_data":   cert_data_b64,   # Base64 of the PFX file
    "passphrase":  passphrase_b64,  # Base64 of the passphrase string (can be "")
}

headers = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "central-cert-uploader/1.1",
}

session = requests.Session()
session.headers.update(headers)
session.timeout = 45

def show_response(prefix: str, resp: requests.Response):
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        pass
    body_preview = body if len(body) <= 1200 else body[:1200] + "…"
    log.error(f"{prefix}: {resp.status_code} {resp.reason}\n{body_preview}\n")

def looks_like_bug_message(text: str) -> bool:
    # Aruba’s gateway has returned this exact message when the request was actually valid.
    return "Missing Required Query Parameter" in text and "invalid arguments" in text

def try_call(method: str, url: str) -> requests.Response:
    log.debug(f"{method} {url}")
    if method == "PUT":
        return session.put(url, data=json.dumps(payload))
    else:
        return session.post(url, data=json.dumps(payload))

def upload():
    log.info(f"Uploading certificate '{CERT_NAME}' to Aruba Central")
    log.debug(f"Cluster base URL: {BASE_URL}")
    if CENTRAL_CID:
        log.debug("CENTRAL_CID present (used only for POST fallback)")

    # 1) Preferred for non-MSP tenants
    url_put_non_msp = f"{BASE_URL}/configuration/v1/non_msp/certificate"
    resp = try_call("PUT", url_put_non_msp)
    if resp.ok:
        log.info("Success via PUT /configuration/v1/non_msp/certificate")
        return True
    show_response("PUT non_msp failed", resp)
    if resp.status_code != 400 and resp.status_code != 415:
        return False

    # 2) Legacy/alternate POST without CID
    url_post = f"{BASE_URL}/configuration/v1/certificates"
    log.info("Retrying via POST /configuration/v1/certificates ...")
    resp = try_call("POST", url_post)
    if resp.ok:
        log.info("Success via POST /configuration/v1/certificates")
        return True
    show_response("POST (no cid) failed", resp)

    # 3) POST with ?cid=<CENTRAL_CID> if we have it
    if CENTRAL_CID:
        url_post_cid = f"{url_post}?cid={CENTRAL_CID}"
        log.info("Retrying via POST with ?cid=<CENTRAL_CID> ...")
        resp = try_call("POST", url_post_cid)
        if resp.ok:
            log.info("Success via POST /configuration/v1/certificates?cid=...")
            return True
        show_response("POST (?cid) failed", resp)

    # If we hit the known buggy message, surface a helpful hint
    try:
        t = resp.text or ""
        if looks_like_bug_message(t):
            log.error(
                "Server returned the known APIGW message for certificate upload. "
                "This has been documented by Aruba and fixed in newer Central builds. "
                "If JSON/body is correct (as in this script), try again later, or upload once via the UI "
                "(Global → Maintain → Organization → Certificates) to confirm your cert is valid."
            )
    except Exception:
        pass

    return False

if __name__ == "__main__":
    ok = upload()
    sys.exit(0 if ok else 2)
