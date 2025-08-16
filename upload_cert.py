#!/usr/bin/env python3
# upload_cert.py — Upload (and optionally REPLACE) a certificate to Aruba Central.

import os
import sys
import json
import base64
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote
from typing import Optional, Dict, Any, List

import requests
from dotenv import load_dotenv

# integrate cleanup_logs (safe if module is missing) ----
try:
    from log_management import cleanup_logs
except Exception:
    def cleanup_logs():
        pass

# Logging
LOG_DIR = Path("log")
LOG_DIR.mkdir(parents=True, exist_ok=True)
try:
    cleanup_logs()  # trim before opening handlers
except Exception:
    pass

logger = logging.getLogger("central-cert")
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

fh = RotatingFileHandler(LOG_DIR / "upload_cert.log", maxBytes=2_000_000, backupCount=4, encoding="utf-8")
fh.setLevel(logging.DEBUG); fh.setFormatter(fmt); logger.addHandler(fh)

eh = RotatingFileHandler(LOG_DIR / "error.log", maxBytes=1_000_000, backupCount=4, encoding="utf-8")
eh.setLevel(logging.ERROR); eh.setFormatter(fmt); logger.addHandler(eh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))
ch.setFormatter(fmt); logger.addHandler(ch)

logging.getLogger("urllib3").setLevel(logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)

# checks
def ensure_apigw(url: str) -> str:
    try:
        p = urlparse(url)
        host = p.hostname or ""
        if host.startswith("app"):
            fixed = urlunparse(p._replace(netloc=host.replace("app", "apigw", 1)))
            logger.warning("BASE_URL pointed at UI host (%s); using API gateway: %s", host, fixed)
            return fixed
    except Exception:
        pass
    return url

def b64_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")

def b64_str(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def md5_hex(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def die(msg: str, code: int = 1):
    logger.error(msg); sys.exit(code)

def redact_headers(h: Dict[str, str]) -> Dict[str, str]:
    out = dict(h)
    if "Authorization" in out:
        out["Authorization"] = "Bearer ***REDACTED***"
    return out

def is_already_present(resp_text: str) -> bool:
    t = (resp_text or "").lower()
    return "already present" in t and "md5sum" in t

def looks_like_missing_qp(resp_text: str) -> bool:
    t = (resp_text or "").lower()
    return "missing required query parameter" in t and "invalid arguments" in t

def preview_text(resp: requests.Response) -> str:
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    return text if len(text) <= 2000 else text[:2000] + " …<truncated>…"

# token refresh
def load_cached_refresh_token(cache_path: Path, fallback: str) -> str:
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        return data.get("refresh_token") or fallback
    except Exception:
        return fallback

def refresh_access_token(base_url: str, client_id: str, client_secret: str,
                         refresh_token: str, cache_path: Path, timeout: int = 30) -> str:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    refresh_token = load_cached_refresh_token(cache_path, refresh_token)
    url = f"{base_url.rstrip('/')}/oauth2/token"
    params = {
        "client_id": client_id, "client_secret": client_secret,
        "grant_type": "refresh_token", "refresh_token": refresh_token,
    }
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    logger.debug("Refreshing token: POST %s with params %s", url, {**params, "client_secret": "***", "refresh_token": "***"})
    r = requests.post(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    cache = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", refresh_token),
        "expires_in": data.get("expires_in", 7200),
    }
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    logger.info("Obtained fresh access token (expires_in=%s)", cache["expires_in"])
    return cache["access_token"]

# Central API helpers
def send_json(session: requests.Session, method: str, url: str, body=None, timeout: int = 45) -> requests.Response:
    if body is None: 
        body = {}
    safe = dict(body)
    if "cert_data" in safe:
        safe["cert_data"] = "<omitted>"
    if "passphrase" in safe and safe["passphrase"]: 
        safe["passphrase"] = "<redacted>"
    logger.debug("%s %s", method, url)
    logger.debug("Headers: %s", redact_headers(session.headers))
    if body: 
        logger.debug("Body (truncated): %s", json.dumps(safe)[:2048])
    return session.request(method, url, data=json.dumps(body) if body else None, timeout=timeout)

def list_certs(session: requests.Session, base_url: str, timeout: int, central_cid: str,
               limit: int, max_total: int) -> List[Dict[str, Any]]:
    """
    Paginated list of certificates.
    Adds required ?limit param (and offset). Includes ?cid when CENTRAL_CID is set.
    NOTE: Many clusters cap limit at 20 — we clamp earlier in main().
    """
    base_endpoint = f"{base_url.rstrip('/')}/configuration/v1/certificates"
    all_rows: List[Dict[str, Any]] = []
    offset = 0

    while len(all_rows) < max_total:
        params = {"limit": limit, "offset": offset}
        if central_cid:
            params["cid"] = central_cid
        logger.debug("GET %s params=%s", base_endpoint, params)
        r = session.get(base_endpoint, params=params, headers={
            "Authorization": session.headers.get("Authorization", ""),
            "Accept": "application/json",
            "User-Agent": session.headers.get("User-Agent", "central-cert"),
        }, timeout=timeout)
        if not r.ok:
            logger.error("List certs failed: %s %s\n%s", r.status_code, r.reason, preview_text(r))
            break

        try:
            data = r.json()
            if isinstance(data, list):
                batch = data
            elif isinstance(data, dict):
                if "certificates" in data:
                    batch = data.get("certificates") or []
                elif "data" in data and isinstance(data["data"], list):
                    batch = data["data"]
                else:
                    batch = []
            else:
                batch = []
        except Exception:
            logger.error("Could not parse list certificates response.")
            break

        all_rows.extend(batch)
        logger.debug("Fetched %d rows (offset=%d, limit=%d, total=%d)",
                     len(batch), offset, limit, len(all_rows))
        if len(batch) < limit:
            break  # last page
        offset += limit

    return all_rows[:max_total]

def find_cert_by_name(certs: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    name_lower = name.lower()
    for c in certs:
        if str(c.get("cert_name", "")).lower() == name_lower:
            return c
    return None

def find_cert_by_md5(certs: List[Dict[str, Any]], md5_hex_str: str) -> Optional[Dict[str, Any]]:
    target = md5_hex_str.lower()
    for c in certs:
        md5v = str(c.get("md5sum", "")).lower()
        if md5v == target:
            return c
    return None

def delete_cert(session: requests.Session, base_url: str, cert_name: str, timeout: int = 45, central_cid: str = "") -> bool:
    # URL-encode cert_name to be safe (spaces, special chars)
    url = f"{base_url.rstrip('/')}/configuration/v1/certificates/{quote(cert_name, safe='')}"
    if central_cid:
        url += f"?cid={central_cid}"
    r = send_json(session, "DELETE", url, None, timeout)
    if r.ok:
        logger.info("Deleted certificate '%s'.", cert_name)
        return True
    logger.error("Delete failed for '%s': %s %s\n%s", cert_name, r.status_code, r.reason, preview_text(r))
    return False

# main
def main() -> int:
    load_dotenv(override=True)

    BASE_URL = ensure_apigw((os.getenv("BASE_URL") or "").rstrip("/"))
    if not BASE_URL:
        die("BASE_URL missing. Example: https://apigw-uswest4.central.arubanetworks.com")

    # token sources
    ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", "").strip()
    CLIENT_ID = os.getenv("CLIENT_ID", "").strip()
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", "").strip()
    REFRESH_TOKEN = os.getenv("REFRESH_TOKEN", "").strip()
    WRITE_TOKEN_CACHE = os.getenv("WRITE_TOKEN_CACHE", "1").lower() in ("1","true","yes")
    token_cache = LOG_DIR / "central_token.json"

    # cert config
    CERT_PATH = (os.getenv("CERTIFICATE_PATH") or "").strip().strip('"').strip("'")
    CERT_NAME = (os.getenv("CERTIFICATE_NAME") or "").strip()
    CERT_PW   = os.getenv("CERTIFICATE_PASSPHRASE", "")

    CENTRAL_CID = (os.getenv("CENTRAL_CID") or "").strip()
    FORCE_POST  = os.getenv("FORCE_POST", "false").lower() in ("1","true","yes")
    REPLACE     = os.getenv("REPLACE", "false").lower() in ("1","true","yes")
    TIMEOUT     = int(os.getenv("REQUEST_TIMEOUT", "45"))

    # list pagination knobs (cluster caps limit at 20 → clamp)
    raw_limit = int(os.getenv("CERT_LIST_LIMIT", "200"))
    CERT_LIST_LIMIT = min(max(raw_limit, 1), 20)
    if raw_limit != CERT_LIST_LIMIT:
        logger.warning("CERT_LIST_LIMIT %s exceeds cluster max; clamped to %s.", raw_limit, CERT_LIST_LIMIT)
    CERT_LIST_MAX   = int(os.getenv("CERT_LIST_MAX", "5000"))

    if not CERT_PATH or not CERT_NAME:
        die("CERTIFICATE_PATH and CERTIFICATE_NAME are required in .env")

    cert_file = Path(os.path.normpath(CERT_PATH))
    if not cert_file.exists():
        hint = ""
        if "\\" in CERT_PATH and not CERT_PATH.startswith("\\\\"):
            hint = " (Windows: escape backslashes or use forward slashes.)"
        die(f"Certificate file not found: {CERT_PATH}{hint}")

    # detect format from extension
    ext = cert_file.suffix.lower()
    if ext in (".pfx", ".p12"):
        cert_format = "PKCS12"
        if not CERT_PW:
            die("CERTIFICATE_PASSPHRASE is required for PKCS12 (.pfx/.p12).")
    elif ext in (".pem", ".crt", ".cer", ".key", ".chain"):
        cert_format = "PEM"
    else:
        cert_format = "PEM"
        logger.warning("Unknown extension '%s' — defaulting CERTIFICATE_FORMAT=PEM.", ext)

    # file data & passphrase
    try:
        cert_data_b64 = b64_file(cert_file)
    except Exception as e:
        die(f"Failed to read certificate file: {e}")
    passphrase_b64 = b64_str(CERT_PW) if CERT_PW else ""
    local_md5 = md5_hex(cert_file)
    logger.debug("Local file MD5: %s", local_md5)

    payload = {
        "cert_name":   CERT_NAME,
        "cert_type":   "SERVER_CERT",
        "cert_format": cert_format,   # PKCS12 / PEM
        "cert_data":   cert_data_b64, # base64 of file
        "passphrase":  passphrase_b64 # base64 of passphrase ("" if none)
    }

    # access token
    try:
        if CLIENT_ID and CLIENT_SECRET and REFRESH_TOKEN:
            access_token = refresh_access_token(BASE_URL, CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, token_cache, timeout=30)
        elif ACCESS_TOKEN:
            access_token = ACCESS_TOKEN
            logger.info("Using ACCESS_TOKEN from .env (no auto-refresh configured).")
            if WRITE_TOKEN_CACHE:
                try:
                    token_cache.write_text(json.dumps({"access_token": access_token}, indent=2), encoding="utf-8")
                    logger.debug("Wrote ACCESS_TOKEN to %s", token_cache)
                except Exception as e:
                    logger.warning("Could not write token cache (%s): %s", token_cache, e)
        else:
            die("Provide either ACCESS_TOKEN or (CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN) in .env.")
    except requests.HTTPError as e:
        body = ""
        try: 
            body = e.response.text[:1200]
        except Exception: 
            pass
        die(f"Failed to refresh access token: {e}\n{body}")

    session = requests.Session()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",  # only used on JSON POST/PUT/DELETE
        "User-Agent": "central-cert-uploader/1.7",
    }
    session.headers.update(headers)

    # endpoints
    put_non_msp     = f"{BASE_URL}/configuration/v1/non_msp/certificate"
    post_certs      = f"{BASE_URL}/configuration/v1/certificates"
    post_certs_cid  = f"{post_certs}?cid={CENTRAL_CID}" if CENTRAL_CID else None

    logger.info("Uploading certificate '%s' to Aruba Central (REPLACE=%s)", CERT_NAME, str(REPLACE).upper())

    # optional REPLACE-by-name preflight
    if REPLACE:
        logger.info("REPLACE is true — checking for existing certificate named '%s' ...", CERT_NAME)
        certs = list_certs(session, BASE_URL, TIMEOUT, CENTRAL_CID, CERT_LIST_LIMIT, CERT_LIST_MAX)
        existing = find_cert_by_name(certs, CERT_NAME)
        if existing:
            existing_md5 = str(existing.get("md5sum", "")).lower()
            logger.info("Found existing cert '%s' with MD5 %s", CERT_NAME, existing_md5 or "<unknown>")
            if existing_md5 and existing_md5 == local_md5.lower():
                logger.info("Existing cert already matches your file (same MD5). Nothing to replace.")
                print(json.dumps({"status": "already_present_same_md5", "cert_name": CERT_NAME, "md5": existing_md5}, indent=2))
                return 0
            # Different content — delete by name
            if delete_cert(session, BASE_URL, CERT_NAME, TIMEOUT, CENTRAL_CID):
                logger.info("Proceeding to upload fresh content for '%s' ...", CERT_NAME)
            else:
                die("Could not delete existing certificate (maybe in use). Aborting.", 2)

    # upload sequence
    def try_sequence() -> requests.Response:
        # 1) PUT non_msp (unless forced)
        if not FORCE_POST:
            r = send_json(session, "PUT", put_non_msp, payload, TIMEOUT)
            if r.ok: 
                return r
            body = preview_text(r)
            if r.status_code == 400 and is_already_present(body):
                return r
            if r.status_code not in (400, 404, 405, 415):
                return r  # unexpected -> return

        # 2) POST without cid
        r2 = send_json(session, "POST", post_certs, payload, TIMEOUT)
        if r2.ok or (r2.status_code == 400 and is_already_present(preview_text(r2))):
            return r2

        # 3) POST with cid
        if post_certs_cid:
            r3 = send_json(session, "POST", post_certs_cid, payload, TIMEOUT)
            return r3
        return r2

    try:
        resp = try_sequence()
        if resp.ok:
            logger.info("✅ Upload succeeded.")
            print(resp.text or "{}")
            return 0

        body = preview_text(resp)
        # Duplicate MD5 handling
        if resp.status_code == 400 and is_already_present(body):
            logger.warning("Central reports identical certificate bytes already exist (duplicate MD5). Searching list to identify the cert...")
            certs = list_certs(session, BASE_URL, TIMEOUT, CENTRAL_CID, CERT_LIST_LIMIT, CERT_LIST_MAX)
            hit = find_cert_by_md5(certs, local_md5)
            if hit:
                other_name = hit.get("cert_name") or "<unknown>"
                logger.warning("Identical certificate already stored as '%s'. Central blocks duplicate uploads by MD5.", other_name)
                print(json.dumps({
                    "status": "duplicate_md5_in_store",
                    "existing_cert_with_same_md5": other_name,
                    "desired_name": CERT_NAME,
                    "action": "Reuse existing cert or delete it first (risky) before uploading under a new name."
                }, indent=2))
                return 2
            else:
                logger.warning("Duplicate MD5 reported but list API did not include a match (possibly beyond pagination cap or permission-scoped).")
                print(json.dumps({"status": "duplicate_md5_but_not_listed"}, indent=2))
                return 2

        # Normal error dump
        logger.error("Upload failed: %s %s\n%s", resp.status_code, resp.reason, body)
        if looks_like_missing_qp(body):
            logger.error("Gateway reports missing query parameter; ensure CENTRAL_CID is correct and try again later if JSON is correct.")
        return 2

    finally:
        try:
            cleanup_logs()
        except Exception:
            pass

if __name__ == "__main__":
    sys.exit(main())
