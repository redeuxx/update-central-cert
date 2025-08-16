# token_refresh.py — Refresh Aruba Central token

import os
import json
import time
import logging
import requests
from pathlib import Path

def _load_cached_refresh_token(cache_path: str, fallback: str) -> str:
    try:
        data = json.loads(Path(cache_path).read_text())
        return data.get("refresh_token") or fallback
    except Exception:
        return fallback

def get_access_token(base_url: str, client_id: str, client_secret: str,
                     refresh_token_env: str, cache_path: str = "log/central_token.json",
                     logger: logging.Logger | None = None, timeout: int = 30) -> str:
    """
    Refreshes and returns a fresh access token.
    - Reads latest refresh_token from cache (if present), else uses env value.
    - Writes the new access/refresh token pair back to cache.
    """
    log = logger or logging.getLogger("token-refresh")
    Path(cache_path).parent.mkdir(parents=True, exist_ok=True)

    # Always prefer the most recent refresh_token we saved
    refresh_token = _load_cached_refresh_token(cache_path, refresh_token_env)

    url = f"{base_url.rstrip('/')}/oauth2/token"
    # Aruba’s Refresh API takes params as query string; Content-Type: application/json
    # grant_type=refresh_token + client_id + client_secret + refresh_token
    # Response includes: access_token, refresh_token, expires_in (~7200 seconds)
    params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    r = requests.post(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    data = r.json()

    # Persist the newest tokens; future runs will use the updated refresh_token
    cache = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", refresh_token),
        "fetched_at": int(time.time()),
        "expires_in": data.get("expires_in", 7200),
    }
    Path(cache_path).write_text(json.dumps(cache, indent=2))
    log.debug("Refreshed Central token; expires_in=%s", cache["expires_in"])
    return cache["access_token"]