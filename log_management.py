# log_management.py — Remove entries from log files

from datetime import datetime, timedelta
from pathlib import Path

def cleanup_logs():
    """
    Trim lines older than 2 years in files under ./log.
    Assumes log lines start with 'YYYY-MM-DD HH:MM:SS'.
    Keeps non-timestamped lines if the file mtime is within 2 years.
    """
    log_dir = Path("log")
    log_dir.mkdir(parents=True, exist_ok=True)

    # True 10-year window (3650 days)
    ten_years_ago = datetime.now() - timedelta(days=730)

    for p in log_dir.iterdir():
        if not p.is_file():
            continue

        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines(True)
        except Exception:
            # If we can't read the file, skip it
            continue

        filtered = []
        for line in lines:
            # Robust: try to parse first 19 chars as 'YYYY-MM-DD HH:MM:SS'
            ts_str = line[:19]
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                if ts >= ten_years_ago:
                    filtered.append(line)
            except ValueError:
                # If there's no parsable timestamp at start, keep the line
                # if file itself is not older than 10 years by mtime.
                try:
                    if (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)) < timedelta(days=3650):
                        filtered.append(line)
                except Exception:
                    # If stat fails, err on the side of keeping the line
                    filtered.append(line)

        try:
            p.write_text("".join(filtered), encoding="utf-8")
        except Exception:
            # If we can't write, ignore silently (don't crash callers)
            pass
