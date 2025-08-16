import os
from datetime import datetime, timedelta

def cleanup_logs():
    """Removes log entries older than ten years."""
    log_dir = 'log'
    os.makedirs(log_dir, exist_ok=True)

    ten_years_ago = datetime.now() - timedelta(days=730)
    
    for filename in os.listdir(log_dir):
        log_file = os.path.join(log_dir, filename)
        if os.path.isfile(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            filtered_lines = []
            for line in lines:
                try:
                    log_date_str = line.split(' - ')[0]
                    log_date = datetime.strptime(log_date_str, '%Y-%m-%d %H:%M:%S')
                    if log_date >= ten_years_ago:
                        filtered_lines.append(line)
                except (ValueError, IndexError):
                    # Keep lines that don't have a timestamp at the beginning,
                    # but are not older than ten years.
                    if datetime.now() - datetime.fromtimestamp(os.path.getmtime(log_file)) < timedelta(days=3650):
                        filtered_lines.append(line)

            with open(log_file, 'w') as f:
                f.writelines(filtered_lines)
