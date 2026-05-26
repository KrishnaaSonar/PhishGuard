# history.py
# PhishGuard - Scan History Manager
# Stores and retrieves past scan sessions in memory and to a local file

import json
import os
from datetime import datetime

# File to persist history between sessions
HISTORY_FILE = "results.txt"

# In-memory scan history list
_scan_history = []


def add_scan(email_preview: str, result: dict):
    """
    Adds a new scan result to the history.
    email_preview: First 80 characters of the email (truncated)
    result: Full result dictionary from detector.py
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summarize the triggered flags as a short string
    flags_summary = " | ".join(result.get("flags", {}).keys())
    if not flags_summary:
        flags_summary = "None"

    # Build history entry
    entry = {
        "session": len(_scan_history) + 1,
        "time": timestamp,
        "risk": result.get("risk_level", "UNKNOWN"),
        "score": result.get("score", 0),
        "flags": flags_summary,
        "preview": email_preview[:80] + ("..." if len(email_preview) > 80 else "")
    }

    _scan_history.append(entry)

    # Save to file as well (append mode)
    _save_to_file(entry)

    return entry


def get_history() -> list:
    """Returns the full in-memory scan history list."""
    return _scan_history


def clear_history():
    """Clears the in-memory history (does not delete the file)."""
    _scan_history.clear()


def _save_to_file(entry: dict):
    """Appends a scan entry to the results.txt file."""
    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n--- Session {entry['session']} ---\n")
            f.write(f"Time  : {entry['time']}\n")
            f.write(f"Risk  : {entry['risk']}\n")
            f.write(f"Score : {entry['score']}\n")
            f.write(f"Flags : {entry['flags']}\n")
            f.write(f"Email : {entry['preview']}\n")
    except Exception as e:
        print(f"[History] Failed to save to file: {e}")


def load_history_from_file():
    """
    Optional: Load history entries from file on app startup.
    This is a simple text-based loader for display only.
    """
    if not os.path.exists(HISTORY_FILE):
        return []

    loaded = []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        # Return raw content for display in the GUI
        return content
    except Exception as e:
        print(f"[History] Failed to load from file: {e}")
        return ""