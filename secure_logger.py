"""
Tamper-Evident Logging System
==============================
Uses SHA-256 hash chaining to link each log entry to the previous one.
Any modification, deletion, or reordering of entries breaks the chain
and is caught during verification.
"""

import hashlib
import json
import os
import time
from datetime import datetime


LOG_FILE = "secure_audit.log"


def compute_hash(entry: dict) -> str:
    """Compute SHA-256 hash of a log entry (excluding the entry's own hash field)."""
    entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
    serialized = json.dumps(entry_copy, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def load_log() -> list:
    """Load existing log entries from file. Returns empty list if file doesn't exist."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    entries = []
    for line in lines:
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def save_entry(entry: dict):
    """Append a single entry to the log file."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def add_log_entry(event_type: str, description: str, user: str = "system"):
    """
    Add a new log entry to the chain.
    Each entry stores:
      - sequence number
      - timestamp
      - event type and description
      - user who triggered the event
      - hash of the previous entry (prev_hash)
      - hash of the current entry (entry_hash)
    """
    entries = load_log()

    if len(entries) == 0:
        prev_hash = "0" * 64   # genesis block — no previous entry
        seq = 1
    else:
        last = entries[-1]
        prev_hash = last["entry_hash"]
        seq = last["seq"] + 1

    entry = {
        "seq": seq,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "description": description,
        "user": user,
        "prev_hash": prev_hash,
    }

    entry["entry_hash"] = compute_hash(entry)
    save_entry(entry)
    print(f"[+] Entry #{seq} added — {event_type}: {description}")
    return entry


def verify_log() -> bool:
    """
    Walk through every log entry and verify:
      1. The entry's stored hash matches a freshly computed hash (detects modification).
      2. The entry's prev_hash matches the previous entry's hash (detects deletion/reordering).
    """
    entries = load_log()

    if not entries:
        print("[!] Log is empty — nothing to verify.")
        return True

    print(f"\n{'='*55}")
    print(f"  Verifying {len(entries)} log entries...")
    print(f"{'='*55}")

    tampered = False

    for i, entry in enumerate(entries):
        seq = entry.get("seq", i + 1)

        # --- Check 1: recompute hash and compare ---
        recomputed = compute_hash(entry)
        if recomputed != entry.get("entry_hash"):
            print(f"[FAIL] Entry #{seq} — CONTENT TAMPERED (hash mismatch)")
            tampered = True
            continue

        # --- Check 2: chain linkage ---
        if i == 0:
            expected_prev = "0" * 64
        else:
            expected_prev = entries[i - 1]["entry_hash"]

        if entry.get("prev_hash") != expected_prev:
            print(f"[FAIL] Entry #{seq} — CHAIN BROKEN (prev_hash mismatch, entry deleted or reordered)")
            tampered = True
            continue

        print(f"[OK]   Entry #{seq} — {entry['event_type']} at {entry['timestamp']}")

    print(f"{'='*55}")
    if tampered:
        print("  RESULT: Log integrity COMPROMISED — tampering detected!")
    else:
        print("  RESULT: All entries verified — log is INTACT.")
    print(f"{'='*55}\n")

    return not tampered


def display_log():
    """Pretty-print the current log to the console."""
    entries = load_log()
    if not entries:
        print("[!] No log entries found.")
        return

    print(f"\n{'='*55}")
    print(f"  Audit Log — {len(entries)} entries")
    print(f"{'='*55}")
    for e in entries:
        print(f"\n  Seq       : {e['seq']}")
        print(f"  Time      : {e['timestamp']}")
        print(f"  Event     : {e['event_type']}")
        print(f"  Desc      : {e['description']}")
        print(f"  User      : {e['user']}")
        print(f"  Prev Hash : {e['prev_hash'][:20]}...")
        print(f"  This Hash : {e['entry_hash'][:20]}...")
    print(f"\n{'='*55}\n")


def simulate_tampering():
    """
    Demonstration: manually corrupt entry #2 in the log file
    to show the verifier catches it.
    """
    entries = load_log()
    if len(entries) < 2:
        print("[!] Need at least 2 entries to simulate tampering.")
        return

    print("\n[*] Simulating tampering — modifying entry #2 directly in the file...")
    entries[1]["description"] = "TAMPERED DESCRIPTION"

    with open(LOG_FILE, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    print("[*] Entry #2 has been secretly modified. Running verifier...\n")


# ─── CLI Menu ────────────────────────────────────────────────────────────────

def menu():
    while True:
        print("\n  Tamper-Evident Log System")
        print("  --------------------------")
        print("  1. Add a log entry")
        print("  2. Display log")
        print("  3. Verify log integrity")
        print("  4. Simulate tampering (demo)")
        print("  5. Exit")
        choice = input("\n  Choice: ").strip()

        if choice == "1":
            etype = input("  Event type (e.g. LOGIN, TRANSACTION): ").strip()
            desc  = input("  Description: ").strip()
            user  = input("  Username: ").strip() or "anonymous"
            add_log_entry(etype, desc, user)

        elif choice == "2":
            display_log()

        elif choice == "3":
            verify_log()

        elif choice == "4":
            simulate_tampering()
            verify_log()

        elif choice == "5":
            print("  Bye.")
            break
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    menu()
