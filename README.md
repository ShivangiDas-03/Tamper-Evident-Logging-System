# Tamper-Evident Audit Logging System

A lightweight, tamper-evident audit log system built in Python. It uses **SHA-256 hash chaining** — similar to a blockchain — to link every log entry to the one before it. Any modification, deletion, or reordering of entries is automatically detected during verification.

---

## How It Works

Each log entry stores:
- A sequence number and timestamp
- The event type, description, and acting user
- The hash of the **previous** entry (`prev_hash`)
- Its own hash (`entry_hash`), computed over all the above fields

During verification, the system recomputes every hash from scratch and checks that the chain is unbroken. If anyone tampers with an entry — even a single character — the hash mismatches and the tampering is flagged.

```
Entry #1  →  Entry #2  →  Entry #3  →  Entry #4
  hash1        hash2        hash3        hash4
    ↑            ↑            ↑
 prev_hash    prev_hash    prev_hash
```

---

## Features

- SHA-256 hash chaining for tamper detection
- Detects content modification, entry deletion, and reordering
- Simple append-only log format (newline-delimited JSON)
- Built-in tampering simulator for demonstration
- Interactive CLI menu

---

## Getting Started

**Requirements:** Python 3.7+ (no external dependencies)

```bash
# Clone the repository
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

# Run the application
python secure_logger.py
```

---

## Usage

The CLI presents a menu with the following options:

```
1. Add a log entry       — Record a new event
2. Display log           — Pretty-print all entries
3. Verify log integrity  — Check the full hash chain
4. Simulate tampering    — Demo: corrupt an entry and catch it
5. Exit
```

### Example — Adding entries and verifying

```
Choice: 1
Event type: LOGIN
Description: User admin logged in from 192.168.1.10
Username: admin
[+] Entry #1 added — LOGIN: User admin logged in from 192.168.1.10

Choice: 3

=======================================================
  Verifying 1 log entries...
=======================================================
[OK]   Entry #1 — LOGIN at 2026-04-02T14:33:14Z
=======================================================
  RESULT: All entries verified — log is INTACT.
=======================================================
```

### Example — Detecting tampering

```
Choice: 4
[*] Simulating tampering — modifying entry #2 directly in the file...
[*] Entry #2 has been secretly modified. Running verifier...

[FAIL] Entry #2 — CONTENT TAMPERED (hash mismatch)
  RESULT: Log integrity COMPROMISED — tampering detected!
```

---

## Log Format

Logs are stored as newline-delimited JSON in `secure_audit.log`:

```json
{
  "seq": 1,
  "timestamp": "2026-04-02T14:33:14.114683Z",
  "event_type": "LOGIN",
  "description": "User admin logged in from 192.168.1.10",
  "user": "admin",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "97e54e7a5ada209b8e899c12ff41c67659bb72adf41130968b8e68da702e7257"
}
```

The genesis entry (first entry) uses 64 zeros as its `prev_hash`.

---

## Project Structure

```
.
├── secure_logger.py      # Main application
├── secure_audit.log      # Sample audit log (demo data only)
├── .gitignore            # Excludes sensitive files
└── README.md             # This file
```

---

## Security Notes

- This system detects tampering but does **not** prevent it — physical/OS-level access controls are needed for that.
- For production use, consider storing hashes in a separate, write-protected location or a trusted third-party service.
- Never commit real database exports, credentials, or production log files to version control.

---

## License

MIT License — free to use and modify.
