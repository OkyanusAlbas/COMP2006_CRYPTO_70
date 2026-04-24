# ============================================================
# IMPORTS — standard library only (good: no external deps)
# ============================================================

import hmac
import hashlib
import os
import time
import secrets
import json
from datetime import datetime


# ============================================================
# SHARED SECRET
# ============================================================

SHARED_SECRET = b"CompanyX_VaultServerSharedKey_2025_Secure!"


# ============================================================
# HELPERS
# ============================================================

def generate_nonce(length: int = 32) -> str:
    return secrets.token_hex(length)


def compute_hmac(secret: bytes, nonce: str, timestamp: str, request_type: str) -> str:
    message = f"{nonce}{timestamp}{request_type}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def current_timestamp() -> str:
    return str(int(time.time()))


def is_timestamp_valid(timestamp: str, tolerance_seconds: int = 30) -> bool:
    try:
        return abs(int(time.time()) - int(timestamp)) <= tolerance_seconds
    except:
        return False


def now():
    return datetime.utcnow().isoformat()


# ============================================================
# VAULT
# ============================================================

class PasswordVault:

    def __init__(self):
        self._secret = SHARED_SECRET
        self._active_nonces = {}
        self._vault_store = {}
        self.audit_log = []

    def log_event(self, event, data=None):
        self.audit_log.append({
            "time": now(),
            "event": event,
            "data": data or {}
        })

    def issue_challenge(self):
        nonce = generate_nonce()
        self._active_nonces[nonce] = time.time()

        print(f"[VAULT] Issued nonce: {nonce[:20]}...")

        self.log_event("CHALLENGE_ISSUED", {"nonce": nonce})
        return {"nonce": nonce}

    def verify_and_grant(self, token):

        nonce = token.get("nonce")
        timestamp = token.get("timestamp")
        request_type = token.get("request_type")
        received = token.get("hmac_token")

        print("[VAULT] Verifying authentication...")

        # -------------------------
        # Nonce check
        # -------------------------
        if nonce not in self._active_nonces:
            print(" ✗ Invalid nonce")
            self.log_event("AUTH_DENIED", {"reason": "invalid_nonce"})
            return {"status": "denied"}

        del self._active_nonces[nonce]

        # -------------------------
        # Timestamp check
        # -------------------------
        if not is_timestamp_valid(timestamp):
            print(" ✗ Timestamp invalid")
            self.log_event("AUTH_DENIED", {"reason": "invalid_timestamp"})
            return {"status": "denied"}

        # -------------------------
        # HMAC check
        # -------------------------
        expected = compute_hmac(self._secret, nonce, timestamp, request_type)

        if not hmac.compare_digest(expected, received):
            print(" ✗ HMAC mismatch (attack detected)")
            self.log_event("AUTH_DENIED", {"reason": "hmac_mismatch"})
            return {"status": "denied"}

        print(" ✓ Authentication successful")
        self.log_event("AUTH_GRANTED", {"request_type": request_type})

        return {"status": "granted"}

    def store_record(self, user, site, record):
        if user not in self._vault_store:
            self._vault_store[user] = {}

        self._vault_store[user][site] = record
        print("[VAULT] Record stored")

        self.log_event("RECORD_STORED", {"user": user, "site": site})

        return {"status": "stored"}

    def retrieve_record(self, user, site):
        print("[VAULT] Record retrieved")

        self.log_event("RECORD_RETRIEVED", {"user": user, "site": site})

        return self._vault_store.get(user, {}).get(site)

    def print_audit_log(self):
        print("\n[VAULT] -- Audit Log --")
        for entry in self.audit_log:
            print(entry)


# ============================================================
# SERVER
# ============================================================

class PasswordServer:

    def __init__(self, vault):
        self._vault = vault
        self._secret = SHARED_SECRET

    def authenticate(self, request_type):

        print(f"\n[SERVER] Requesting access for: {request_type}")

        challenge = self._vault.issue_challenge()
        nonce = challenge["nonce"]

        timestamp = current_timestamp()
        hmac_token = compute_hmac(self._secret, nonce, timestamp, request_type)

        print(f"[SERVER] Generated HMAC: {hmac_token[:25]}...")

        token = {
            "nonce": nonce,
            "timestamp": timestamp,
            "request_type": request_type,
            "hmac_token": hmac_token,
        }

        result = self._vault.verify_and_grant(token)
        return result["status"] == "granted"


# ============================================================
# DEMO
# ============================================================

def demo():

    print("=" * 60)
    print(" HMAC Authentication Demo")
    print("=" * 60)

    vault = PasswordVault()
    server = PasswordServer(vault)

    # -------------------------
    # SUCCESS
    # -------------------------
    print("\n--- SUCCESSFUL AUTHENTICATION ---")

    if server.authenticate("STORE_RECORD"):
        vault.store_record("user1", "gmail.com", {"C1": "encrypted_data"})

    if server.authenticate("RETRIEVE_RECORD"):
        data = vault.retrieve_record("user1", "gmail.com")
        print("[SERVER] Retrieved:", json.dumps(data, indent=2))


    # -------------------------
    # ATTACK 1 — IMPERSONATION
    # -------------------------
    print("\n--- ATTACK: WRONG SECRET (IMPERSONATION) ---")

    challenge = vault.issue_challenge()

    fake_hmac = compute_hmac(
        b"wrong_secret",
        challenge["nonce"],
        current_timestamp(),
        "RETRIEVE_RECORD"
    )

    fake_token = {
        "nonce": challenge["nonce"],
        "timestamp": current_timestamp(),
        "request_type": "RETRIEVE_RECORD",
        "hmac_token": fake_hmac,
    }

    print("[ATTACKER] Sending forged token...")
    print(vault.verify_and_grant(fake_token))


    # -------------------------
    # ATTACK 2 — REPLAY
    # -------------------------
    print("\n--- ATTACK: REPLAY ---")

    challenge = vault.issue_challenge()
    nonce = challenge["nonce"]

    timestamp = current_timestamp()
    valid_hmac = compute_hmac(SHARED_SECRET, nonce, timestamp, "RETRIEVE_RECORD")

    token = {
        "nonce": nonce,
        "timestamp": timestamp,
        "request_type": "RETRIEVE_RECORD",
        "hmac_token": valid_hmac,
    }

    print("[SERVER] First use (valid):")
    print(vault.verify_and_grant(token))

    print("[ATTACKER] Reusing same token:")
    print(vault.verify_and_grant(token))


    # -------------------------
    # ATTACK 3 — OLD TIMESTAMP
    # -------------------------
    print("\n--- ATTACK: OLD TIMESTAMP ---")

    challenge = vault.issue_challenge()

    old_time = str(int(time.time()) - 1000)

    old_hmac = compute_hmac(
        SHARED_SECRET,
        challenge["nonce"],
        old_time,
        "RETRIEVE_RECORD"
    )

    old_token = {
        "nonce": challenge["nonce"],
        "timestamp": old_time,
        "request_type": "RETRIEVE_RECORD",
        "hmac_token": old_hmac,
    }

    print(vault.verify_and_grant(old_token))

    # -------------------------
    # AUDIT LOG OUTPUT
    # -------------------------
    vault.print_audit_log()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    demo()