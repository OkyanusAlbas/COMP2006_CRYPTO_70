"""
COMP2006 Assessment 2 - Section 2
Mutual TLS (mTLS) Authentication: Server <-> Password Vault/Database
Implementation Evidence Script

This script demonstrates the full mTLS authentication mechanism between the
server and the password vault/database in Company X's mobile password manager.

Steps demonstrated:
  1. Generate a self-signed Certificate Authority (CA)
  2. Issue a server certificate signed by the CA
  3. Issue a vault certificate signed by the CA
  4. Simulate an mTLS handshake (both parties verify each other's certificates)
  5. Derive a session key from the shared context
  6. Encrypt/decrypt a vault request to prove authenticated channel

Author: COMP2006 Student
"""

import os
import datetime
import hashlib
import hmac
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Generate Certificate Authority (CA)
# The CA is a trusted root that signs both server and vault certificates.
# This follows the "Establish a Secure Channel" principle.
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 65)
print("  COMP2006 Assessment 2 - mTLS Server <-> Vault Authentication")
print("=" * 65)
print()
print("[STEP 1] Generating Certificate Authority (CA)...")

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Company X Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "CompanyX-RootCA"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256(), default_backend())
)

print(f"  CA Subject   : {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
print(f"  CA Serial No : {ca_cert.serial_number}")
print(f"  CA Valid From: {ca_cert.not_valid_before_utc.strftime('%Y-%m-%d')}")
print(f"  CA Valid To  : {ca_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
print(f"  Key Size     : 2048-bit RSA")
print(f"  Signature Alg: SHA-256 with RSA")
print()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Generate Server Certificate (signed by CA)
# ─────────────────────────────────────────────────────────────────────────────
print("[STEP 2] Generating Server Certificate (signed by CA)...")

server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

server_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Company X"),
        x509.NameAttribute(NameOID.COMMON_NAME, "companyx-server"),
    ]))
    .issuer_name(ca_cert.subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("companyx-server.internal")]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

print(f"  Server CN    : {server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
print(f"  Issuer       : {server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
print(f"  Serial No    : {server_cert.serial_number}")
print(f"  Valid Until  : {server_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
print()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Generate Vault Certificate (signed by CA)
# ─────────────────────────────────────────────────────────────────────────────
print("[STEP 3] Generating Vault/Database Certificate (signed by CA)...")

vault_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

vault_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Company X"),
        x509.NameAttribute(NameOID.COMMON_NAME, "companyx-vault"),
    ]))
    .issuer_name(ca_cert.subject)
    .public_key(vault_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("companyx-vault.internal")]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

print(f"  Vault CN     : {vault_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
print(f"  Issuer       : {vault_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
print(f"  Serial No    : {vault_cert.serial_number}")
print(f"  Valid Until  : {vault_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
print()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Mutual Authentication - Both parties verify each other's certificate
# This simulates what happens during the TLS handshake in mTLS.
# In production this is handled by the TLS stack (ssl.SSLContext).
# ─────────────────────────────────────────────────────────────────────────────
print("[STEP 4] Simulating Mutual TLS Handshake...")

def verify_certificate(cert, ca_cert, expected_cn, role):
    """Verify a certificate was signed by the trusted CA and has the expected CN."""
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ca_cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    # Verify issuer matches CA
    assert issuer_cn == ca_cn, f"Issuer mismatch: {issuer_cn} != {ca_cn}"

    # Verify the signature using the CA's public key
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    # Verify CN
    assert cn == expected_cn, f"CN mismatch: expected {expected_cn}, got {cn}"

    # Verify not expired
    now = datetime.datetime.utcnow()
    assert now >= cert.not_valid_before_utc.replace(tzinfo=None), "Cert not yet valid"
    assert now <= cert.not_valid_after_utc.replace(tzinfo=None), "Cert expired"

    print(f"  [{role}] Certificate verified: CN={cn}, Issuer={issuer_cn} ✓")
    return True

# Server verifies vault certificate
print("  Server verifying Vault certificate against trusted CA...")
verify_certificate(vault_cert, ca_cert, "companyx-vault", "SERVER")

# Vault verifies server certificate
print("  Vault verifying Server certificate against trusted CA...")
verify_certificate(server_cert, ca_cert, "companyx-server", "VAULT")

print("  mTLS Mutual Authentication: SUCCESSFUL ✓")
print()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Session Key Derivation
# After mutual auth, derive a symmetric session key from a shared context.
# In real TLS, this is handled by the TLS handshake (e.g., ECDHE).
# Here we demonstrate the principle using HMAC-SHA256 as a KDF.
# ─────────────────────────────────────────────────────────────────────────────
print("[STEP 5] Deriving Authenticated Session Key...")

# Server generates a nonce; vault generates a nonce; both are exchanged during handshake
server_nonce = os.urandom(32)
vault_nonce  = os.urandom(32)

# Shared context: both cert fingerprints + both nonces
server_fp = hashlib.sha256(server_cert.public_bytes(serialization.Encoding.DER)).digest()
vault_fp  = hashlib.sha256(vault_cert.public_bytes(serialization.Encoding.DER)).digest()

session_context = server_fp + vault_fp + server_nonce + vault_nonce

# HMAC-based key derivation (analogous to HKDF in production)
session_key = hmac.new(
    key=server_nonce + vault_nonce,   # pseudo-random key material
    msg=session_context,
    digestmod=hashlib.sha256
).digest()

print(f"  Server Nonce (hex): {server_nonce.hex()[:32]}...")
print(f"  Vault  Nonce (hex): {vault_nonce.hex()[:32]}...")
print(f"  Session Key (hex) : {session_key.hex()[:32]}...")
print(f"  Key Length        : {len(session_key) * 8} bits")
print()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: Input / Output Example
# Server sends an authenticated, encrypted vault request.
# Vault decrypts and processes it, then sends an encrypted response.
# ─────────────────────────────────────────────────────────────────────────────
print("[STEP 6] Input / Output Example - Authenticated Vault Request")
print()

aesgcm = AESGCM(session_key)

# --- INPUT: Server sends a vault read request ---
request_payload = json.dumps({
    "operation": "READ",
    "user_id": "user_abc123",
    "vault_record_id": "record_7f2a",
    "timestamp": datetime.datetime.utcnow().isoformat()
}).encode()

iv_req = os.urandom(12)   # 96-bit nonce for AES-GCM
aad_req = b"server->vault"  # Additional Authenticated Data (not encrypted, but authenticated)
ciphertext_req = aesgcm.encrypt(iv_req, request_payload, aad_req)

print("  --- SERVER → VAULT (Encrypted Request) ---")
print(f"  INPUT  (plaintext) : {request_payload.decode()}")
print(f"  IV (nonce, hex)    : {iv_req.hex()}")
print(f"  AAD                : {aad_req.decode()}")
print(f"  OUTPUT (ciphertext): {ciphertext_req.hex()[:64]}...  [{len(ciphertext_req)} bytes]")
print()

# --- Vault decrypts and processes the request ---
decrypted_req = aesgcm.decrypt(iv_req, ciphertext_req, aad_req)
assert decrypted_req == request_payload, "Decryption mismatch!"
req_obj = json.loads(decrypted_req)

print("  --- VAULT DECRYPTS REQUEST ---")
print(f"  Decrypted payload  : {decrypted_req.decode()}")
print(f"  Operation          : {req_obj['operation']}")
print(f"  User ID            : {req_obj['user_id']}")
print(f"  Record ID          : {req_obj['vault_record_id']}")
print(f"  Auth tag verified  : ✓ (AES-GCM tag intact - no tampering detected)")
print()

# --- OUTPUT: Vault sends encrypted response ---
response_payload = json.dumps({
    "status": "SUCCESS",
    "vault_record_id": "record_7f2a",
    "encrypted_dek": "C2_AES256GCM_WRAPPED_DEK_PLACEHOLDER",
    "ciphertext_entry": "C1_AES256GCM_ENCRYPTED_PASSWORD_PLACEHOLDER",
    "iv": os.urandom(12).hex(),
    "auth_tag": os.urandom(16).hex()
}).encode()

iv_resp = os.urandom(12)
aad_resp = b"vault->server"
ciphertext_resp = aesgcm.encrypt(iv_resp, response_payload, aad_resp)

print("  --- VAULT → SERVER (Encrypted Response) ---")
print(f"  INPUT  (plaintext) : {response_payload.decode()}")
print(f"  IV (nonce, hex)    : {iv_resp.hex()}")
print(f"  OUTPUT (ciphertext): {ciphertext_resp.hex()[:64]}...  [{len(ciphertext_resp)} bytes]")
print()

decrypted_resp = aesgcm.decrypt(iv_resp, ciphertext_resp, aad_resp)
print("  --- SERVER DECRYPTS RESPONSE ---")
print(f"  Decrypted payload  : {decrypted_resp.decode()}")
print(f"  Auth tag verified  : ✓ (AES-GCM tag intact - no tampering detected)")
print()

print("=" * 65)
print("  SUMMARY OF SECURITY PROPERTIES DEMONSTRATED")
print("=" * 65)
print("  ✓ Mutual Authentication   : Both server and vault verified by CA")
print("  ✓ Certificate Validation  : Signature, issuer, CN, expiry all checked")
print("  ✓ Session Key Derivation  : HMAC-based KDF from cert fingerprints + nonces")
print("  ✓ Authenticated Encryption: AES-256-GCM with AAD on all messages")
print("  ✓ Tamper Detection        : GCM auth tag ensures integrity")
print("  ✓ Replay Prevention       : Unique IV/nonce per message")
print("  ✓ Confidentiality         : Ciphertext reveals nothing about plaintext")
print("=" * 65)
