"""
Cryptographic Engine Tests.
Verifies AES-256-GCM authenticated encryption, unique nonces,
tampering detection, tag verification, and key rotation.
"""

import json
import base64
import pytest
from Crypto.Random import get_random_bytes
from modules.crypto_engine import AESGCMCryptoEngine, DecryptionError, KeyRotationError

def test_aes_gcm_encryption_structure():
    engine = AESGCMCryptoEngine()
    plaintext = "Patient confidential diagnosis note"
    encrypted = engine.encrypt_text(plaintext)
    
    assert isinstance(encrypted, str)
    # Decode envelope
    raw_json = base64.b64decode(encrypted.encode('utf-8')).decode('utf-8')
    envelope = json.loads(raw_json)
    
    assert envelope["v"] == 1
    assert "n" in envelope
    assert "t" in envelope
    assert "c" in envelope
    # Verify nonce is 12 bytes
    nonce = base64.b64decode(envelope["n"])
    assert len(nonce) == 12
    # Verify tag is 16 bytes (128 bits)
    tag = base64.b64decode(envelope["t"])
    assert len(tag) == 16


def test_unique_nonce_per_operation():
    engine = AESGCMCryptoEngine()
    plaintext = "Identical clinical diagnosis"
    
    enc1 = engine.encrypt_text(plaintext)
    enc2 = engine.encrypt_text(plaintext)
    
    assert enc1 != enc2, "Identical plaintext must produce different ciphertexts due to unique nonces"
    
    env1 = json.loads(base64.b64decode(enc1).decode('utf-8'))
    env2 = json.loads(base64.b64decode(enc2).decode('utf-8'))
    assert env1["n"] != env2["n"], "Nonces must be unique per encryption operation"


def test_authenticated_decryption_roundtrip():
    engine = AESGCMCryptoEngine()
    original_text = "Detailed psychiatric history and medication dosage: 50mg Sertraline daily."
    encrypted = engine.encrypt_text(original_text)
    decrypted = engine.decrypt_text(encrypted)
    
    assert decrypted == original_text


def test_tampering_detection_ciphertext_modification():
    """Modifying even 1 bit in ciphertext must cause authentication tag verification failure."""
    engine = AESGCMCryptoEngine()
    encrypted = engine.encrypt_text("Strictly confidential medical data")
    
    raw_json = base64.b64decode(encrypted).decode('utf-8')
    envelope = json.loads(raw_json)
    
    # Tamper with ciphertext bytes
    ciphertext_bytes = bytearray(base64.b64decode(envelope["c"]))
    ciphertext_bytes[0] ^= 0x01  # Flip one bit
    envelope["c"] = base64.b64encode(ciphertext_bytes).decode('utf-8')
    
    tampered_payload = base64.b64encode(json.dumps(envelope).encode('utf-8')).decode('utf-8')
    
    with pytest.raises(DecryptionError) as exc_info:
        engine.decrypt_text(tampered_payload)
    assert "altered" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


def test_tampering_detection_tag_modification():
    """Modifying 1 bit in authentication tag must cause verification failure."""
    engine = AESGCMCryptoEngine()
    encrypted = engine.encrypt_text("Allergy: Anaphylaxis to Penicillin")
    
    raw_json = base64.b64decode(encrypted).decode('utf-8')
    envelope = json.loads(raw_json)
    
    # Tamper with tag
    tag_bytes = bytearray(base64.b64decode(envelope["t"]))
    tag_bytes[0] ^= 0xFF
    envelope["t"] = base64.b64encode(tag_bytes).decode('utf-8')
    
    tampered_payload = base64.b64encode(json.dumps(envelope).encode('utf-8')).decode('utf-8')
    
    with pytest.raises(DecryptionError):
        engine.decrypt_text(tampered_payload)


def test_binary_file_encryption_roundtrip():
    engine = AESGCMCryptoEngine()
    raw_binary = b"%PDF-1.4\x00\x01\x02\xFF\xFE\xFDDiagnostic radiology scan binary data"
    
    encrypted_file = engine.encrypt_binary(raw_binary)
    assert encrypted_file.startswith(b"EHR_GCM_V1\x00")
    
    decrypted_file = engine.decrypt_binary(encrypted_file)
    assert decrypted_file == raw_binary


def test_binary_tampering_detection():
    engine = AESGCMCryptoEngine()
    raw_binary = b"Confidential lab biopsy report bytes"
    encrypted_file = bytearray(engine.encrypt_binary(raw_binary))
    
    # Flip bit in payload
    encrypted_file[-1] ^= 0x01
    
    with pytest.raises(DecryptionError):
        engine.decrypt_binary(bytes(encrypted_file))


def test_key_rotation():
    key_v1 = get_random_bytes(32)
    key_v2 = get_random_bytes(32)
    
    engine = AESGCMCryptoEngine(key_ring={1: key_v1, 2: key_v2}, active_version=1)
    
    # Encrypt under version 1
    enc_v1 = engine.encrypt_text("Record created in Year 1")
    env1 = json.loads(base64.b64decode(enc_v1).decode('utf-8'))
    assert env1["v"] == 1
    
    # Rotate record to version 2
    rotated_v2 = engine.rotate_record(enc_v1, new_version=2)
    env2 = json.loads(base64.b64decode(rotated_v2).decode('utf-8'))
    assert env2["v"] == 2
    
    # Verify decrypted text still matches
    assert engine.decrypt_text(rotated_v2) == "Record created in Year 1"
