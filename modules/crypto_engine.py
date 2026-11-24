"""
AES-256-GCM Cryptographic Engine for Electronic Health Records (EHR).
Complies with NIST SP 800-38D specifications for Galois/Counter Mode.

Key Features:
- Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM.
- Cryptographically strong random 96-bit (12-byte) unique nonce for EVERY operation.
- 128-bit (16-byte) authentication tag verification.
- Tamper detection: strictly raises DecryptionError if any ciphertext or tag bit is altered.
- NEVER silently falls back to plaintext.
- Key rotation and version-tagged envelope handling.
- Secure encrypted file streaming/packaging.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from config import Config

FILE_MAGIC_HEADER = b"EHR_GCM_V1\x00"

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

class DecryptionError(CryptoError):
    """Raised when ciphertext authentication or decryption fails."""
    pass

class KeyRotationError(CryptoError):
    """Raised when a key version cannot be resolved in the key ring."""
    pass


class AESGCMCryptoEngine:
    def __init__(self, key_ring: Optional[Dict[int, bytes]] = None, active_version: int = 1):
        self.key_ring = key_ring or Config.KEY_RING
        self.active_version = active_version or Config.KEY_ROTATION_VERSION

    def get_key(self, version: Optional[int] = None) -> Tuple[int, bytes]:
        """Resolves encryption key for the specified version or returns active version."""
        v = version if version is not None else self.active_version
        if v not in self.key_ring:
            raise KeyRotationError(f"Encryption key version '{v}' not found in active key ring.")
        key = self.key_ring[v]
        if len(key) != 32:
            raise CryptoError(f"AES-256 key must be 32 bytes (got {len(key)} bytes).")
        return v, key

    def encrypt_text(self, plaintext: str, associated_data: Optional[str] = None) -> str:
        """
        Encrypts a string using AES-256-GCM with a unique 96-bit nonce.
        Returns a compact, versioned JSON payload serialized to base64.
        """
        if plaintext is None:
            return ""
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)

        version, key = self.get_key()
        # 12-byte (96-bit) nonce recommended by NIST for GCM
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        if associated_data:
            cipher.update(associated_data.encode('utf-8'))

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        envelope = {
            "v": version,
            "n": base64.b64encode(nonce).decode('utf-8'),
            "t": base64.b64encode(tag).decode('utf-8'),
            "c": base64.b64encode(ciphertext).decode('utf-8'),
            "ad": associated_data is not None
        }
        
        envelope_json = json.dumps(envelope, separators=(',', ':'))
        return base64.b64encode(envelope_json.encode('utf-8')).decode('utf-8')

    def decrypt_text(self, encrypted_payload: str, associated_data: Optional[str] = None) -> str:
        """
        Authenticates and decrypts an AES-256-GCM envelope.
        Raises DecryptionError if the ciphertext, tag, or associated data has been tampered with.
        """
        if not encrypted_payload:
            return ""

        try:
            raw_json = base64.b64decode(encrypted_payload.encode('utf-8')).decode('utf-8')
            envelope = json.loads(raw_json)
            
            version = envelope["v"]
            nonce = base64.b64decode(envelope["n"])
            tag = base64.b64decode(envelope["t"])
            ciphertext = base64.b64decode(envelope["c"])
            has_ad = envelope.get("ad", False)
        except Exception as e:
            raise DecryptionError(f"Invalid encrypted payload structure: {str(e)}")

        _, key = self.get_key(version)

        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if has_ad and associated_data:
                cipher.update(associated_data.encode('utf-8'))
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext_bytes.decode('utf-8')
        except (ValueError, KeyError) as e:
            raise DecryptionError("Decryption/Authentication failed: data has been altered or key is invalid.") from e

    def encrypt_binary(self, raw_bytes: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypts raw binary data (e.g. PDF, DICOM, images) using AES-256-GCM.
        Binary Format:
        [11-byte Magic Header: EHR_GCM_V1\0]
        [1-byte Version byte]
        [12-byte Nonce]
        [16-byte Auth Tag]
        [Ciphertext]
        """
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise CryptoError("Data to encrypt must be bytes.")

        version, key = self.get_key()
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        if associated_data:
            cipher.update(associated_data)

        ciphertext, tag = cipher.encrypt_and_digest(raw_bytes)

        version_byte = version.to_bytes(1, byteorder='big')
        return FILE_MAGIC_HEADER + version_byte + nonce + tag + ciphertext

    def decrypt_binary(self, encrypted_file_bytes: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Authenticates and decrypts binary data encrypted with encrypt_binary.
        Raises DecryptionError if the header or ciphertext is corrupted or tampered.
        """
        if not encrypted_file_bytes or len(encrypted_file_bytes) < len(FILE_MAGIC_HEADER) + 1 + 12 + 16:
            raise DecryptionError("Encrypted binary data is truncated or invalid.")

        header_len = len(FILE_MAGIC_HEADER)
        header = encrypted_file_bytes[:header_len]
        if header != FILE_MAGIC_HEADER:
            raise DecryptionError("Invalid file header: not a valid encrypted EHR document.")

        version = int.from_bytes(encrypted_file_bytes[header_len:header_len+1], byteorder='big')
        nonce_start = header_len + 1
        nonce_end = nonce_start + 12
        tag_end = nonce_end + 16

        nonce = encrypted_file_bytes[nonce_start:nonce_end]
        tag = encrypted_file_bytes[nonce_end:tag_end]
        ciphertext = encrypted_file_bytes[tag_end:]

        _, key = self.get_key(version)

        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if associated_data:
                cipher.update(associated_data)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError) as e:
            raise DecryptionError("Binary decryption failed: authentication tag mismatch or corrupted file.") from e

    def rotate_record(self, old_payload: str, new_version: Optional[int] = None, associated_data: Optional[str] = None) -> str:
        """
        Re-encrypts a payload under a new key version without exposing plaintext.
        """
        plaintext = self.decrypt_text(old_payload, associated_data=associated_data)
        target_version = new_version or self.active_version
        
        # Save temporary active version
        prev_version = self.active_version
        try:
            self.active_version = target_version
            return self.encrypt_text(plaintext, associated_data=associated_data)
        finally:
            self.active_version = prev_version


# Singleton instance
crypto_engine = AESGCMCryptoEngine()
