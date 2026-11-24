from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import os


# Key generation (use a secure method to store this key, e.g., environment variable or hardware security module)
def generate_key(password: str, salt: bytes) -> bytes:
    # Use scrypt to derive a 256-bit key from the password and salt
    return scrypt(password.encode(), salt=salt, key_len=32, N=2 ** 14, r=8, p=1)


# Encryption function (AES-256 CBC)
def encrypt_data(data: str, password: str) -> str:
    salt = get_random_bytes(16)  # Generate a random salt
    key = generate_key(password, salt)

    # Generate random IV (Initialization Vector) for CBC mode
    iv = get_random_bytes(AES.block_size)

    # Create cipher object using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the data to make sure it's a multiple of AES.block_size
    padding = AES.block_size - len(data) % AES.block_size
    data_padded = data + chr(padding) * padding

    # Encrypt the data
    encrypted_data = cipher.encrypt(data_padded.encode())

    # Return the salt, IV, and encrypted data as base64 encoded strings
    return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')


# Decryption function (AES-256 CBC)
def decrypt_data(encrypted_data: str, password: str) -> str:
    # Decode the base64 encoded encrypted data
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    # Extract the salt, IV, and encrypted data
    salt = encrypted_data_bytes[:16]
    iv = encrypted_data_bytes[16:32]
    encrypted_message = encrypted_data_bytes[32:]

    # Generate the key from the password and salt
    key = generate_key(password, salt)

    # Create cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_message)

    # Unpad the decrypted data
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]

    return decrypted_data.decode('utf-8')


# Example usage
if __name__ == '__main__':
    patient_data = "Patient: Vedant Nichante, Diagnosis: Hypertension, Treatment: Medication , Prescription: 30 days supply"
    password = "secure_password_123"  # In practice, use a stronger method for password storage

    # Encrypt patient healthcare record
    encrypted_record = encrypt_data(patient_data, password)
    print("Encrypted Data: ", encrypted_record)

    # Decrypt patient healthcare record
    decrypted_record = decrypt_data(encrypted_record, password)
    print("Decrypted Data: ", decrypted_record)
