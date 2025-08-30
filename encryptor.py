# encryptor.py
import argparse
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ========== CONFIG ==========
KEY_SIZE = 32          # 256 bits
SALT_SIZE = 16         # 128-bit salt
IV_SIZE = 16           # 128-bit IV
ITERATIONS = 100000    # PBKDF2 iterations (slow for brute-force)

# ========== FUNCTIONS ==========
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secure 256-bit AES key from a password and salt."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_file(password: str, input_path: str, output_path: str):
    # 1. Read file
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # 2. Generate salt + derive key
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)

    # 3. Generate IV
    iv = get_random_bytes(IV_SIZE)

    # 4. AES-CBC Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # AES requires block size multiple → pad manually
    pad_len = AES.block_size - (len(plaintext) % AES.block_size)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)

    ciphertext = cipher.encrypt(padded_plaintext)

    # 5. Save (salt + iv + ciphertext) into output file
    with open(output_path, "wb") as f:
        f.write(salt + iv + ciphertext)

    print(f"✅ Encrypted {input_path} → {output_path}")

def decrypt_file(password: str, input_path: str, output_path: str):
    # 1. Read file
    with open(input_path, "rb") as f:
        data = f.read()

    # 2. Extract salt + iv + ciphertext
    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = data[SALT_SIZE+IV_SIZE:]

    # 3. Derive key
    key = derive_key(password, salt)

    # 4. AES-CBC Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]

    # 5. Save to file
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"🔓 Decrypted {input_path} → {output_path}")

# ========== CLI ==========
def main():
    parser = argparse.ArgumentParser(description="🛡️ AES-256 File Encryptor/Decryptor")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Choose to encrypt or decrypt a file.")
    parser.add_argument("input", help="Path to input file")
    parser.add_argument("output", help="Path to output file")
    parser.add_argument("-p", "--password", required=True, help="Password for encryption/decryption")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.password, args.input, args.output)
    else:
        decrypt_file(args.password, args.input, args.output)

if __name__ == "__main__":
    main()
