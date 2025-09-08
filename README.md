# 🔐 Advanced Encryption Tool

A Python-based **AES-256 encryption & decryption tool** with password-based key derivation (PBKDF2), random salt, IV, and HMAC integrity check.  
This ensures files are encrypted securely and cannot be modified or decrypted without the correct password.



## ✨ Features
- AES-256-CBC encryption
- PBKDF2 key derivation with random salt
- Random IV for each encryption
- HMAC-SHA256 integrity check (detects wrong password/tampering)
- Simple CLI usage



## 📦 File Format Layout
Each `.enc` file is structured as follows:

[ 16 bytes salt ][ 16 bytes IV ][ ciphertext... ][ 32 bytes HMAC ]

- Salt → stored so the same key can be regenerated at decryption  
- IV → ensures unique ciphertext even if plaintext & password are same  
- Ciphertext → the encrypted data  
- HMAC → validates password & detects tampering  



## ⚙️ Installation
1. Clone or download the project  
2. Install dependencies:
   pip install pycryptodome



## 🚀 Usage
Run the tool from terminal:

### Encrypt a file
python3 encryptor.py encrypt input.txt output.enc -p yourpassword

✅ Example:
python3 encryptor.py encrypt test.txt secret.enc -p hunter2

### Decrypt a file
python3 encryptor.py decrypt input.enc output.txt -p yourpassword

✅ Example:
python3 encryptor.py decrypt secret.enc decrypted.txt -p hunter2



## 🔍 Example File Flow
- Encrypting `test.txt` with password `hunter2` produces `secret.enc`.  
- Opening `secret.enc` shows binary gibberish (normal).  
- Only by running the tool with the same password will you get back `test.txt`.  
- Wrong password → decryption fails with HMAC error (no garbage output).



## 🛡️ Security Notes
- Salt & IV are not secret and are stored in the file.  
- Password strength is critical → use a strong password!  
- Without the correct password, AES + HMAC makes brute-forcing infeasible.  



## 🧪 Debugging / Inspect Encrypted File
You can inspect parts of the encrypted file in hex:

```python
with open("secret.enc", "rb") as f:
    data = f.read()

salt = data[:16]
iv = data[16:32]
hmac_stored = data[-32:]
ciphertext = data[32:-32]

print("Salt:", salt.hex())
print("IV:", iv.hex())
print("HMAC:", hmac_stored.hex())
print("Ciphertext length:", len(ciphertext))
