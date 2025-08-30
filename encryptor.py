# encryptor.py
import argparse

def main():
    parser = argparse.ArgumentParser(description="🛡️ AES-256 File Encryptor/Decryptor")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Choose to encrypt or decrypt a file.")
    parser.add_argument("input", help="Path to input file")
    parser.add_argument("output", help="Path to output file")
    args = parser.parse_args()

    if args.mode == "encrypt":
        print("🔐 Encrypting:", args.input)
        # encryption logic goes here
    else:
        print("🔓 Decrypting:", args.input)
        # decryption logic goes here

if __name__ == "__main__":
    main()
