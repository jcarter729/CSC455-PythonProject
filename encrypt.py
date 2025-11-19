from cryptography.fernet import Fernet

def Generate_key():
    key = Fernet.generate_key()
    return key

def Encrypt(key, data):
    f = Fernet(key)
    encrypted = f.encrypt(data)
    with open("Secret.txt", "wb") as enc:
        enc.write(encrypted)

def Decrypt(key, data):
    f = Fernet(key)
    decrypted = f.decrypt(data)
    with open("Secret.txt", "wb") as dec:
        dec.write(decrypted)

if __name__ == "__main__":
    choice = input("Generate a key? (y/n): ").strip().lower()

    if choice == "y":
        with open("secret.key", "wb") as f:
            f.write(Generate_key())

    try:
        choice2 = int(input("Press 1 to encrypt and 2 to decrypt!"))
    except ValueError:
        print("Invalid choice")
        raise SystemExit(1)

    with open("secret.key", "rb") as f2:
        key = f2.read()

    with open("Secret.txt", "rb") as files:         # replace Secret.txt with your file name
        data = files.read()
        if choice2 == 1:
            Encrypt(key, data)
        else:
            Decrypt(key, data)