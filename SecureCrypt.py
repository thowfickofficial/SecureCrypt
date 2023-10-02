from cryptography.fernet import Fernet
import os

# Function to generate a new encryption key and save it securely
def generate_key(key_file="secret.key"):
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as key_file:
            key_file.write(key)
            print("Key generated and saved.")
    else:
        print("Key already exists.")

# Function to load the encryption key from a file
def load_key(key_file="secret.key"):
    if os.path.exists(key_file):
        with open(key_file, "rb") as key_file:
            return key_file.read()
    else:
        print("Key file not found. Generate a new key.")
        return None

# Function to encrypt a text message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Function to decrypt a text message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        print("Decryption failed:", str(e))
        return None

# Function to generate a random password
def generate_password(length=16):
    import string
    import random
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Main function to interact with the user
if __name__ == "__main__":
    while True:
        print("\nOptions:")
        print("1. Generate Key")
        print("2. Encrypt a Text Message")
        print("3. Decrypt a Text Message")
        print("4. Generate Random Password")
        print("5. Quit")

        choice = input("Choose an option: ")

        if choice == "1":
            generate_key()
        elif choice == "2":
            key = load_key()
            if key:
                message = input("Enter the message to encrypt: ")
                encrypted_message = encrypt_message(message, key)
                print("Encrypted message:", encrypted_message.decode())
        elif choice == "3":
            key = load_key()
            if key:
                encrypted_message = input("Enter the encrypted message: ")
                decrypted_message = decrypt_message(encrypted_message.encode(), key)
                if decrypted_message:
                    print("Decrypted message:", decrypted_message)
        elif choice == "4":
            password_length = int(input("Enter the length of the password: "))
            password = generate_password(password_length)
            print("Generated password:", password)
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")
