import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256, pbkdf2_hmac

class A_AES:
    def __init__(self, key_size, password=None, salt=None):
        """
        Initialize the A_AES class with a specified key size.
        :param key_size: Size of the key in bits (512, 768, or 1024).
        :param password: Optional password for key derivation.
        :param salt: Optional salt for key derivation.
        """
        self.key_size = key_size // 8  # Convert bits to bytes
        self.block_size = 64  # A-AES block size is 512 bits / 8 = 64 bytes

        if password is None:
            raise ValueError("Password must be provided for key derivation.")
        
        # Generate a salt if not provided
        self.salt = salt or get_random_bytes(16)

        # Derive a key using PBKDF2
        self.key = pbkdf2_hmac('sha256', password.encode(), self.salt, 100000, dklen=self.key_size)

    def encrypt(self, data):
        """
        Encrypt the given data using A-AES.
        :param data: Data to encrypt.
        :return: Encrypted data with IV prepended.
        """
        # Derive a valid AES key (256 bits = 32 bytes)
        aes_key = sha256(self.key).digest()[:32]
        cipher = AES.new(aes_key, AES.MODE_GCM)
        iv = cipher.nonce  # Nonce for AES-GCM

        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return iv + tag + ciphertext  # Prepend IV and tag for decryption

    def decrypt(self, ciphertext):
        """
        Decrypt the given ciphertext using A-AES.
        :param ciphertext: Data to decrypt.
        :return: Decrypted data.
        """
        # Derive a valid AES key (256 bits = 32 bytes)
        aes_key = sha256(self.key).digest()[:32]
        iv = ciphertext[:16]
        tag = ciphertext[16:32]
        encrypted_data = ciphertext[32:]

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

        # Decrypt the data
        data = cipher.decrypt_and_verify(encrypted_data, tag)
        return data


def encrypt_pdf(file_path, output_path, key_size, password):
    """
    Encrypt a PDF file.
    :param file_path: Path to the input PDF file.
    :param output_path: Path to save the encrypted PDF.
    :param key_size: Size of the key in bits.
    :param password: Password for key derivation.
    :return: The salt and key used for encryption.
    """
    try:
        with open(file_path, 'rb') as file:
            pdf_data = file.read()

        a_aes = A_AES(key_size, password)
        encrypted_data = a_aes.encrypt(pdf_data)

        with open(output_path, 'wb') as file:
            file.write(encrypted_data)

        print(f"PDF encrypted successfully: {output_path}")
        return a_aes.salt, a_aes.key  # Return the salt and key
    except Exception as e:
        print(f"Error during encryption: {e}")


def decrypt_pdf(encrypted_file_path, output_path, key_size, password, salt):
    """
    Decrypt an encrypted PDF file.
    :param encrypted_file_path: Path to the encrypted PDF file.
    :param output_path: Path to save the decrypted PDF.
    :param key_size: Size of the key in bits.
    :param password: Password for key derivation.
    :param salt: Salt used during encryption.
    """
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()

        a_aes = A_AES(key_size, password, salt)
        decrypted_data = a_aes.decrypt(encrypted_data)

        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        print(f"PDF decrypted successfully: {output_path}")
    except Exception as e:
        print(f"Error during decryption: {e}")


# Example usage
if __name__ == "__main__":
    input_pdf = 'C:\\Users\\GABRU\\Downloads\\AAES_512_768_1024.pdf'
    encrypted_pdf = 'C:\\Users\\GABRU\\Desktop\\RATTANKUMAR\\Email\\encrypted5.pdf'
    decrypted_pdf = 'C:\\Users\\GABRU\\Desktop\\RATTANKUMAR\\Email\\decrypt5.pdf'
    key_size = 512  # Example: 512 bits
    password = "securepassword123"  # Use a strong password

    # Encrypt the PDF and get the salt and key
    start_time = time.time()
    salt, key = encrypt_pdf(input_pdf, encrypted_pdf, key_size, password)
    print(f"Encryption Time: {time.time() - start_time:.2f} seconds")

    # Decrypt the PDF using the same password and salt
    start_time = time.time()
    decrypt_pdf(encrypted_pdf, decrypted_pdf, key_size, password, salt)
    print(f"Decryption Time: {time.time() - start_time:.2f} seconds")
