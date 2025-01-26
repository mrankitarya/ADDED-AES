# A-AES PDF Encryption and Decryption

This repository demonstrates the implementation of an enhanced AES encryption algorithm (A-AES) for encrypting and decrypting PDF files. The project uses Python and `pycryptodome` to ensure secure and efficient handling of sensitive data.

---

## Features
- **Advanced Encryption**: Implements AES-GCM for authenticated encryption, providing both confidentiality and integrity.
- **Key Derivation**: Uses PBKDF2 with a salt for secure key generation based on a password.
- **Performance Metrics**: Measures encryption and decryption times for analysis.
- **Error Handling**: Includes robust exception handling for a seamless user experience.

---

## Prerequisites
- **Python Version**: Python 3.8 or higher
- **Dependencies**: Install the required library:
  ```bash
  pip install pycryptodome
  ```

---

## How to Use

### 1. Encrypt a PDF
Use the `encrypt_pdf` function to encrypt a PDF file:
```python
salt, key = encrypt_pdf(file_path="input.pdf", 
                         output_path="encrypted.pdf", 
                         key_size=512, 
                         password="securepassword123")
```
- **Parameters**:
  - `file_path`: Path to the input PDF file.
  - `output_path`: Path to save the encrypted PDF.
  - `key_size`: Size of the key in bits (512, 768, or 1024).
  - `password`: Password for deriving the encryption key.

- **Returns**:
  - `salt`: Salt used for key derivation.
  - `key`: Generated encryption key.

---

### 2. Decrypt a PDF
Use the `decrypt_pdf` function to decrypt an encrypted PDF:
```python
decrypt_pdf(encrypted_file_path="encrypted.pdf", 
            output_path="decrypted.pdf", 
            key_size=512, 
            password="securepassword123", 
            salt=salt)
```
- **Parameters**:
  - `encrypted_file_path`: Path to the encrypted PDF file.
  - `output_path`: Path to save the decrypted PDF.
  - `key_size`: Size of the key in bits (same as used during encryption).
  - `password`: Password for deriving the decryption key.
  - `salt`: Salt used during encryption.

---

## File Structure
- **Source Code**: `a_aes_pdf_encryption.py`
- **Example Files**:
  - `input.pdf`: Sample input file.
  - `encrypted.pdf`: Encrypted output file.
  - `decrypted.pdf`: Decrypted output file.
- **Test Results**: `test_results.txt`

---

## Performance
- **Encryption Time**: Measured in seconds and varies based on file size.
- **Decryption Time**: Measured in seconds and varies based on file size.

---

## Error Handling
The implementation includes robust error handling. Common issues:
- **File Not Found**: Ensure input paths are correct.
- **Incorrect Password or Salt**: Ensure the same password and salt are used for decryption.
- **Library Errors**: Install dependencies using `pip install pycryptodome`.



---

## Acknowledgments
- The `pycryptodome` library for cryptographic functionality.
- The assignment instructions for providing a clear project framework.
