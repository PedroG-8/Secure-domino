import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
try:
    from Crypto.Cipher import AES
except ImportError:
    print("Pycrypto not installed")
import json


# Credits
# Pycrypto
# https://www.dlitz.net/software/pycrypto/doc/#crypto-cipher-encryption-algorithms
# Hazmat
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html

# References
# [1] - http://stackoverflow.com/questions/59554404/ddg#59554405

# --- Description ---
# Basic Cryptography related functions
# Functions can read/write from/to json file specified to argument (optional)
# In main block there are performed some tests to secure a certain degree of resilience to errors


def encrypt_aes_pycrypto(msg, key, json_fname=""):
    """

    :param json_fname: File name where to save message
    :param msg:
    :param key:
    :return:
    """
    
    while True:
        if len(msg) % 16 == 0:
            break
        msg = msg + " "

    obj = AES.new(key)
    cipher_text = obj.encrypt(msg)

    # Don't save in .json
    if json_fname == "":
        return cipher_text
    # Save in .json
    else:
        d = {'cipher': cipher_text.hex()}
        try:
            # Save in json
            with open(json_fname, "w") as outf:
                json.dump(d, outf)

            return True

        except IOError:
            return False


def decrypt_aes_pycrypto(key, cipher_text="", json_fname=""):
    """

    :param json_fname:
    :param cipher_text:
    :param key:
    :return:
    """
    assert cipher_text != "" or json_fname != "", "Must input ciphertext!"

    obj2 = AES.new(key)

    if json_fname == "":
        txt = obj2.decrypt(cipher_text)
        return txt
    else:

        with open(json_fname, 'rb') as inf:
            d = json.load(inf)
            txt = obj2.decrypt(
                bytes.fromhex(d['cipher'])
            )

        return txt


def encrypt_aes_hazmat(msg: bytes, key):

    # Setup cipher: AES in CBC mode, w/ a random IV and PKCS #7 padding (similar to PKCS #5)
    iv = os.urandom(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    # Initialize output and write IV before cryptogram
    ciphertext = iv

    # Cicle to repeat while there is data left on the msg variable
    while True:
        # Read a chunk of the msg var to the plaintext variable
        plaintext = msg[:100 * algorithms.AES.block_size]
        msg = msg[100 * algorithms.AES.block_size:]

        if not plaintext or len(plaintext) % algorithms.AES.block_size != 0:
            # Write the contents of ciphertext in the output file
            ciphertext += encryptor.update(padder.update(plaintext) + padder.finalize())
            break
        else:
            # Write the ciphertext in the output file
            ciphertext += encryptor.update(plaintext)

    return ciphertext


def decrypt_aes_hazmat(encrypted_text: bytes, key):

    # Setup cipher: AES in CBC mode, w/ a random IV and PKCS #7 padding (similar to PKCS #5)
    iv = encrypted_text[:algorithms.AES.block_size // 8]
    encrypted_text = encrypted_text[algorithms.AES.block_size // 8:]  # cut out iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

    # Output text initialize
    plaintext = bytes()

    # Cicle to repeat while there is data left on the input file
    while True:
        # Read a chunk of the input file to the plaintext variable
        block = encrypted_text[:100 * algorithms.AES.block_size]
        # Slice block off the encrypted_text
        encrypted_text = encrypted_text[100 * algorithms.AES.block_size:]

        if not block:
            # Write the contents of ciphertext in the output file
            plaintext += unpadder.finalize()
            break
        else:
            # Write the ciphertext in the output file
            plaintext += unpadder.update(decryptor.update(encrypted_text))

    return plaintext


def encrypt_rsa_hazmat(msg: bytes, pub_key: rsa, json_fname=""):
    """

    :param json_fname:
    :param pub_key: public key
    :param msg: plaintext to encrypt
    :return:
    """

    # Calculate the max amount of data we can encrypt with OAEP + SHA 256
    max_len = (pub_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2

    # Read for plaintext no more than maxLen bytes from the input file
    assert len(msg) <= max_len, "Message too big!"

    # Encrypt the plaintext using OAEP + MGF1 (SHA256) + SHA256
    cipher_text = pub_key.encrypt(
        msg, asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )

    # Don't save in .json
    if json_fname == "":
        return cipher_text
    # Save in .json
    else:
        d = {'cipher': cipher_text.hex()}
        try:
            # Save in json
            with open(json_fname, "w") as outf:
                json.dump(d, outf)

            return True

        except IOError:
            return False


def decrypt_rsa_hazmat(priv_key: rsa, cipher_text: bytes = "", json_fname="") -> str:
    """

    :param priv_key:
    :param cipher_text:
    :param json_fname:
    :return:
    """

    # Assure there is input to decrypt
    assert cipher_text != "" or json_fname != "", "Must have input!"

    if json_fname == "":
        txt = b""
        try:
            txt = priv_key.decrypt(
                cipher_text, asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )

        except ValueError:
            return txt
        return txt

    else:

        with open(json_fname, 'r') as inf:
            d = json.load(inf)
            txt = priv_key.decrypt(
                bytes.fromhex(d['cipher']), asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )

        return txt


def sign_rsa_hazmat(priv_key: rsa, msg: bytes, json_fname=""):
    """

    :param json_fname: json file containing the message
    :param msg:
    :param priv_key:
    :return:
    """

    # We need input one way or another
    assert msg != "" or json_fname != "", "No input given!"

    # Calculate the max amount of data we can encrypt with OAEP + SHA 256
    max_len = (priv_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2

    # Read for plaintext no more than maxLen bytes from the input file
    assert len(msg) <= max_len, "Message too big!"

    signed = private_key.sign(
        msg,
        asym_padding.PSS(
            asym_padding.MGF1(hashes.SHA256()),
            asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    if json_fname == "":
        return signed
    else:
        d = {'signature': signed.hex(), 'message': msg.hex()}
        try:
            # Save in json
            with open(json_fname, "w") as outf:
                json.dump(d, outf)

            return True

        except IOError:
            return False


def verify_rsa_hazmat(pub_key: rsa, msg: bytes, signed: bytes = "", json_fname="") -> bool:
    """

    :param json_fname:
    :param signed:
    :param msg:
    :param pub_key:
    :return:
    """

    # Assert there is some kind of input
    assert json_fname != "" or (signed != "" and msg != ""), "No input!"

    if json_fname != "":

        with open(json_fname, "r") as inf:
            d = json.load(inf)

        signed = bytes.fromhex(d["signature"])
        msg = bytes.fromhex(d['message'])

    try:
        pub_key.verify(
            signed,
            msg,
            asym_padding.PSS(
                asym_padding.MGF1(hashes.SHA256()),
                asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    except InvalidSignature:
        # print("Impersonation detected!")
        return False
    return True


if __name__ == '__main__':
    # Testing asymmetric functions:
    import asym_keys

    # Key pair
    private_key = asym_keys.generate_keys(key_size=1024)
    public_key = private_key.public_key()

    # Encryption:
    message = b"hello crypt"
    cipher_text = encrypt_rsa_hazmat(message, public_key)
    text = decrypt_rsa_hazmat(cipher_text=cipher_text, priv_key=private_key)
    print(text)
    assert text == message, f"'hello crypt' != {text}"

    # Signature:
    message = b"Youre lying dolores"
    signature = sign_rsa_hazmat(msg=message, priv_key=private_key)
    assert verify_rsa_hazmat(public_key, message, signature)
    assert not verify_rsa_hazmat(public_key, b"Your lying dolores", signature)

    # Testing Symmetric functions
    # Sym key
    key = "What a load of waffles.."
    message = b"Blimey, Hermione"
    # cipher_text = encrypt_aes_pycrypto(msg=message, key=key)
    # assert decrypt_aes_pycrypto(cipher_text=cipher_text, key=key) == message
    # assert not decrypt_aes_pycrypto(cipher_text=cipher_text, key="What a load oh waffles..") == message

    # Testing with JSON
    filename = "messages.json"
    # RSA
    false_message = b"Blimey, Hermioni"
    # Should pass
    encrypt_rsa_hazmat(msg=message, pub_key=public_key, json_fname=filename)
    assert decrypt_rsa_hazmat(priv_key=private_key, json_fname=filename) == message
    # Should fail
    encrypt_rsa_hazmat(msg=message, pub_key=public_key, json_fname=filename)
    assert not decrypt_rsa_hazmat(priv_key=private_key, json_fname=filename) == false_message

    # AES
    # Should pass
    # assert encrypt_aes_pycrypto(msg=message, key=key, json_fname=filename)
    # assert decrypt_aes_pycrypto(key=key, json_fname=filename) == message
    # # Should fail
    # assert encrypt_aes_pycrypto(msg=false_message, key=key, json_fname=filename)
    # assert not decrypt_aes_pycrypto(key=key, json_fname=filename) == message

    # Should pass
    assert sign_rsa_hazmat(priv_key=private_key, msg=message, json_fname="messages.json")
    assert verify_rsa_hazmat(public_key, msg=message, json_fname=filename)
    # Should fail
    assert sign_rsa_hazmat(priv_key=private_key, msg=message, json_fname="messages.json")
    assert verify_rsa_hazmat(public_key, msg=false_message, json_fname=filename)



