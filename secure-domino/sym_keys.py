import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def generate_key(pwd):
    """
    As in https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions.html
    :param pwd: Any string we want
    :return: Symmetric key based on random salt and password of argument
    """

    salt = os.urandom(16)
    pwd = bytes(pwd, 'utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=1000,
        backend=default_backend())
    key = kdf.derive(pwd)

    # Verification
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=1000,
        backend=default_backend())
    kdf.verify(pwd, key)

    return key


if __name__ == '__main__':

    # Create the key based on a password (Same password doesn't mean same keys)
    secret_key = generate_key(pwd="My password")
