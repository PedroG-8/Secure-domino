from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def generate_keys(key_size: int) -> rsa:
    """

    :param key_size: 1024, 2048, 3072, 4096
    :return: saves password in file named: e.g. keyTM.PEM
    """
    # Assert args
    assert key_size in [1024*i for i in range(1, 5)], "Key_size not correct"

    # Use 65537 (2^16 + 1) as public exponent
    priv_key = rsa.generate_private_key(65537, key_size, default_backend())

    return priv_key


def key_to_bytes(public_key):
    """

    :param public_key: key to be validated
    :return: Key in bytes form (serialized)
    """
    pem = public_key.public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
          )
    return pem


def bytes_to_key(public_pem_data):
    """

    :param public_pem_data: Key serialized
    :return: Key in normal (object) form
    """
    key = serialization.load_pem_public_key(public_pem_data)
    return key


if __name__ == '__main__':
    priv = generate_keys(key_size=1024)
    pub = priv.public_key()

    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Public key hexed to allow it to be sent
    pem_to_send = bytes.hex(pem)

    # Public key received. It will now be de-hexed
    pem = bytes.fromhex(pem_to_send)

    # Get the public key from pem
    pub2 = serialization.load_pem_public_key(pem)
