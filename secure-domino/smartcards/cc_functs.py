import sys
import PyKCS11 as pk
import PyKCS11.LowLevel as pkll
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)
from cryptography.exceptions import InvalidSignature


classes = {
        pkll.CKO_PRIVATE_KEY: 'private key',
        pkll.CKO_PUBLIC_KEY: 'public key',
        pkll.CKO_CERTIFICATE: 'certificate'
    }


def load_pkcs11():
    """

    :return: pkcs11 library
    """
    libs = {
        "linux": "/usr/local/lib/libpteidpkcs11.so",
        "win32": "C:\\Windows\\System32\\pteidpkcs11.dll"
    }

    lib = libs[sys.platform]

    # load pkcs11
    pkcs11 = pk.PyKCS11Lib()
    pkcs11.load(lib)

    return pkcs11


def print_slot_objects():
    """
    Print objects of CC in slot
    :return:
    """

    pkcs11 = load_pkcs11()

    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            objects = session.findObjects()
            for obj in objects:
                label = session.getAttributeValue(obj, [pkll.CKA_LABEL])[0]
                clas = session.getAttributeValue(obj, [pkll.CKA_CLASS])[0]
                print(f"Object with label {label}, of class {classes[clas]}")


def sign_digital(data: bytes):
    """

    :param data: data to be signed with AUTHENTICATION's private key
    :return:
    """

    # --Load library (?)
    pkcs11 = load_pkcs11()

    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)

            priv_key = session.findObjects(
                [
                    (pkll.CKA_CLASS, pkll.CKO_PRIVATE_KEY),
                    (pkll.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            # In guide it's SHA1...I put SHA256 because it seems safer
            signature = bytes(session.sign(priv_key, data, pk.Mechanism(pkll.CKM_SHA256_RSA_PKCS)))

            session.closeSession()

            return signature

    print("No CC provided!")
    return None


def verify_digital(data, signature, public_key=None):
    """

    :param data:
    :param signature:
    :param public_key: Can be given as argument or gotten by in slot citizen card
    :return: Verification that data was signed by the identity related to the public key
    """

    # If public key is not already provided
    if public_key is None:
        # --Load library
        pkcs11 = load_pkcs11()

        slots = pkcs11.getSlotList()

        for slot in slots:
            if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
                session = pkcs11.openSession(slot)

                public_key_handle = session.findObjects(
                    [
                        (pkll.CKA_CLASS, pkll.CKO_PUBLIC_KEY),
                        (pkll.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                    ]
                )[0]

                public_key_der = session.getAttributeValue(
                    public_key_handle, [pkll.CKA_VALUE], True
                )[0]

                session.closeSession()

                public_key = load_der_public_key(bytes(public_key_der), default_backend())

    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        print("Verification succeeded!")
    except InvalidSignature:
        print('Verification failed!')
        sys.exit(1)


def get_authentication_cert_object() -> dict:
    """

    :return: Returns cc's authentication public key's certification info
    """
    pkcs11 = load_pkcs11()

    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            objects = session.findObjects()
            res = objects[4].to_dict()
            session.closeSession()
            return res

    return None


def get_id_serial_number() -> str:
    """

    :return: in-slot-cc's authentication serial number
    """
    return str(
        get_authentication_cert_object()['CKA_SERIAL_NUMBER']
    )


def get_public_key():
    # --Load library
    pkcs11 = load_pkcs11()

    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)

            public_key_handle = session.findObjects(
                [
                    (pkll.CKA_CLASS, pkll.CKO_PUBLIC_KEY),
                    (pkll.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]

            public_key_der = session.getAttributeValue(
                public_key_handle, [pkll.CKA_VALUE], True
            )[0]

            session.closeSession()

            return load_der_public_key(bytes(public_key_der), default_backend())

    return None


if __name__ == '__main__':

    # --Print slot objects? Não faço puto de ideia
    print_slot_objects()

    auth = get_authentication_cert_object()

    # Get public key of cc in slot
    # public_key = get_public_key()
