import PyKCS11 as pk
import PyKCS11.LowLevel as pkll
import cc_functs as ccf

if __name__ == '__main__':

    id_serial = ccf.get_id_serial_number()

    # --Creating a digital signature
    # Create data variable
    data = bytes('data to be signed', 'utf-8')
    signature = ccf.sign_digital(data=data)
    pub = ccf.get_public_key()

    # --Verifying a digital signature
    # Initialize variables
    assert signature is not None, "No signature provided!"
    ccf.verify_digital(
        data=data,
        signature=signature,
        public_key=pub
    )
