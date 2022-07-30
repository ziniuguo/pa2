import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")
        # send 3 (mode 3)
        s.sendall(convert_int_to_bytes(3))
        auth_msg = bytes("hello world", encoding="utf-8")
        # not sure. It should be arbitrary
        # send length of auth msg
        s.sendall(convert_int_to_bytes(len(auth_msg)))
        # send msg
        s.sendall(auth_msg)

        # receive 4 msg from server
        # No idea how to receive, so hardcode for now

        # 1. Verify the signed certificate sent by the Server using ca’s public key
        # Kca+ obtained from cacsertificate.crt file
        # reading cacsertificate
        f_cac = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = f_cac.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()

        f_server_signed = open("auth/server_signed.crt", "rb")
        # should be sent by server, but don't know how to do, so hardcode
        server_cert_raw = f_server_signed.read()
        server_cert = x509.load_pem_x509_certificate(
            data=server_cert_raw, backend=default_backend()
        )
        ca_public_key.verify(
            signature=server_cert.signature,
            data=server_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=server_cert.signature_hash_algorithm
        )

        # 2. Extract server_public_key: Ks+ from it
        server_public_key = server_cert.public_key()

        # 3. Decrypt signed message:
        # Ks-{M} (using the verify method) to verify that
        # M is the same message sent by the client in the first place
        server_public_key.verify(
            auth_msg,  # here should be signed_message from client
            auth_msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )

        # 4. Check validity of server cert
        assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after

        '''
        If the CHECK passes, the client will proceed with file upload protocol (next task)
        In the event that the CHECK fails, the client must close the connection immediately (abort mission)
        '''
        # to be done

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
