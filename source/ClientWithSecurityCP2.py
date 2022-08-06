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


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


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
        signed_message_len = convert_bytes_to_int(
            read_bytes(s, 8)
        )
        signed_message = read_bytes(
            s, signed_message_len
        )

        server_signed_cert_length = convert_bytes_to_int(read_bytes(s, 8))
        server_signed_cert = read_bytes(s, server_signed_cert_length)

        verify_state = True
        # 1. Verify the signed certificate sent by the Server using ca’s public key
        # Kca+ obtained from cacsertificate.crt file
        # reading cacsertificate
        f_cac = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = f_cac.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()

        server_cert = x509.load_pem_x509_certificate(
            data=server_signed_cert, backend=default_backend()
        )
        try:
            ca_public_key.verify(
                signature=server_cert.signature,
                data=server_cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=server_cert.signature_hash_algorithm
            )
        except InvalidSignature:
            verify_state = False

        # 2. Extract server_public_key: Ks+ from it
        server_public_key = server_cert.public_key()

        # 3. Decrypt signed message:
        # Ks-{M} (using the verify method) to verify that
        # M is the same message sent by the client in the first place
        try:
            server_public_key.verify(
                signed_message,  # here should be signed_message from client
                auth_msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            verify_state = False

        # 4. Check validity of server cert
        try:
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
        except AssertionError:
            verify_state = False

        '''
        If the CHECK passes, the client will proceed with file upload protocol (next task)
        In the event that the CHECK fails, the client must close the connection immediately (abort mission)
        '''
        if not verify_state:
            s.sendall(convert_int_to_bytes(2))
            print("Closing connection... Because auth failed.")

        # generate key using Fernet
        session_key_bytes = Fernet.generate_key()  # generates 128-bit symmetric key as bytes
        session_key = Fernet(session_key_bytes)  # instantiate a Fernet instance with key
        s.sendall(convert_int_to_bytes(4))  # send to server mode 4
        # encrypt the session key
        encrypted_session_key_bytes = server_public_key.encrypt(
            session_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        s.sendall(convert_int_to_bytes(len(encrypted_session_key_bytes)))
        s.sendall(encrypted_session_key_bytes)

        while verify_state:
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
            s.sendall(convert_int_to_bytes(1))
            with open(filename, mode="rb") as fp:
                data = fp.read()
                # encryption here
                encrypted_file = session_key.encrypt(
                    data,
                )

                s.sendall(convert_int_to_bytes(len(encrypted_file)))
                s.sendall(encrypted_file)

            filename = "enc_" + filename.split("/")[-1]
            with open(
                    f"send_files_enc/{filename}", mode="wb"
            ) as fp:
                fp.write(encrypted_file)
            print(
                "Saved before sent."
            )

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
