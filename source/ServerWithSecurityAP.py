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
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
            private_key = serialization.load_pem_private_key(
                bytes(key_file.read(), encoding="utf8"), password=None
            )
        public_key = private_key.public_key()
    except Exception as e:
        print(e)

    # Use private_key or public_key for encryption or decryption from now onwards

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            file_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            auth_msg_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            received_auth_msg = read_bytes(
                                client_socket, auth_msg_len
                            )
                            signed_message = private_key.sign(
                                received_auth_msg,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256()
                            )
                            '''
                            M1 from server: size of incoming M2 in bytes
                            M2 from server: signed authentication message
                            another M1 from server: size of incoming M2 in bytes (this is server_signed.crt)
                            another M2 from server: server_signed.crt
                            '''
                            # Reading Certificate as byte without loading it
                            with open(
                                    "auth/server_signed.crt", "rb"
                            ) as server_crt_f:
                                server_crt_raw = server_crt_f.read()

                            # how to send?
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            client_socket.sendall(signed_message)
                            client_socket.sendall(convert_int_to_bytes(len(server_crt_raw)))
                            client_socket.sendall(server_crt_raw)
                            break

    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
