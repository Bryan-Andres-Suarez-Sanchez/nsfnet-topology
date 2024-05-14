"""
API Documentation

This module provides functions for sending and receiving encrypted messages between nodes in a network.

Functions:
    encrypt_message(message: str, public_key: rsa.PublicKey) -> bytes:
        Encrypts the given message using the provided public key.

    decrypt_message(encrypted_message: bytes, private_key: rsa.PrivateKey) -> bytes:
        Decrypts the given encrypted message using the provided private key.

    send_message(origin_node: str, destination_node: str, message: str, public_key: rsa.PublicKey, message_type: str = "user_message") -> None:
        Sends a message from the origin node to the destination node.

    handle_client(client_socket: socket.socket, private_key: rsa.PrivateKey) -> None:
        Handles incoming messages from other nodes.

    listen_for_messages(private_key: rsa.PrivateKey) -> None:
        Listens for incoming messages from other nodes.
"""
import socket
import json
import threading
import base64
import time
import pickle
import rsa
import dijkstra_paths
from controllerserver import network

CHUNK = 1024

file_pri = open('pri_key.txt', 'rb')
private_key = pickle.load(file_pri)
file_pri.close()
# Load public key from file
file_pub = open('pub_key.txt', 'rb')
public_key = pickle.load(file_pub)
file_pub.close()

def encrypt_message(message, public_key):
    """
    Encrypts the given message using the provided public key.

    Args:
        message (str): The message to be encrypted.
        public_key (rsa.PublicKey): The public key used for encryption.

    Returns:
        bytes: The encrypted message.
    """
    return rsa.encrypt(message, public_key)

def decrypt_message(encrypted_message, private_key):
    """
    Decrypts the given encrypted message using the provided private key.

    Args:
        encrypted_message (bytes): The encrypted message.
        private_key (rsa.PrivateKey): The private key used for decryption.

    Returns:
        bytes: The decrypted message.
    """
    return rsa.decrypt(encrypted_message, private_key)

def send_message(origin_node, destination_node, message, public_key, message_type="user_message"):
    """
    Sends a message from the origin node to the destination node.

    Args:
        origin_node (str): The IP address of the origin node.
        destination_node (str): The IP address of the destination node.
        message (str): The message to be sent.
        public_key (rsa.PublicKey): The public key used for encryption.
        message_type (str, optional): The type of message ('user_message' or 'audio_message'). Defaults to "user_message".
    """

    try:
        # Establish connection with the destination node
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", 9011))

        # Connect to the listening port of the node
        # Load routing tables

        with open("routing_tables.json", "r") as file:
            routing_tables = json.load(file)
            if origin_node in routing_tables:
                routing_table_json = routing_tables[origin_node]
                path = routing_table_json[destination_node]


        if message_type == "audio_message":
            # If it is an audio message, attach the file to the message
            # Read and send the audio file in chunks
            with open(audio_file, 'rb') as f:
                i = 0
                while i < 10:
                    i += 1
                    chunk = f.read(53)
                    if not chunk:
                        break
                    encrypted_chunk = encrypt_message(chunk, public_key)
                    data = {
                        "tipo": "audio_message",
                        "origen": origin_node,
                        "destino": destination_node,
                        "mensaje": encrypted_chunk
                    }
                    # Establish a new connection to send the current chunk
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect(("localhost", 9011))  # Conectarse al puerto de escucha del nodo
                    client_socket.sendall(pickle.dumps(data))
                    client_socket.close()  # Cerrar la conexión después de enviar el chunk

            # Send end of file marker
            #client_socket.sendall(pickle.dumps("END_OF_FILE"))
        if message_type == "user_message":
            # Encrypt only the message
            encrypted_message = encrypt_message(message.encode(), public_key)  # Convertir a bytes antes de encriptar

            # Construct the complete message with data information
            data = {
                "tipo": message_type,
                "origen": origin_node,
                "destino": destination_node,
                "mensaje": encrypted_message
            }

            # Send the complete message to the node
            client_socket.sendall(pickle.dumps(data))

        # Close the connection
        dijkstra_paths.visualize_path(path, network)
        client_socket.close()
    except Exception as e:
        print(f"Error sending message: {e}")


def handle_client(client_socket, private_key):
    """
       Handles incoming messages from other nodes.

       Args:
           client_socket (socket.socket): The socket for communication with the client node.
           private_key (rsa.PrivateKey): The private key used for decryption.
       """
    try:
        audio_chunks = b''
        # Recibir el mensaje del nodo
        data = pickle.loads(client_socket.recv(1024))
        message_type = data.get("tipo")
        message = data.get("mensaje")

        # Desencriptar el mensaje
        decrypted_message = decrypt_message(message, private_key)

        # Procesar el mensaje según sea necesario
        if message_type == "user_message":
            print(f"Message received from {data['origen']}: {decrypted_message}")
            # Procesar el mensaje de texto según sea necesario

        elif message_type == "audio_message":
            print(f"Audio message received from {data['origen']}")
            # Concatenar los paquetes de audio
            audio_chunks += decrypted_message
            print("Audio chunk received.")

        else:
            print("Unknown message type")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        # Cerrar la conexión con el nodo
        client_socket.close()

def listen_for_messages(private_key):
    """
        Listens for incoming messages from other nodes.

        Args:
            private_key (rsa.PrivateKey): The private key used for decryption.
        """
    try:
        # Establecer el socket para escuchar mensajes entrantes
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", 7001))  # Puerto de escucha del cliente
        server_socket.listen(5)
        # print("Client listening for incoming messages...")

        while True:
            # Aceptar conexiones entrantes
            client_socket, client_address = server_socket.accept()
            print(f"Client accepted connection from {client_address}")

            # Procesar el mensaje según sea necesario
            threading.Thread(target=handle_client, args=(client_socket, private_key)).start()

    except Exception as e:
        print(f"Error listening for messages: {e}")


if __name__ == "__main__":
    # Iniciar un hilo para escuchar mensajes entrantes
    threading.Thread(target=listen_for_messages, args=(private_key,)).start()
    # Obtener información del mensaje a enviar
    origin_node = "10.0.0.1"
    destination_node = input("Enter destination node: ")
    message_type = input("Enter message type (user_message or audio_message): ")

    if message_type == "user_message":
        message = input("Enter message: ")
        send_message(origin_node, destination_node, message, public_key)
    elif message_type == "audio_message":
        audio_file = "Bye_Bye.wav"  # Cambiar al nombre de tu archivo de audio
        send_message(origin_node, destination_node, audio_file, public_key, message_type="audio_message")
    else:
        print("Invalid message type. Please enter 'user_message' or 'audio_message'.")

    while True:
        time.sleep(1)

