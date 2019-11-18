import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_REGEN_KEY = 4

KEY_TTL = 100

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.leftover_file = None
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks

        self.key = None

        #Arrays of possible ciphers to take from
        self.ciphers = ['AES','3DES','ChaCha20']
        self.modes = ['CBC','GCM','ECB']
        self.sinteses = ['SHA-256','SHA-384','SHA-512']

        #Chosen cipher by server
        self.cipher = None
        self.mode = None
        self.sintese = None

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')

        self.state = STATE_OPEN
        self.negotiate_algos()
        
    def negotiate_algos(self):
        #Escolha random de um dos 
        rand = random.randint(1,5)
        # ciphers = []
        # modes = []
        # sinteses = []
        # for i in range(rand+1):
        #     pass

        #Anuncia os modos de cifra que contem
        message = {'type': 'NEGOTIATE', 'ciphers': self.ciphers[:rand], 'modes': self.modes[:rand], 'sinteses': self.sinteses[:rand]}
        self._send(message)

    def finalize_algorithm(self,message) -> None:
        self.cipher = message.get('cipher')
        self.mode = message.get('mode')
        self.sintese = message.get('sintese')

    def open_connection(self) -> None:
        message = {'type': 'OPEN', 'file_name': self.file_name}
        self._send(message)

        self.state = STATE_OPEN

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'MIC':
            mic = base64.b64decode(message.get('mic'))
            msg = message.get('msg')

            if self.hash_mic(json.dumps(msg).encode()) == mic:
                # logger.debug('MIC Accepted')
                message = msg
                mtype = msg.get('type')
            else:
                logger.debug('MIC Wrong. Message compromissed')
                return

        if mtype == 'SECURE_MSG':
            e_data = base64.b64decode(message.get('data'))
            # logger.debug('Received: {}'.format(e_data))
            iv = base64.b64decode(message.get('iv'))
            # print(iv)
            message = self.sym_decrypt(e_data, iv)
            message = json.loads(message.decode())
            mtype = message.get('type', None)

        logger.debug(f"Received (decrypted): {message}")

        if mtype == 'DH_INIT':
            p = message.get('data').get('p')
            g = message.get('data').get('g')
            self.diffie_hellman_gen_Y(p, g)
            logger.info("Sent Key")
            return
        elif mtype == 'DH_KEY_EXCHANGE':
            pub_key = message.get('data').get('pub_key')
            self.get_key(pub_key)
            self.state = STATE_OPEN
            return
        elif mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return
        elif mtype == 'CIPHER_CHOSEN':
            self.finalize_algorithm(message)
            self.open_connection()
            return
        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        # Calculate Hash and attach it to end of file
        # https://docs.python.org/3.5/library/hmac.html
        # https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#cryptography.hazmat.primitives.hashes.HashAlgorithm
        # https://en.wikipedia.org/wiki/HMAC#Implementation
        # with open(file_name, 'ab') as f:
        #    pass

        if self.leftover_file is None:
            logger.info("Openning file")
            self.leftover_file = open(file_name, 'rb')

        file_ended = True
        n_iterations = 0

        message = {'type': 'DATA', 'data': None}
        read_size = 16 * 60
        while True:
            # print("Current Key: %s" % (self.key))
            if n_iterations == KEY_TTL: 
                logger.info(f"Used the same key {KEY_TTL} times, getting a new one.")
                #Aqui damos restart ao processo e alteramos a self.key
                new_message = {'type': 'REGEN_KEY'}
                self.state = STATE_REGEN_KEY

                ##Guardar restos dos conteudos num file
                #f2 = open("tmp/leftover_file","w+")
                #data = f.read()
                #f2.write(base64.b64encode(data).decode())
                #f2.close()
                #self.leftover_file == 'tmp/leftover_file'

                self._send(new_message)
                n_iterations = 0
                file_ended = False
                break

            data = self.leftover_file.read(16 * 60)
            message['data'] = base64.b64encode(data).decode()
            self._send(message)
            n_iterations += 1

            if len(data) != read_size:
                break

        if file_ended:
            self.leftover_file.close()
            self.leftover_file = None
            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        if self.key and self.cipher:
            message_c, iv = self.encrypt_data(json.dumps(message).encode())
            new_message = {
                    'type' : 'SECURE_MSG',
                    'data' : base64.b64encode(message_c).decode(),
                    'iv' : base64.b64encode(iv).decode()
                    }
            mic = self.hash_mic(json.dumps(new_message).encode())
            mic_message = {
                    'type' : 'MIC',
                    'msg' : new_message,
                    'mic' : base64.b64encode(mic).decode()
                    }
            logger.debug("Send: {}".format(mic_message))
            message_b = (json.dumps(mic_message) + '\r\n').encode()
            self.transport.write(message_b)
            return

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)

    def diffie_hellman_gen_Y(self, p, g):
        logger.debug("Starting Diffie-Hellman key exchange.")
        logger.debug("Getting key from params")

        params_numbers = dh.DHParameterNumbers(p,g)
        parameters = params_numbers.parameters(default_backend())

        # self.a = random.randint(1, 10)
        # g = DIFFIE_HELLMAN_AGREED_ALPHA
        # q = DIFFIE_HELLMAN_AGREED_PRIME

        # Y = (g**self.a) % q

        # msg = { 'type' : 'DH_INIT', 'data' : Y }

        # self._send(msg)

        # Generate a private key for use in the exchange.
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        msg = { 'type' : 'DH_KEY_EXCHANGE', 
                'data' : { 
                    'pub_key' : self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
                    }
                }
        self._send(msg)
        return True

    def get_key(self, server_pub_key_b):

        logger.debug("Getting shared key")

        algo = None
        if self.sintese == 'SHA-256':
            algo = hashes.SHA256()
        elif self.sintese == 'SHA-384':
            algo = hashes.SHA384()
        elif self.sintese == 'SHA-512':
            algo = hashes.SHA512()

        server_pub_key = load_pem_public_key(server_pub_key_b.encode(), default_backend())

        shared_key = self.private_key.exchange(server_pub_key)

        length = 32
        if self.cipher == '3DES':
            length = 16

        # Perform key derivation.
        derived_key = HKDF(
            algorithm=algo,
            length=length,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        self.key = derived_key

        logger.debug(f'Got key {self.key}')

    def encrypt_data(self, text):
        iv = None
        if self.cipher == 'ChaCha20':
            iv = os.urandom(16)
            algorithm = algorithms.ChaCha20(self.key, iv)
        elif self.cipher == "3DES":
            algorithm = algorithms.TripleDES(self.key)
        elif self.cipher == "AES":
            algorithm = algorithms.AES(self.key)

        if not self.cipher == 'ChaCha20':
            iv = os.urandom(int(algorithm.block_size / 8))
            if self.mode == 'CBC':
                mode = modes.CBC(iv)
            elif self.mode == "GCM":
                mode = modes.GCM(iv)
            elif self.mode == "ECB":
                iv = None
                mode = modes.ECB()

        if self.cipher == 'ChaCha20':
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            bs = int(algorithm.block_size / 8)
            # print("Block size:", bs) 
            missing_bytes = bs - (len(text) % bs) 
            if missing_bytes == 0:
                missing_bytes = 16
            # print("Padding size:", missing_bytes)
            padding = bytes([missing_bytes] * missing_bytes)
            text += padding

            cipher = Cipher(algorithm, mode, backend=default_backend())

        encryptor = cipher.encryptor()

        cryptogram = encryptor.update(text) + encryptor.finalize()
        # print("Cryptogram:", cryptogram)
        # print('IV:', iv)

        return cryptogram, iv
    
    def sym_decrypt(self, cryptogram, iv=None):
        if self.cipher == 'ChaCha20':
            algorithm = algorithms.ChaCha20(self.key,iv)
        elif self.cipher == "3DES":
            algorithm = algorithms.TripleDES(self.key)
        elif self.cipher == "AES":
            algorithm = algorithms.AES(self.key)

        if self.mode == 'CBC':
            mode = modes.CBC(iv)
        elif self.mode == "GCM":
            mode = modes.GCM(iv)
        elif self.mode == "ECB":
            mode = modes.ECB()

        if self.cipher == 'ChaCha20':
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            cipher = Cipher(algorithm, mode, backend=default_backend())

        decryptor = cipher.decryptor()
        text = decryptor.update(cryptogram) + decryptor.finalize()

        if not self.cipher == 'ChaCha20':
            padding_size = text[-1]
            if padding_size >= len(text):
                raise(Exception("Invalid padding. Larger than text"))
            elif padding_size > int(algorithm.block_size / 8):
                raise(Exception("Invalid padding. Larger than block size"))
            ntext = text[:-padding_size]
        else:
            ntext = text

        # print("Decrypted text:", ntext)

        return ntext

    def hash_mic(self, msg):

        algo = None
        if self.sintese == 'SHA-256':
            algo = hashes.SHA256()
        elif self.sintese == 'SHA-384':
            algo = hashes.SHA384()
        elif self.sintese == 'SHA-512':
            algo = hashes.SHA512()

        digest = hashes.Hash(algo, backend=default_backend())
        digest.update(msg)
        return digest.finalize()

def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()
