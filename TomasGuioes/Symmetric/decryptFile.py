import getpass
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import DES3,AES
from Crypto.Random import get_random_bytes

def genSymmetricKey(name,pw,salt):
    #switch hashes
    if name=='3DES':
        lenKey = 16
    elif name=='AES-128':
        lenKey = 16
    else:
        lenKey = 32

    password_provided = pw # This is input in the form of a string
    password = password_provided.encode() # Convert to type bytes
    salt = salt # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=lenKey,
        salt=salt,
        iterations=80000,
        backend=default_backend()
    )
    key = kdf.derive(password) # Can only use kdf once
    return key

def decryptFile(key,origin,dest, algorithm):
    #Readfile
    with open(origin, 'rb') as f:
        padded_data = f.read()

    #User nonce here
    if algorithm=='3DES':
        

        iv = os.urandom(8)
        cipher = DES3.new(key, DES3.MODE_CFB, IV=iv)
        msg = cipher.decrypt(padded_data)

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(msg)
        data = data + unpadder.finalize()

        with open(dest, 'wb') as f:
            f.write(data)

    elif algorithm=='AES-128':
        

        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        msg = cipher.decrypt(padded_data)

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(msg)
        data = data + unpadder.finalize()

        with open(dest, 'wb') as f:
            f.write(data)

    #elif algorithm=='ChaCha20':
     #   cipher = ChaCha20.new(key=key)
      #  msg = cipher.encrypt(data)
       # with open(dest, 'wb') as f:
        #    f.write(msg)
    else:
        print("Algorithm Invalid")


p = getpass.getpass()
salt = os.urandom(16)

algo = input('Algoritmo? (3DES/AES-128) ')
key = genSymmetricKey(algo,p,salt)
print("Key: ",key)
decryptFile(key,'encryptedtext.txt','decryptedtext.txt',algo)