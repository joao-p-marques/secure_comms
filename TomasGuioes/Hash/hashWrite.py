from cryptography.hazmat.primitives import hashes
import sys
import hashlib

def hashContents(origin, hashType):
    #Readfile
    try:
        with open(origin, 'rb') as f:
            texto = f.read()

    except:
        print("Invalid file.")
        sys.exit(0)

    #SHA-1
    if hashType=="1":
        data = hashlib.sha1(texto).hexdigest()
        with open("hashSHA1.txt", 'w+') as f:
            f.write(data)
        print(data)
    
    #SHA-2 256 bits
    elif hashType=="2":
        data = hashlib.sha256(texto).hexdigest()
        with open("hashSHA256.txt", 'w+') as f:
            f.write(data)
        print(data)

    #SHA-2 384 bits
    elif hashType=="3":
        data = hashlib.sha384(texto).hexdigest()
        with open("hashSHA384.txt", 'w+') as f:
            f.write(data)
        print(data)

    #SHA-2 512 bits
    elif hashType=="4":
        data = hashlib.sha512(texto).hexdigest()
        with open("hashSHA512.txt", 'w+') as f:
            f.write(data)
        print(data)

    #MD5 
    elif hashType=="5":
        data = hashlib.md5(texto).hexdigest()
        with open("hashMD5.txt", 'w+') as f:
            f.write(data)
        print(data)

    else:
        print("Hash type invalid, try again.")



menu = "Hash? \n(1) - SHA-1\n(2) - SHA-2 (256bits)\n(3) - SHA-2 (384bits)\n(4) - SHA-2 (512bits)\n(5) - MD5\n-> "

typeHash = input(menu)
filename = input("\nNome ficheiro? -> ")

hashContents(filename,typeHash)