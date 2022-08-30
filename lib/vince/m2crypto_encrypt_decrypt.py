"""
M2Crypto based encrypt and decrypt routines that helps encrypt
a string using a key and later decrypt it. The key can be binary
it is provided to initialize the class ED in base64 encoded 
format to facilitate random bytes as key like `os.urandom()`
"""
import M2Crypto
import base64

class ED(object):
    """
    This class creates an encryption object using a base64encoded 
    random bytes :base64key: that will be used to create a "key" and "iv" 
    Once initialized successfully with a key, the encrypt and decrypt
    methods can be used to encrypt a plaintext data and decrypt a cyphertext 
    data
    """
    def __init__(self, base64key):
        rawkey = base64.b64decode(base64key)
        self.iv = rawkey[:16]
        self.key = rawkey[16:]

    def encrypt(self, plaintext):
        """
        :param plaintext: 
        :return: ciphertext in hexadecimal form 
        """
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=self.key, iv=self.iv, op=1)
        ciphertext = cipher.update(plaintext.encode()) + cipher.final()
        return ciphertext.hex()

    def decrypt(self, cyphertext):
        """
        :param cyphertext:
        :return: plaintext as str 
        """        
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=self.key, iv=self.iv, op=0)
        plaintext = cipher.update(bytes.fromhex((cyphertext))) + cipher.final()
        return plaintext
