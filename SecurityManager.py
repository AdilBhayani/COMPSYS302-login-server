"""
This file is responsible for managing the encryption and the security of the application.

The file implements functions which allow for encryption and decryption of messages using
XOR, AES and RSA standards.



"""

import hashlib
import binascii
import Crypto.Cipher.XOR
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import Crypto.Random

bs = '16'
login_server_key = '150ecd12d550d05ad83f18328e536f53'
xor_key = '01101001'
Aes_key = '41fb5b5ae4d57c5ee528adb078ac3b2e'
print 'Generating RSA key'
random_generator = Crypto.Random.new().read
Rsa_key = RSA.generate(1024, random_generator)


def RSA_encrypt(enc, receiver_pub_key):
    """
    This function encrypts a string using the receivers public key.
    """
    enc = str(enc)
    receiver_pub_key = RSA.importKey(binascii.unhexlify(receiver_pub_key))
    return binascii.hexlify(receiver_pub_key.encrypt(enc,32)[0])

def RSA_decrypt(enc):
    """
    This function decrypts a string using the users private key.
    """
    return Rsa_key.decrypt(binascii.unhexlify(enc)).encode('utf-8')

def RSA_get_public_key():
    """
    This function allows the mainfile to get the public key to send to the login server.
    """
    return binascii.hexlify(Rsa_key.publickey().exportKey("DER"))


def AES_decryption(enc):
    """
    Performs AES decryption using the globablly declared AES key.
    """
    try:
        enc = binascii.unhexlify(enc)
        iv = enc[:16]
        cipher = AES.new(Aes_key, AES.MODE_CBC, iv )
        return cipher.decrypt(enc[16:]).rstrip(' ')
    except:
        return enc

def AES_encryption(enc,server=False):
    """
    Performs AES encryption using the globablly declared AES key.
    """
    enc = str(enc)
    enc = enc + ((16 - len(enc) % 16) * ' ')
    iv = enc[:16]
    aes_cipher = None
    if server:
        aes_cipher = AES.new(login_server_key, AES.MODE_CBC, iv)
    else:
        aes_cipher = AES.new(Aes_key, AES.MODE_CBC, iv)
    enc = aes_cipher.encrypt(enc)
    return binascii.hexlify(iv + enc)

def xor_encryption(enc):
    """
    Performs XOR encrytion on a string using the global XOR key.
    """
    xor_cipher = Crypto.Cipher.XOR.XORCipher(xor_key)
    enc = xor_cipher.encrypt(unicode(enc))
    return binascii.hexlify(enc)

def xor_decryption(enc):
    """
    Performs XOR decryption on a string using the globabl xor key.
    """
    enc = binascii.unhexlify(enc)
    cipher = Crypto.Cipher.XOR.XORCipher(xor_key)
    return cipher.decrypt(enc)

def encryption_hash_checker(input_dict, file = False):
    """
    Decrypts a message and validates the hash when a message is received.

    Calls decrypter function to decrypt the message then validates the hash.
    """
    if ('encryption' in input_dict and ('encryption' in input_dict and unicode(input_dict['encryption']) != u'0')):
        if ((int(input_dict['encryption']) < 0 or int(input_dict['encryption']) > 3)):
            return ('9: Encryption Standard Not Supported') #Encryption Standard Not Supported
        elif(int(input_dict['encryption']) > 0):
            input_dict = decrypter(input_dict) #Decrypt the message
    
    if ('hashing' in input_dict and ('hash' in input_dict and unicode(input_dict['hashing']) != u'0')):
        if ((int(input_dict['hashing']) < 0 or int(input_dict['hashing']) > 4)):
            return ('10: Hashing Standard Not Supported') #Hashing Standard Not Supported
        elif(int(input_dict['hashing']) > 0):
            if not file:
                if (not (hash_matcher(input_dict['message'],input_dict['hashing'],input_dict['hash'],input_dict['sender']))):
                    return('7: Hash does not match') #Hash does not match
            elif (not (hash_matcher(input_dict['file'],input_dict['hashing'],input_dict['hash'],input_dict['sender']))):
                    return('7: Hash does not match') #Hash does not match
    elif('hashing' in input_dict and unicode(input_dict['hashing']) != u'0' and 'hash' not in input_dict):
        return ('7: No hash provided') #No hash provided
    return None

def get_accepted_parameters(response_list):
    """
    Returns a dictionary specifyingS the highest supported encryption and hashing standard that both users support.
    """
    parameters_dict = {'hashing' : 0, 'encryption' : 0}
    if response_list == None:
        return parameters_dict
    else:
        hashing_list = response_list[len(response_list)-1].split(' ')
        encryption_list = response_list[len(response_list)-2].split(' ')
        if len(hashing_list) > 1 and hashing_list[0].lower().startswith('hashing'):
            try:
                i = len(hashing_list) - 1
                while i > 1:
                    if int(hashing_list[i][0]) < 5:
                        parameters_dict['hashing'] = int(hashing_list[i][0])
                        break
                    i = i - 1
                         
            except:
                pass
        if len(encryption_list) > 1 and encryption_list[0].lower().startswith('encryption'):
            try:
                i = len(encryption_list) - 1
                while i > 1:
                    if int(encryption_list[i][0]) < 3:
                        parameters_dict['encryption'] = int(encryption_list[i][0])   
                        break
                    i = i - 1     
            except:
                pass
        return parameters_dict


def hash_matcher(message, option, the_hash = '', the_username =''):
    """
    Returns True if hashes match or False if they don't.
    """
    try:
        the_username = the_username.encode('ascii')
        hashed_message = None
        if option == u'1':
            hashed_message = unicode(hashlib.sha256(message).hexdigest())          
        elif option == u'2':
            hashed_message = unicode(hashlib.sha256(message+the_username).hexdigest())
        elif option == u'3':
            hashed_message = unicode(hashlib.sha512(message).hexdigest())
        elif option == u'4':
            hashed_message = unicode(hashlib.sha512(message+the_username).hexdigest())
        return hashed_message == the_hash.encode('utf-8')
    except:
        return False

def hash_creator(message,option,the_username=''):
    """
    Creates a hash for the specified message to allow the receiver to verify validatity.
    """
    try:
        the_username = the_username.encode('ascii')
        hashed_message = None
        if option == u'1':
            hashed_message = unicode(hashlib.sha256((message).encode('utf-8')).hexdigest())          
        elif option == u'2':
            hashed_message = unicode(hashlib.sha256((message+the_username).encode('utf-8')).hexdigest())
        elif option == u'3':
            hashed_message = unicode(hashlib.sha512((message).encode('utf-8')).hexdigest())
        elif option == u'4':
            hashed_message = unicode(hashlib.sha512((message+the_username).encode('utf-8')).hexdigest())
        return hashed_message
    except:
        return "Internal error"

def decrypter(input_dict):
    """
    Decrypts the message based on the encryption method number.
    """
    if input_dict.get('encryption') == '1':
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey':
                input_dict[key] = xor_decryption(input_dict[key]) #XOR decryption
    elif input_dict.get('encryption') == '2':
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey':
                input_dict[key] = AES_decryption(input_dict[key]) #AES decryption
    elif input_dict.get('encryption') == '3':
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey':
                input_dict[key] = RSA_decrypt(input_dict[key]) #RSA decryption
    return input_dict

def encryptor(input_dict, public_key):
    """
    Encrypts a message before sending it to the receiver.
    """
    if input_dict.get('encryption') == 1:
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey':
                input_dict[key] = xor_encryption(input_dict[key])
    elif input_dict.get('encryption') == 2:
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey':
                input_dict[key] = AES_encryption(input_dict[key])
    elif input_dict.get('encryption') == 3:
        for key in input_dict:
            if key != 'sender' and key != 'destination' and key != 'encryption' and key != 'decryptionKey' and public_key != None:
                input_dict[key] = RSA_encrypt(input_dict[key], public_key)
    return input_dict