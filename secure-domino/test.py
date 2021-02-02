import socket
import sys
import pickle
import Colors
import string
from deck_utils import Player
import random
from Crypto.Cipher import AES
from asym_keys import *
from ciphers import *
from cryptography.hazmat.primitives import serialization

def pad16Bytes (msg):
    paddingChars=16-len(msg)%16
    paddedMsg=msg
    for i in range(paddingChars):
        paddedMsg=paddedMsg+b'\0'
    return paddedMsg

# Creates a string with 16 bytes padding
def pad16Str (msg):
    paddingChars=16-len(str (msg))%16
    paddedMsg=''.join(['\0' for i in range(paddingChars)])
    return str (msg)+paddedMsg

def sendDataPlayer(msg,player_secret):
    psecret = bytes (pad16Str(str (player_secret)),'utf-8')
    # encrypton with AES and the message needs to be a multiple of 16
    new_msg = bytes(msg)
    iv = 16 * b'\0'
    aes = AES.new(psecret, AES.MODE_CBC, iv)
    encd = aes.encrypt(pad16Bytes(new_msg))
    return encd

def receiveDataPlayer(player_data, player_secret):
    psecret = bytes (pad16Str(str (player_secret)),'utf-8')
    while True:
        #print(msg)
        iv = 16 * b'\0'
        aes = AES.new(psecret, AES.MODE_CBC, iv)
        new_data = aes.decrypt(player_data)
        list_data = list(bytes(new_data))
        return list_data

def sendListData(msg,player_secret):
    psecret = bytes (pad16Str(str (player_secret)),'utf-8')
    # encrypton with AES and the message needs to be a multiple of 16
    iv = 16 * b'\0'
    aes = AES.new(psecret, AES.MODE_CBC, iv)
    encd = aes.encrypt(pad16Bytes(msg))
    return encd

def receive_data_cena_fixe(player_data, player_secret):
    psecret = bytes (pad16Str(str (player_secret)),'utf-8')
    while True:
        #print(msg)
        iv = 16 * b'\0'
        aes = AES.new(psecret, AES.MODE_CBC, iv)
        new_data = aes.decrypt(player_data)
        new_data = new_data.replace(b'\x00', b'')
        return new_data

pl1 = 15

ls = [b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFZKn1lJvNmXK95FUBGwmZ7rb6\nIxrJj8YNXp0antj6gV7DivIkLTnq6eC2oWH9kOF2FFAeLvxLDCZKEQwuipev/om5\nhat6j4Rj7sGyQxqeYDVoKtYmKtAzpzV/yolPEhOxQ4wTWOarAZm9UU+xX+vabkH4\n3weQYMhqZFTqVcBh+wIDAQAB\n-----END PUBLIC KEY-----\n', b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFZKn1lJvNmXK95FUBGwmZ7rb6\nIxrJj8YNXp0antj6gV7DivIkLTnq6eC2oWH9kOF2FFAeLvxLDCZKEQwuipev/om5\nhat6j4Rj7sGyQxqeYDVoKtYmKtAzpzV/yolPEhOxQ4wTWOarAZm9UU+xX+vabkH4\n3weQYMhqZFTqVcBh+wIDAQAB\n-----END PUBLIC KEY-----\n', b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFZKn1lJvNmXK95FUBGwmZ7rb6\nIxrJj8YNXp0antj6gV7DivIkLTnq6eC2oWH9kOF2FFAeLvxLDCZKEQwuipev/om5\nhat6j4Rj7sGyQxqeYDVoKtYmKtAzpzV/yolPEhOxQ4wTWOarAZm9UU+xX+vabkH4\n3weQYMhqZFTqVcBh+wIDAQAB\n-----END PUBLIC KEY-----\n']
ls_enc = []
ls_desenc = []

for i in ls:
    ls_enc.append(sendListData(i, pl1))

print('Lista encriptada: ' + str(ls_enc))


# ls_enc = sendDataPlayer(ls, pl1)
# print(str(ls_enc) + '\n')
for i in ls_enc:
    ls_desenc.append(receive_data_cena_fixe(i, pl1))

print('Lista desencriptada: ' + str(ls_desenc) + '\n')
