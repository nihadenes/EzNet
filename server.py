# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: SocketServer                                                                     #
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

import threading
import hashlib
import random
import string
import base64
import socket
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
        PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=hash_sha256(hash_sha256(salt)).encode("utf-8"), iterations=100000,
                   backend=default_backend()).derive(hash_sha256(hash_sha256(password)).encode())).decode("utf-8")


# Socket functions.

def getenc(packettype=None, message=None, ipadress=None):
    return '("' + '", "'.join([encode64(str(x)) for x in [packettype, message, ipadress]]) + '")'


def getdec(msg):
    return [decode64(x) for x in msg.split('"')[1::2]]


def console_log(ip=None, port=None, cpacket=None, packet=None, msg=None, prefix=None):
    data = json.load(open("console_msg.json", "r") )
    end = data[cpacket].format(prefix=prefix, ip=ip, port=port, packet=packet, msg=msg) if cpacket in data else False
    print(end)
    return end
    

def handle_client(conn, addr):
    console_log(ip=addr[0], port=addr[1], cpacket="client.connect", prefix=PREFIX)

    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            try:
                msg = json.loads(decode64(conn.recv(msg_length).decode(FORMAT)))
            except Exception as e:
                conn.send(f"message.corrupted {e}".encode(FORMAT))
                connected = False

            if msg["packagetype"] == "client.disconnect":
                console_log(ip=addr[0], port=addr[1], cpacket="client.disconnect", prefix=PREFIX)
                connected = False
            else:
                console_log(ip=addr[0], port=addr[1], cpacket="client.message", packet="Message", msg=msg,  prefix=PREFIX)
                
            conn.send("msg.received".encode(FORMAT))

def start():
    server.listen()
    console_log(cpacket="server.listen", ip=SERVER, prefix=PREFIX)
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


try:
    SERVER, PORT, FORMAT, PREFIX, HEADER = socket.gethostbyname(socket.gethostname()), 8080, "utf-8", "[INFO]", 64
    ADDR = (SERVER, PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    console_log(cpacket="server.start", prefix=PREFIX)
    start()
    
    
except Exception as e:
    print(f"An error occured, {e}")
    input()