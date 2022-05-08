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
from datetime import datetime



# Config area.

global SERVER, PORT, FORMAT, PREFIX, HEADER, ADDR
SERVER, PORT, FORMAT, HEADER = socket.gethostbyname(socket.gethostname()), 9090, "utf-8", 64
ADDR = (SERVER, PORT)

PREFIX = {
    "error": "[!]",
    "info": "[*]",
    "warning": "[-]",
}

log_messages = {
    "server.client.connect": "[{ip}][{port}] Connected.",
    "server.client.disconnect": "[{ip}][{port}] Disconnected.",
    "server.client.client.message": "[{ip}][{port}] [{packet}] [{msg}]",
    "server.client.request": "[{ip}][{port}] Requesting [{msg}]",
    "server.client.getkey": "[{ip}][{port}] Requests key, the key is [{msg}]",
    "server.start": "Server is starting...",
    "server.listen": "Server is listening on {ip};"
}


# 100-199 are for client side, 200-299 are for server side, and 300-399 are for general side errors..

error_messages = {
    100: "Client sent corrupt packet.",
    101: "Client got disconnected.",
    102: "Client sent a request that is not supported.",
    103: "Client sent so many fucking packets.",

    200: "Server error.",
    201: "Server sent corrupt packet.",
    202: "Server got disconnected.",

    300: "Corrupt packet.",
    301: "Connection lost.",
    302: "Connection failed.",
    303: "Hash is incorrect.",
    304: "Message is corrupted."
}


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
    except:
        return False


def fernetdecrypt(key, string):
    try:
        return Fernet(key.encode("utf-8")).decrypt(string.encode("utf-8")).decode("utf-8")
    except:
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

def getenc(packagetype=None, message=None, ipadress=None, key=None):
    message = json.dumps({"packagetype": packagetype, "message": message, "ipadress": ipadress})
    if key != None:
        return encode64(encode64("encrypted.packet") + "_" + fernetencrypt(key, json.dumps(message)))
    else:
        return encode64(encode64(hash_sha256(message)) + "_" + encode64(message))


def getdec(msg, key=None):
    try:
        if key != None:
            msg = fernetdecrypt(key, msg)
            return json.loads(msg)
        else:
            msg = decode64(msg)
            hash, msg = decode64(msg.split("_")[0]), decode64(msg.split("_")[1])
            if hash == hash_sha256(msg):
                return json.loads(msg)
            else:
                raise Exception(303)
    except:
        raise Exception(304)


def console_log(ip=None, port=None, cpacket=None, packet=None, msg=None, prefix="info"):
    date = "["  + datetime.today().strftime('%Y-%m-%d') + "] [" + datetime.today().strftime('%H:%M:%S') + "]"
    end = PREFIX[prefix] + " " + date + " " + log_messages[cpacket].format(prefix=prefix, ip=ip, port=port, packet=packet, msg=msg)
    print(end)


def send(client=None, packagetype=None, message=None, ipadress=None):
    def directsend(client=client, packagetype=packagetype, message=message, ipadress=ipadress):

        message = getenc(packagetype=packagetype, message=message, ipadress=ipadress)
        send_length = str(len(message.encode(FORMAT))).encode(FORMAT) + b' ' * (HEADER - len(str(len(message.encode(FORMAT))).encode(FORMAT)))

        try:
            client.send(send_length)
            client.send(message.encode(FORMAT))
        except:
            return "connection_error"

        try:
            receive = client.recv(2048).decode(FORMAT)
        except:
            return "connection_error"

        try:
            return getdec(receive)
        except:
            return "message_corrupted"

    tries = 9999999
    while tries > 0:
        tries -= 1 if tries != 0 else 0
        result = directsend()
        if result == "connection_error" or result == "client_side_error":
            raise Exception(f"Connection error, {result}.")
        elif result == "message_corrupted":
            pass
        else:
            return result
    return False


def client():

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    hash_key = send(client=client, packagetype="client.getkey")
    print(hash_key["message"])


main = True
errortry = 5
while main:
    try:
        client()
        main = False
    except Exception as e:
        time.sleep(300) if errortry == 0 else None
        errortry -= 1 if errortry != 0 else 0
        print(f"Client failed, [{e}], [{e.__class__}].")
        time.sleep(5)
