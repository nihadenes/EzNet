# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: SocketEncryption                                                                  #
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

import binascii
import hashlib
import random
import string
import base64
import zlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


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


def hash_CRC32(hash_string):
    return hex(zlib.crc32(hash_string.encode("utf-8"))% 2**32)[2:]


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