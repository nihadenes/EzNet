# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: EzNet                                                                            #
# File: encryption.py	                                                                    #
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

# Casual importances.
import hashlib
import random
import string
import base64
import zlib

# RSA encryption modules.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# Functions for encrypting and hashing.

# For encrypting strings with Base64. Base64 is a form of encryption.
def encode64(encde):
    # Stripping "=" because I'm a psyco.
    return base64.b64encode(encde.encode("utf-8")).decode("utf-8").strip("=")

# For decrypting strings with Base64. Base64 is a form of encryption.
def decode64(decde):
    # Add try if the string is not decodeable, not to give an error.
    try:
        # Returning the decoded string.
        return base64.b64decode(get64(decde).encode("utf-8")).decode("utf-8")
    except:
        # Return false if the string is not decodeable.
        return False

# For checking if a string is Base64.
def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except:
        return False

# Get64 is for checking how many "=" were there in the encoded string.
def get64(string):
    try:
        return string + "=" * [isBase64(string + x) for x in ["", "=", "=="]].index(True)
    except:
        return False

# SHA256 is a hashing algorithm.
def hash_sha256(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode("utf-8")).hexdigest()
    return sha_signature

# CRC32 is a hashing algorithm.
def hash_CRC32(hash_string):
    return hex(zlib.crc32(hash_string.encode("utf-8"))% 2**32)[2:]

# Function for encrypting strings with AES.
def fernetencrypt(key, string):
    try:
        return Fernet(key.encode("utf-8")).encrypt(string.encode("utf-8")).decode("utf-8")
    except:
        return False

# Function for decrypting strings with AES.
def fernetdecrypt(key, string):
    try:
        return Fernet(key.encode("utf-8")).decrypt(string.encode("utf-8")).decode("utf-8")
    except:
        return False
    
# Function for getting a key for AES encryption.
def fernetgetkey(password, salt):
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=hash_sha256(hash_sha256(salt)).encode("utf-8"),
                   iterations=100000,
                   backend=default_backend()).derive(hash_sha256(hash_sha256(password)).encode())).decode("utf-8")


# Useful functions.

# Creates randomized strings.
def randomlet(lentgth):
    return ''.join(random.choice(string.ascii_letters) for i in range(lentgth))

# Turns a text into seperated lines.
def paragraph(string, liner):
    return [string[i:i + liner] for i in range(0, len(list(string)), liner)]