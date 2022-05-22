# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: EzNet                                                                            #
# File: communication.py	                                                                #
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
import json

from datetime import datetime
from encryption import *


# Config area.

# Prefix is for the prefix of all log messages.
PREFIX = {
    "error": "[!]",
    "info": "[*]",
    "warning": "[-]",
}

# log_messages is a thing we've created for easily accessing log messages to make it better.
log_messages = {
    "server.client.connect": "Connected.",
    "server.client.disconnect": "Disconnected.",
    "server.client.message": "[{msg}]",
    "server.client.request": "Requesting [{msg}]",
    "server.client.getkey": "Requests key, the key is [{msg}]",
    "server.start": "Server is starting...",
    "server.listen": "Server is listening on {ip};"
}


# 100-199 are for client side, 200-299 are for server side, and 300-399 are for general side errors..

# error_messages is a thing we've created for easily accessing error messages to make it better.
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
    303: "System doesn't have the hask key or the key is wrong."
}


# Socket functions.

# A funtion to log messages to the console.
def console_log(ip=None, port=None, id=None, cpacket=None, packet=None, msg=None):

    prefix = "warning"
    log_msg = ""

    # Try to turn packet into integer if not turn it into string. We can access error messages dict with only integers.
    try:
        cpacket = int(cpacket)
    except:
        cpacket = str(cpacket)

    # Check if the packet is an error packet.
    if cpacket in error_messages:
        prefix = "error"
        log_msg = error_messages[int(cpacket)]

    # Check if the packet is a log message.
    elif cpacket in log_messages:
        prefix = "info"
        log_msg = log_messages[cpacket]

    # IDS is for adding an ip adress to the beginning of a log message to know which client is doing things and so.
    ids = f"[{str(ip)}:{str(port)}] " if id == True else ""
    
    # Generate a date text.
    date = "[" + datetime.today().strftime('%Y-%m-%d') + "] [" + \
        datetime.today().strftime('%H:%M:%S') + "]"

    # Connect strings.    
    premsg = PREFIX[prefix] + " " + date + " "

    # Connect strings.
    end = premsg + ids + log_msg
    
    # Format it.
    end = end.format(prefix=prefix, ip=ip, port=port, packet=packet, msg=msg)

    # Bruh.
    print(end)

# Getenc function is for packaging our messages for easer access.
def getenc(packagetype=None, message=None, ipadress=None, key=None):

    # Turn our dict into string with json.
    message = json.dumps({"packagetype": packagetype, "message": message, "ipadress": ipadress})

    # If there's no key, send a package without encryption, elsewards encrypt it.
    if key == None:
        # Hash them for checking if there's corruptions. I do a second check in TCP protocol because I'M A PSYCHOPATH AS I SAID BEFORE.
        return encode64(encode64(hash_CRC32(message)) + "_" + encode64(message))
    else:
        # Encrypt it bro.
        return encode64(encode64("encrypted.packet") + "_" + encode64(fernetencrypt(key, message)))
    
    # Fuck you, "getenc" function won't return anything you stupid bastard.

# "getdec" function is for unpacking our messages.
def getdec(msg, key=None):

    # Adding try to check if the hash is wrong or the messasge is corrupted.
    try:

        # Unpack base64 encrypted strings.
        msg = [decode64(i) for i in decode64(msg).split("_")]

        # Split our message into header and main packet variables.
        header_packet, main_packet = msg[0], msg[1]

        # Check if it's an encrypted package or not.
        if header_packet == "encrypted.packet":

            # Adding try to check if the key is wrong or the messasge is corrupted. 
            # Ain't adding hash control on encrypted packages because RSA already does it for us :) .
            try:
                # Decrypt it.
                return json.loads(fernetdecrypt(key, main_packet))
            except:
                # If it's wrong, return an error.
                raise Exception(300)

        # If it's a normal message, just check the hash.
        elif header_packet == hash_CRC32(main_packet):
            # Return the message.
            return json.loads(main_packet)
        else:
            raise Exception(300)
    except:
        raise Exception(300)
