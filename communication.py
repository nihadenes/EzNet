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

import json

from datetime import datetime
from encryption import *


# Config area.

PREFIX = {
    "error": "[!]",
    "info": "[*]",
    "warning": "[-]",
}

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

def console_log(ip=None, port=None, id=None, cpacket=None, packet=None, msg=None):

    prefix = "warning"
    log_msg = ""

    try:
        cpacket = int(cpacket)
    except:
        cpacket = str(cpacket)

    if cpacket in error_messages:
        prefix = "error"
        log_msg = error_messages[int(cpacket)]

    elif cpacket in log_messages:
        prefix = "info"
        log_msg = log_messages[cpacket]

    ids = f"[{str(ip)}:{str(port)}] " if id == True else ""

    date = "[" + datetime.today().strftime('%Y-%m-%d') + "] [" + \
        datetime.today().strftime('%H:%M:%S') + "]"
    premsg = PREFIX[prefix] + " " + date + " "

    end = premsg + ids + log_msg
    end = end.format(prefix=prefix, ip=ip, port=port, packet=packet, msg=msg)

    print(end)


def getenc(packagetype=None, message=None, ipadress=None, key=None):
    message = json.dumps(
        {"packagetype": packagetype, "message": message, "ipadress": ipadress})
    if key == None:
        return encode64(encode64(hash_CRC32(message)) + "_" + encode64(message))
    else:
        return encode64(encode64("encrypted.packet") + "_" + encode64(fernetencrypt(key, message)))


def getdec(msg, key=None):
    try:
        msg = [decode64(i) for i in decode64(msg).split("_")]
        header_packet, main_packet = msg[0], msg[1]
        if header_packet == "encrypted.packet":
            try:
                return json.loads(fernetdecrypt(key, main_packet))
            except:
                raise Exception(300)

        elif header_packet == hash_CRC32(main_packet):
            return json.loads(main_packet)
        else:
            raise Exception(300)
    except:
        raise Exception(300)
