# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: EzNet                                                                            #
# File: client.py	                                                                        #
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

from pickle import NONE
import subprocess
import threading
import socket
import time
import uuid

from communication import *
from encryption import *


# Config area. socket.gethostbyname(socket.gethostname())

global SERVER, PORT, FORMAT, HEADER, HASH_KEY, ADDR
SERVER, PORT, FORMAT, HEADER, HASH_KEY = "xn--tea.space", 9090, "utf-8", 64, None
ADDR = (SERVER, PORT)


def send(client=None, packagetype=None, message=None, ipadress=None):
    def directsend(client=client, packagetype=packagetype, message=message, ipadress=ipadress):
        
        message = getenc(packagetype=packagetype, message=message, ipadress=ipadress, key=HASH_KEY)
        send_length = str(len(message.encode(FORMAT))).encode(FORMAT) + b' ' * (HEADER - len(str(len(message.encode(FORMAT))).encode(FORMAT)))

        try:
            client.send(send_length)
            client.send(message.encode(FORMAT))
        except:
            raise Exception(301)

        try:
            receive = client.recv(2048).decode(FORMAT)
        except:
            raise Exception(301)

        try:
            receive = getdec(receive, key=HASH_KEY)
            if receive["packagetype"] == "corrupt.packet":
                print("corrupted idiot bitch.")
                raise Exception(300)
            return receive
        except Exception as e:
            raise Exception(e)
    trysend = True
    while trysend:
        try:
            result = directsend()
        except Exception as e:
            try:
                e = int(str(e)) 
            except:
                e = str(e)
            result = e
        if result == 301:
            raise Exception(f"Connection error, {result}.")
        elif result == 300:
            return result
        else:
            return result
    return False
  
  
def client():

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    global HASH_KEY
    HASH_KEY = (send(client=client, packagetype="client.getkey"))["message"]

    mac_adress = (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]))

    print(mac_adress)

    for i in range(100000):
        send(client=client, packagetype="client.message", message=randomlet(1024))
        time.sleep(0.1)





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
        