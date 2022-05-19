# ------------------------- [ Sub Project File | Coding: utf-8 ] -------------------------- #
# Project: EzNet                                                                            #
# File: server.py	                                                                        #
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
import random
import string
import socket
import time
import json
import re

from communication import *
from encryption import *



# Config area.

global SERVER, PORT, FORMAT, HEADER, ADDR, CLIENTLIST
SERVER, PORT, FORMAT, HEADER = socket.gethostbyname(socket.gethostname()), 9090, "utf-8", 64
ADDR = (SERVER, PORT)


def handle_client(conn, addr):
    def directsend(conn=conn):
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
        except:
            raise Exception(301)

        if msg_length:
            try:
                msg_length = int(msg_length)
            except:
                raise Exception(300)
            try:
                receive = conn.recv(msg_length).decode(FORMAT)
            except:
                raise Exception(301)
            try:
                return getdec(receive, key=hash_key)
            except:
                raise Exception(300)
            

    console_log(ip=addr[0], port=addr[1], cpacket="server.client.connect", id=True)

    reply = None
    connected = True
    hash_key=None
    while connected:
        try:
            msg = directsend()
            if msg != None:

                if msg["packagetype"] == "client.getkey":
                    hash_key = fernetgetkey(hash_sha256(randomlet(128)), hash_sha256(randomlet(128)))
                    reply = getenc(packagetype="server.hashkey", message=hash_key)
                    console_log(ip=addr[0], port=addr[1], id=True, cpacket="server.client.getkey", msg=hash_key)

                elif msg["packagetype"] == "client.bot.introduce":
                    print("This is a bot.")


                else:
                    console_log(ip=addr[0], port=addr[1], id=True, cpacket="server.client.message", msg=msg)


        except Exception as e:
            try:
                e = int(str(e)) 
            except:
                e = str(e)

            console_log(ip=addr[0], port=addr[1], id=True, cpacket=e)
            
            if e == 301:
                connected = False
            elif e == 300:
                reply = getenc(packagetype="corrupt.packet", key=hash_key)

        if reply == None:
            reply = getenc(packagetype="no.reply", key=hash_key)
        try:
            conn.send(reply.encode(FORMAT))
        except:
            connected = False
        reply = None



def server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    console_log(cpacket="server.start")

    server.listen()

    console_log(cpacket="server.listen", ip=SERVER)
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

main = True
errortry = 5 
while main:
    try:
        server()
        main = False

    except Exception as e:
        time.sleep(300) if errortry == 0 else None
        errortry -= 1 if errortry != 0 else 0
        print(f"Server failed, [{e}], [{e.__class__}].")
        time.sleep(5)
