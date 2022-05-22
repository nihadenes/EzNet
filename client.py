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

# Casual importances.
import threading
import socket
import time
import uuid

# Our side libraries for encryption, communication, packaging and unpacking.
from communication import *
from encryption import *

# Global our confşg messages so we can use them in our functions.
# ADDR: The address of the server. 
# FORMAT: The format of the message. ("ascii", "utf-8", "utf-16", "utf-32"...etc)
# HEADER: The header of the message as we send our main message's length to make TCP more reliable.
global ADDR, FORMAT, HEADER
ADDR, FORMAT, HEADER = ("xn--tea.space", 9090), "utf-8", 64

# "send" function is for sending our messages to the server.
def send(client=None, packagetype=None, message=None, ipadress=None, key=None):

    # Function to send data.
    def send_data(client=None, message=None):

        # Adding try to give an error code to the algorithm.
        try:
            # Sending the length of the message to make TCP more reliable.
            send_length = str(len(message.encode(FORMAT))).encode(FORMAT)

            # Completing header message to {HEADER} amount of bits.
            send_length += b' ' * (HEADER - len(str(len(message.encode(FORMAT))).encode(FORMAT)))

            # Send length of the message and the main message.
            client.send(send_length)
            client.send(message.encode(FORMAT))

        except:
            # If there is an error, raise an exception with a specified error code.
            raise Exception(301)

    # Function to receive data.
    def recv_data(client=None):

        # Adding try to give an error code to the algorithm.
        try:
            # Getting the legnth of the message. (Wanted to make the function of getting the header message to be more efficient)
            msg_length = ""

            # Get the message until it fully arrives.
            while len(msg_length) != HEADER:

                # Get the message part by part.
                part = client.recv(HEADER - len(msg_length))

                # Add the message part to the message length.
                msg_length += part.decode(FORMAT)

            # Convert the message length to an integer. (It automatically removes the spaces)
            msg_length = int(msg_length)


            # Get the main message.
            receive = ""

            # Get the message until it fully arrives.
            while len(receive) != msg_length:

                # Get the message part by part.
                part = client.recv(msg_length - len(receive))

                # Add the message part to the message.
                receive += part.decode(FORMAT)

            # Return the message. 
            return receive

        except:

            # If there is an error, raise an exception with a specified error code.
            raise Exception(301)

    # Function for sending our package.
    def send_packet(client=client, packagetype=packagetype, message=message, ipadress=ipadress, key=key):

        # Packaging the data.
        message = getenc(packagetype=packagetype, message=message, ipadress=ipadress, key=key)

        # Send our data.
        send_data(client=client, message=message)

        # Receive reply data from the server.
        receive = recv_data(client=client)

        # Unpackage the data.
        receive = getdec(receive, key=key)

        # Return the data.
        return receive

    # Return our package.
    return send_packet()


# "client" function is for creating our client.
def client():
    # Create a socket client and use TCP protocol.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to our server.
    client.connect(ADDR)

    # Get the session hash key for peer-to-peer encrypted communication.
    hash_key = (send(client=client, packagetype="client.getkey"))["message"]

    # Just send random things for testing.
    for i in range(10000):
        send(client=client, packagetype="client.message", message=randomlet(1000000), key=hash_key)


# Run the client forever, even if there's errors.
while True:
    try:
        # Run the client.
        client()

    except Exception as e:
        print(f"Client failed, [{e}], [{e.__class__}].")
        time.sleep(5)