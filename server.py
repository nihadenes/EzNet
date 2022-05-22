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

# Casual importances.
import threading
import socket
import time
# Our side libraries for encryption, communication, packaging and unpacking.
from communication import *
from encryption import *

# Global our confşg messages so we can use them in our functions.
# ADDR: The address of the server. 
# FORMAT: The format of the message. ("ascii", "utf-8", "utf-16", "utf-32"...etc)
# HEADER: The header of the message as we send our main message's length to make TCP more reliable.
global ADDR, FORMAT, HEADER
ADDR, FORMAT, HEADER = (socket.gethostbyname(socket.gethostname()), 9090), "utf-8", 64

# Define our handle client function to handle every client differently.
def handle_client(conn, addr):

    # Function to send data.
    def send_data(conn=None, message=None):

        # Adding try to give an error code to the algorithm.
        try:
            # Sending the length of the message to make TCP more reliable.
            send_length = str(len(message.encode(FORMAT))).encode(FORMAT)

            # Completing header message to {HEADER} amount of bits.
            send_length += b' ' * (HEADER - len(str(len(message.encode(FORMAT))).encode(FORMAT)))

            # Send length of the message and the main message.
            conn.send(send_length)
            conn.send(message.encode(FORMAT))

        except:
            # If there is an error, raise an exception with a specified error code.
            raise Exception(301)

    # Function to receive data.
    def recv_data(conn=None):

        # Adding try to give an error code to the algorithm.
        try:
            # Getting the legnth of the message. (Wanted to make the function of getting the header message to be more efficient)
            msg_length = ""

            # Get the message until it fully arrives.
            while len(msg_length) != HEADER:

                # Get the message part by part.
                part = conn.recv(HEADER - len(msg_length))

                # Add the message part to the message length.
                msg_length += part.decode(FORMAT)

            # Convert the message length to an integer. (It automatically removes the spaces)
            msg_length = int(msg_length)


            # Get the main message.
            receive = ""

            # Get the message until it fully arrives.
            while len(receive) != msg_length:

                # Get the message part by part.
                part = conn.recv(msg_length - len(receive))

                # Add the message part to the message.
                receive += part.decode(FORMAT)

            # Return the message. 
            return receive

        except:

            # If there is an error, raise an exception with a specified error code.
            raise Exception(301)

    # Function to listen the client.
    def listen_client(conn=conn):

        receive = recv_data(conn=conn)
        return getdec(receive, key=hash_key)

    # New connection log.
    console_log(ip=addr[0], port=addr[1], cpacket="server.client.connect", id=True)

    # Defining reply here to not to get an error.
    reply = None

    # Defining hash_key here to not to get an error.
    hash_key = None

    # Defining connected for ending the loop after the job is done.
    connected = True

    # While the client is connected.
    while connected:

        # Catch errors to log to the cat eaisly.
        try:
            # Listen for the client and wait for a message.
            msg = listen_client()

            # Process the message.
            if msg["packagetype"] == "client.getkey":

                # Define a random key for safe connection.
                hash_key = fernetgetkey(hash_sha256(randomlet(128)), hash_sha256(randomlet(128)))

                # Prepare the reply to send the key to the client.
                reply = getenc(packagetype="server.hashkey", message=hash_key)

                # Log to the console that client has requested the session key.
                console_log(ip=addr[0], port=addr[1], id=True, cpacket="server.client.getkey", msg=hash_key)

            elif msg["packagetype"] == "client.message":
                    
                    # Log to the console that client has sent a message.
                    console_log(ip=addr[0], port=addr[1], id=True, cpacket="server.client.message", msg=msg)
            del msg

        except Exception as e:

            # Turn exception to an integer to read it.
            try:
                e = int(str(e))

                # Log error to the console.
                console_log(ip=addr[0], port=addr[1], id=True, cpacket=e)
            except:
                e = str(e)


        # Define a reply message if there are no reply messages defined.
        reply = getenc(packagetype="no.reply", key=hash_key) if reply == None else reply
        
        # Adding try to catch error codes to log them.
        try:

            # Send our reply.
            send_data(conn=conn, message=reply)

            # Set reply none to not to send the same reply again.
            reply = None

        except:

            # Close connection if client has already disconnected/lost connectiom.
            connected = False


# Define our server function to make the code more readable.
def server():

    # Define a server socket.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the server on the socket.
    server.bind(ADDR)

    # Log to the console that the server is ready.
    console_log(cpacket="server.start")

    # Start server for listening..    
    server.listen()

    # Inform the console that the server is listening.
    console_log(cpacket="server.listen", ip=ADDR[0])

    # Run the server forever.
    while True:

        # Accept clients and wait for them.
        conn, addr = server.accept()

        # Start a new thread for the client.
        thread = threading.Thread(target=handle_client, args=(conn, addr))

        # Start the thread for the new client.
        thread.start()

# Run the server forever even if there are errors.
while True:

    # Catch errors and log it to the console and continue on the job.
    try:
        server()

    # Except.
    except Exception as e:
        print(f"Server failed, [{e}], [{e.__class__}].")
        time.sleep(5)
