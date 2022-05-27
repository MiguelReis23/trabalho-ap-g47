#!/usr/bin/python3

import os
import sys
import socket
import json
import base64
from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES

# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue (cipherkey, data):
	cipher = AES.new(cipherkey, AES.MODE_ECB)
	dataenctypted= cipher.encrypt(bytes("%16d"%(data), "utf-8"))
	dataenctyptedtosend= base64.b64encode(dataenctypted)
	return str(dataenctyptedtosend, "utf-8")


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue (cipherkey, data):
	cipher= AES.new(cipherkey, AES.MODE_ECB)
	datadecrypted= base64.b64encode(data)
	datadecrypted= cipher.decrypt(bytes(datadecrypted))
	return int(str(datadecrypted, "utf-8"))


# verify if response from server is valid or is an error message and act accordingly
def validate_response (client_sock, response):
	if "error" in response:
		print ("Error: %s" % (response["error"]))
		client_sock.close ()
		sys.exit (3)


# process QUIT operation
def quit_action (client_sock):
	response = sendrecv_dict (client_sock, {"op": "QUIT"})
	if "error" in response:
		print ("Error: %s" % (response["error"]))
	client_sock.close ()
	sys.exit (4)


# Outcomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP" }
#
# Incomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, min, max }


#
# Suporte da execução do cliente
#
def run_client (client_sock, client_id):
	result= sendrecv_dict (client_sock, {"op": "START", "client_id": client_id})
	print(result)
	result1 = sendrecv_dict(client_sock, { "op": "NUMBER", "number": 10 })
	result2 = sendrecv_dict(client_sock, { "op": "NUMBER", "number": 12 })
	result3 = sendrecv_dict(client_sock, { "op": "NUMBER", "number": 15 })
	print(result1)
	print(result2)
	print(result3)
	result5= sendrecv_dict (client_sock, {"op": "QUIT"})
	print(result5)
	result4 = sendrecv_dict(client_sock, { "op": "STOP" })
	print(result4)

 
 
def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error
	if client_id <1:
		print ("Error: client_id is not defined")
		sys.exit (1)
	client_id = sys.argv[1]
	port = int(sys.argv[2])
	hostname = sys.argv[3] if len(sys.argv) > 3 else "localhost"

	client_sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	client_sock.connect ((hostname, port))

	run_client (client_sock, sys.argv[1])

	client_sock.close ()
	sys.exit (0)

if __name__ == "__main__":
	main()
