import socket
import sys

# Create a TCP/IP socket and listen on port 10000
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)
sock.listen(1)

# Type: 1 Byte
# States what type of packet this is and what type of information it contained in the packet
# 1-Open, 2-Update, 3-Notification, 4-Keepalive, and 5-Route-Refresh

# Length: 2 Bytes
# Total length of the BPG Message including the BGP headers
# 19 <= Length <= 4096

# Marker: 16-bytes
# Used to authentication BGP
# All ones if there is no auth or if it's an OPEN message

_type = 0b00000001
_length = [0b00000000,  0b00011101]
_marker = []

for i in range(0,16):
	_marker.append(0b11111111)

_version = 0b00000100

_AS = [0b11111101, 0b11110010]
_hold_time = 0
_BID = [10, 10, 10, 10]

_opt_param_len = 0

_opt_params = [] # TLV = 1 Byte, 1 Byte, X Bytes specified by the former 


# def proc_open_sent(data):


def send_open(connection):
	
	unprocessed_fields = [_marker, _length, _type, _version, _AS, _hold_time, _BID, _opt_param_len, _opt_params]
	message = []

	for field in unprocessed_fields:
		
		if type(field) == type(list()):
			[message.append(x) for x in field]
		else:
			message.append(field)
	print(bytes(message))
	connection.sendall(bytes(message))


# Establish a TCP session
connection, client_address = sock.accept()

send_open(connection)

# Recieve OPEN 
# data = connection.recv(4096)

connection.close()
		

