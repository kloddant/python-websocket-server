import socket
import threading
import hashlib
import base64
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from SocketServer import ThreadingMixIn, TCPServer, StreamRequestHandler, BaseRequestHandler
import struct
from textwrap import dedent
import datetime
import json
import cgi

SECRET_KEY = "12345"
DEFAULT_PRIVACY = ["public", "private"][0]

# http://stackoverflow.com/questions/4685217/parse-raw-http-headers
class HttpRequest(BaseHTTPRequestHandler):

	def __init__(self, request_text):
		self.rfile = StringIO(request_text)
		self.raw_requestline = self.rfile.readline()
		self.error_code = self.error_message = None
		self.parse_request()

	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message

# http://stackoverflow.com/questions/10237926/convert-string-to-list-of-bits-and-viceversa
def string_to_bitlist(s):
	result = []
	for c in s:
		bits = bin(ord(c))[2:]
		bits = '00000000'[len(bits):] + bits
		result.extend([int(b) for b in bits])
	return result

def bitlist_to_string(bitlist):
	chars = []
	for b in range(len(bitlist) / 8):
		byte = bitlist[b*8:(b+1)*8]
		chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
	return ''.join(chars)

# http://stackoverflow.com/questions/12461361/bits-list-to-integer-in-python
def bitlist_to_int(bitlist):
	out = 0
	for bit in bitlist:
		out = (out << 1) | bit
	return out

def keys_in_dict(keys, dict):
	if all (k in dict for k in keys):
		return True
	else:
		return False

class WebSocketAPI:

	def handle_data(self, handler, data):
		print "Handling data..."
		socket = handler.request
		address = handler.client_address
		ip = address[0]
		port = address[1]
		data = json.loads(cgi.escape(data))
		secret_key = False

		if 'secret_key' in data and data['secret_key'] != SECRET_KEY:
			return
		if 'secret_key' in data and data['secret_key'] == SECRET_KEY:
			secret_key = data['secret_key']
		if ip in self.banned_ips:
			return
		if not 'function' in data:
			return
		if not 'callback' in data:
			data['callback'] = ""

		function = data['function']

		if function == "send_message" and keys_in_dict(['message', 'recipient_ids'], data):
			self.send_message(handler, ip, port, data['recipient_ids'], data['message'], data["callback"])
		elif function == "retrieve_clients":
			self.retrieve_clients(socket, ip, secret_key, data["callback"])
		elif function == "set_custom_variables":
			self.set_custom_variables(handler, data["custom_variables"], data["callback"])
		elif function == "set_privacy" and 'privacy' in data:
			self.set_privacy(handler, data['privacy'], data["callback"])
		elif function == "block_ip" and "ip" in data:
			self.block_ip(handler, data['ip'], data["callback"])
		elif function == "ban_ip" and keys_in_dict(['ip', 'secret_key'], data):
			self.ban_ip(socket, data["ip"], data["callback"])

	def send_message(self, handler, ip, port, recipient_ids, message, callback):
		print "Sending message..."
		client = self.handler_to_client(handler)
		sender = {"id": client["id"], "ip": ip, "port": port, "custom": client["custom"]}
		for recipient_id in recipient_ids:
			recipient_id = str(recipient_id)
			if recipient_id not in self.clients:
				continue
			recipient = self.clients[recipient_id]
			if ip not in recipient["blocked"] and (ip in recipient["allowed"] or recipient["privacy"] == "public"):
				socket = recipient["handler"].request
				outgoing_data = json.dumps({"function":"send_message", "sender": sender, "message": message})
				self.send(socket, outgoing_data)
		response = json.dumps({"function": "send_message", "sender": sender, "message": message, "callback": callback})
		self.send(handler.request, response)
		print response

	def retrieve_clients(self, socket, ip, secret_key, callback):
		print "Retrieving clients..."
		clients = {}
		for client_id, client in self.clients.iteritems():
			if ((client["privacy"] == "public" or ip in client["allowed"]) and not ip in client["blocked"]) or secret_key:
				clients[client_id] = {}
				clients[client_id]["id"] = client["id"]
				clients[client_id]["ip"] = client["ip"]
				clients[client_id]["port"] = client["port"]
				clients[client_id]["custom"] = client["custom"]
		response = json.dumps({"function":"retrieve_clients", "clients": clients, "callback": callback})
		self.send(socket, response)
		print clients
		return clients

	def set_custom_variables(self, handler, custom_variables, callback):
		client = self.handler_to_client(handler)
		for key, value in custom_variables.iteritems():
			client["custom"][key] = value
		response = json.dumps({"function": "set_custom_variables", "callback": callback})
		self.send(handler.request, response)

	def set_privacy(self, handler, privacy, callback):
		if privacy not in ["public", "private"]:
			return
		client = self.handler_to_client(handler)
		if client:
			client["privacy"] = privacy
		response = json.dumps({"function": "set_privacy", "callback": callback})
		self.send(handler.request, response)

	def block_ip(self, handler, ip, callback):
		client = self.handler_to_client(handler)
		if client:
			client["blocked"].append(ip)
		response = json.dumps({"function": "block_ip", "callback": callback})
		self.send(handler.request, response)

	def ban_ip(self, socket, ip, callback):
		self.banned_ips.add(ip)
		response = json.dumps({"function": "ban_ip", "callback": callback})
		self.send(socket, response)


class WebSocketServer(ThreadingMixIn, TCPServer, WebSocketAPI):

	global SECRET_KEY
	global DEFAULT_PRIVACY
	client_id_counter = 0
	clients = {}
	banned_ips = set()

	def __init__(self, port=8888, host=socket.gethostbyname(socket.gethostname())):
		print "Initializing..."
		self.port = port
		self.host = host
		TCPServer.__init__(self, (host, port), WebSocketHandler)
		self.ip = self.server_address[0]
		threading.Timer(60, self.remove_expired_clients)
		print "Server initialized at "+str(self.ip)+":"+str(self.port)
		self.serve_forever()

	def add_client(self, handler, address):
		print "Adding client..."
		client = {
			"id": str(self.client_id_counter),
			"handler": handler,
			"ip": address[0],
			"port": address[1],
			"datetime": datetime.datetime.now(),
			"allowed": [], #ip addresses
			"blocked": [], #ip addresses
			"privacy": DEFAULT_PRIVACY,
			"custom": {},
		}
		self.clients[str(self.client_id_counter)] = client
		self.client_id_counter += 1
		print client
		return client

	def send(self, socket, data):
		print "Sending data..."
		frame = bytearray()
		fin = 0x80
		opcode = 0x0f
		mask = 0x80
		payload_data = data.encode('UTF-8')
		payload_length = len(payload_data)
		frame.append(fin | 0x01)

		if payload_length <= 125:
			frame.append(payload_length)
		elif payload_length >= 126 and payload_length <= 65535:
			frame.append(0x7e)
			frame.extend(struct.pack(">H", payload_length))
		else:
			frame.append(0x7f)
			frame.extend(struct.pack(">Q", payload_length))
		frame += payload_data
		socket.send(frame)

	def handler_to_client(self, handler):
		for client_id, client in self.clients.iteritems():
			if 'handler' in client and client['handler'] == handler:
				return client
		return None

	def disconnect(self, handler):
		client = self.handler_to_client(handler)
		if client and client["id"] in self.clients:
			del self.clients[client["id"]]

	def remove_expired_clients(self):
		for client in self.clients:
			if datetime.datetime.now() > client["datetime"] + datetime.timedelta(minutes=10):
				del self.clients[client["id"]]


class WebSocketHandler(StreamRequestHandler):

	keep_alive = True
	handshook = False

	def __init__(self, socket, addr, server):
		self.server=server
		StreamRequestHandler.__init__(self, socket, addr, server)

	def handle(self):
		while self.keep_alive:
			if not self.handshook:
				self.handshake()
			else:
				self.read_message()

	def read_message(self):
		print "Reading message..."
		frame = self.request.recv(1024)

		if not frame:
			self.keep_alive = False
			return

		frame = string_to_bitlist(frame)

		fin = frame[0]
		opcode = hex(bitlist_to_int(frame[4:8]))
		mask = frame[8]
		payload_length = bitlist_to_int(frame[9:16])

		if (payload_length <= 125):
			length = payload_length
			cursor = 16
		elif (payload_length == 126):
			length = bitlist_to_int(frame[16:32])
			cursor = 32
		elif (payload_length == 127):
			length = bitlist_to_int(frame[16:80])
			cursor = 80

		masking_key = bitlist_to_string(frame[cursor:cursor+32])
		cursor = cursor + 32

		payload_data = bitlist_to_string(frame[cursor:cursor+length*8])

		decoded = ""
		if (opcode in [hex(0x0), hex(0x1), hex(0x2)]):
			payload_data_as_hex = bytearray()
			payload_data_as_hex.extend(payload_data)
			masking_key_as_hex = bytearray()
			masking_key_as_hex.extend(masking_key)
			for char in payload_data_as_hex:
				char ^= masking_key_as_hex[len(decoded) % 4]
				decoded += chr(char)
		elif (opcode == 0x9):
			pass
		else:
			self.keep_alive = False
			return

		self.server.handle_data(self, decoded)

		print decoded
		return decoded


	def handshake(self):
		print "Handshaking..."
		data = self.request.recv(1024).decode().strip()
		request = HttpRequest(data)
		key = request.headers['Sec-WebSocket-Key'].encode()
		sec_websocket_accept =  base64.b64encode(hashlib.sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode()).digest()).strip().decode("ASCII")
		
		headers = dedent("""\
			HTTP/1.1 101 Switching Protocols\r
			Upgrade: websocket\r
			Connection: Upgrade\r
			Sec-WebSocket-Accept: %s\r
			\n""") % (sec_websocket_accept,)
		response = headers.encode()

		# self.server and self.client_address are properties of BaseRequestHandler
		self.request.send(response)
		client = self.server.add_client(self, self.client_address)
		self.handshook = True

	# This is a property of BaseRequestHandler
	def finish(self):
		self.server.disconnect(self)
