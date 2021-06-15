import socket 		# socket allows to establish connection over the internet
from IPy import IP	# for conversion of domain name to ip

class PortScan():
	banners = []
	open_ports = []
	def __init__(self, target, port_number):
		self.target = target
		self.port_number = port_number


	def scan(self):
		for port in range(1, 82):
			self.scan_port(port)


	def check_ip(self):
		try:
			IP(self.target)
			return(self.target) 	# if user inputs ip address simply returns the ip address
		except ValueError:
			return socket.gethostbyname(self.target)		# if user inputs domain url then returns the ip address


	def scan_port(self, port):
		try:
			converted_ip = self.check_ip()
			sock = socket.socket() 		# socket descriptor
			sock.settimeout(0.5) 	  # lower the timeout smaller the accuracy but makes the port scanner faster
			sock.connect((converted_ip, port)) 	# will try to connect to the ipaddress and port
			self.open_ports.append(port)
			try: 
				banner = sock.recv(1024).decode().strip('\n').strip('\r')
				self.banners.append(banner)
			except:
				self.banners.append(' ')
			sock.close()
		except:
			pass 	#pass if the port is closed
