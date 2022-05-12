import sys

# Datagram object for parsing input hex stream and calculating checksum
class Datagram:
	ID = 0x11

	def __init__(self, packet):
		if packet[-4:] == ".txt":
			packet = str(open(packet, "r").read())
		self._packetData = []

		indexIP = sys.maxsize
		for i in range(0, len(packet), 4):
			if indexIP == sys.maxsize and packet[i + 2:i + 4] == hex(Datagram.ID)[-2:]:
				indexIP = i + 8
			if i >= indexIP:
				self._packetData.append(int(packet[i:i+4], 16))

		self._msg = DatagramSection("Datagram", len(self._packetData))
		self._msg.add_field(PsuedoHeader(self._packetData))
		self._msg.add_field(Header(self._packetData))
		self._msg.add_field(Payload(self._packetData))

	def calculate_checksum(self):
		operands = []
		for x in self._msg.get_operands():
			operands.extend(x.get_operands())
		return CheckSumCalculator(operands).calc_sum()

	def get_raw_packet_strings(self):
		return list(map(hex, self._packetData))

	def __str__(self):
		str = self._msg.__str__()
		for i in self._msg.get_operands():
			str += i.__str__()
		return str

# datagramSection object allows for dynamic allocation of UDP datagram sections
class DatagramSection:
	def __init__(self, section_name, size):
		self._fields = []
		self._section_name = section_name
		self.SIZE = size

	def cut_packet(self, packet):
		del packet[0:self.SIZE]

	def add_field(self, field):
		if not isinstance(field, list):
			field = [field]
		self._fields.extend(field)

	def get_operands(self):
		return self._fields

	def __str__(self):
		return "~~~ " + self._section_name + " ~~~\n"

#Parses IP Pseudo header from hex Stream
class PsuedoHeader(DatagramSection):
	SIZE = int((12 - 4) / 2)

	def __init__(self, packet_data):
		DatagramSection.__init__(self, "IP Psuedo-Header", PsuedoHeader.SIZE)

		self._sourcePort = packet_data[0:2]
		self._destinationPort = packet_data[2:4]

		self.add_field([*[Datagram.ID], *self._sourcePort, *self._destinationPort])
		self.cut_packet(packet_data)

	def __str__(self):
		return super().__str__() + ("Protocol ID: {0[0]}\n"
				"Source Port: {0[1]} {0[2]}\n"
				"Destination Port: {0[3]} {0[4]}\n").format(list(map(hex, self.get_operands())))

#Parses UDP header from hex stream
class Header(DatagramSection):
	SIZE = int(8 / 2)

	def __init__(self, packet):
		DatagramSection.__init__(self, "UDP Header", Header.SIZE)

		self._sourcePort = packet[0]
		self._destinationPort = packet[1]
		self._lengthUDP = packet[2]

		self.add_field([*[self._lengthUDP], *[self._sourcePort],
						*[self._destinationPort], *[self._lengthUDP]])

		self.cut_packet(packet)

	def __str__(self):
		return super().__str__() + ("Source Port: {0[1]}\n"
				"DestinationPort: {0[2]}\n"
				"UDP Length: {0[3]}\n").format(list(map(hex, self.get_operands())))

# parses UDP payload from hex Stream
class Payload(DatagramSection):
	def __init__(self, packet_data):
		DatagramSection.__init__(self, "UDP Payload", 0)

		self._payload = []
		for x in packet_data:
			self._payload.append(x)

		self.add_field(self._payload)

	def __str__(self):
		return super().__str__() + str(list(map(hex, self.get_operands())))

#performs checksum on UDP datagram parsed by datagram object
class CheckSumCalculator:
	def __init__(self, operands):
		self._packet = operands
		self._sum = self._packet[0]

	def calc_sum(self):
		for x in self._packet[1:]:
			self._sum = self.add_hex(self._sum, x)

		return hex(self.take_ones_compliment())

	@staticmethod
	def add_hex(n1, n2):
		sum = n1 + n2

		while sum >= 0x10000:
			sum %= 0x10000
			sum += 1

		return sum

	def take_ones_compliment(self):
		return 0xffff - self._sum


#instantiate datagram object and call calculate_checksum
def main():
	hex_stream = ("45a00028d545000040114cfba9fe01e9a9fe01ffc7271388001499cb434d44000000001ba9fe01ff")
	if sys.argv[-1] != sys.argv[0]:
		hex_stream = sys.argv[-1]

	packet = Datagram(hex_stream)

	print(packet)
	print(">>> UDP Checksum: " + str(packet.calculate_checksum()))


if __name__ == "__main__":
	main()
