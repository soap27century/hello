import socket, asyncio
import random, sys, time


class EchoClient(asyncio.Protocol):	
	def __init__(self):
		self.rules=['look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n',
							'open chest<EOL>\n','get hammer in chest<EOL>\n','hit flyingkey with hammer<EOL>\n',
							'get key<EOL>\n','unlock door with key<EOL>\n','open door<EOL>\n']
		self.bg=0;
		self.ed=5;
		self.t=0;

	def connection_made(self, transport):
		self.transport = transport

	def data_received(self, data):
		print(data)
		data=data.decode()
		data=data.split('<EOL>\n')
		if self.t==0:
			for line in data:
				if line!='':
					temp=line.split(' ')
					if 'autograde' in temp:
						self.transport.write("SUBMIT,Weichen Wang,wwang123@jhu.edu,7,3088<EOL>\n".encode())
						return
					if ('SUBMIT' in temp) and ('OK' in temp):
						self.t=1;
						return
		if self.bg<len(self.rules):
			if self.bg!=self.ed:
					self.transport.write(self.rules[self.bg].encode())
					self.bg+=1
			else:
				for line in data:
					if line!='':
						seli=line.split(' ')
						if (temp[-1]=='wall'):
							self.transport.write(self.rules[self.bg].encode())						
							self.bg+=1
							break


if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52',19004)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		loop.close()
	#client.close()
	#loop.run_until_complete(client.close())
	#loop.run_forever()
	
	loop.close()
