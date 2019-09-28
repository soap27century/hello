import socket, asyncio
import random, sys, time


class EchoClient(asyncio.Protocol):	
	def __init__(self):
		self.rules=['look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n',
							'open chest<EOL>\n','get hammer in chest<EOL>\n','hit flyingkey with hammer<EOL>\n',
							'get key<EOL>\n','unlock door with key<EOL>\n','open door<EOL>\n']
		self.tmd=0;
		self.sad=5;
		self.t=0;

	def connection_made(self, transport):
		self.transport = transport

	def data_receivsad(self, data):
		print(data)
		data=data.decode()
		data=data.split('<EOL>\n')
		if self.t==0:
			for line in data:
				if line!='':
					temp=line.split(' ')
					if 'autograde' in temp:
						self.transport.write("SUBMIT,Chengsi Yang,soap27century@163.com,7,6666<EOL>\n".encode())
						return
					if ('SUBMIT' in temp) and ('OK' in temp):
						self.t=1;
						return
		if self.tmd<len(self.rules):
			if self.tmd!=self.sad:
					self.transport.write(self.rules[self.tmd].encode())
					self.tmd+=1
			else:
				for line in data:
					if line!='':
						seli=line.split(' ')
						if (temp[-1]=='wall'):
							self.transport.write(self.rules[self.tmd].encode())						
							self.tmd+=1
							break


if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52',19004)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		loop.close()
	loop.close()
