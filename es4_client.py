import socket, asyncio
import random, sys, time


class EchoClient(asyncio.Protocol):	
	def __init__(self):
		self.escapestep=['look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n',
							'open chest<EOL>\n','get hammer in chest<EOL>\n','hit flyingkey with hammer<EOL>\n',
							'get key<EOL>\n','unlock door with key<EOL>\n','open door<EOL>\n']
		self.sad=0;
		self.sad2=5;
		self.fla=0;

	def connection_made(self, transport):
		self.transport = transport

	def data_received(self, data):
		print(data)
		data=data.decode()
		data=data.split('<EOL>\n')
		if self.fla==0:
			for line in data:
				if line!='':
					seli=line.split(' ')
					if 'autograde' in seli:
						self.transport.write("SUBMIT,chengsiyang,soap27century@jh.edu,7,3925<EOL>\n".encode())
						return
					if ('SUBMIT' in seli) and ('OK' in seli):
						self.fla=1;
						return
		if self.sad<len(self.escapestep):
			if self.sad!=self.sad2:
					self.transport.write(self.escapestep[self.sad].encode())
					self.sad+=1
			else:
				for line in data:
					if line!='':
						seli=line.split(' ')
						if (seli[-1]=='wall'):
							self.transport.write(self.escapestep[self.sad].encode())						
							self.sad+=1
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