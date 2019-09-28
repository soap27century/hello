import socket, asyncio
import random, sys, time
import playground
class EchoClient(asyncio.Protocol):	
	def __init__(self):
		self.escapestep=['look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n',
							'open chest<EOL>\n','get hammer in chest<EOL>\n','hit flyingkey with hammer<EOL>\n',
							'get key<EOL>\n','unlock door with key<EOL>\n','open door<EOL>\n']
		self.es_iter=0;
		self.es_itst=5;
		self.fla=0;

	def connection_made(self, transport):
		self.transport = transport
		self.transport.write('<EOL>\n'.encode())

	def data_received(self, data):
		print(data)
		data=data.decode()
		data=data.split('<EOL>\n')
		if self.fla==0:
			for line in data:
				if line!='':
					seli=line.split(' ')
					if 'autograde' in seli:
						self.transport.write("SUBMIT,CHengsiyang,soap27century@163.com,7,6666<EOL>\n".encode())
						return
					if ('SUBMIT' in seli) and ('OK' in seli):
						self.fla=1;
						return
		if self.es_iter<len(self.escapestep):
			if self.es_iter!=self.es_itst:
					self.transport.write(self.escapestep[self.es_iter].encode())
					self.es_iter+=1
			else:
				for line in data:
					if line!='':
						seli=line.split(' ')
						if (seli[-1]=='wall'):
							self.transport.write(self.escapestep[self.es_iter].encode())						
							self.es_iter+=1
							break


if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(EchoClient,'20194.0.0.19000',19005)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		loop.close()
	#client.close()
	#loop.run_until_complete(client.close())
	#loop.run_forever()
	
	loop.close()
