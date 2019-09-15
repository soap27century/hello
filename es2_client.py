import asyncio

flagcount=0

class EchoClient(asyncio.Protocol):
	def __init__(self):
		pass

	def connection_made(self, transport):
		self.transport = transport

	def data_received(self, data):
		global flagcount
		print(data)
		data=data.decode()
		data=data.split('<EOL>')
		if flagcount==0:
			for i in data:
				isp=i.split('\n')
				isp=' '.join(isp)
				print(isp)
				if 'autograde' in isp:
					self.transport.write("SUBMIT,Haoshuai Ding,dhaoshu1@jhu.edu,7,1810<EOL>\n".encode())
				if ('TEST' in isp) and ('OK' in isp):
					self.transport.write("look<EOL>\n".encode())
					flagcount=1
		else:
			listcom=['look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n','open chest<EOL>\n','get hammer in chest<EOL>\n','unlock door with hairpin<EOL>\n','open door<EOL>\n']
			if flagcount-1<len(listcom):
				self.transport.write(listcom[flagcount-1].encode())
				flagcount+=1
			else:
				print(data)
					

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52',19003)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass
	#client.close()
	#loop.run_until_complete(client.close())
	#loop.run_forever()
	
	loop.close()
