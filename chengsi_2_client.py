import asyncio

flag=0

class EchoClient(asyncio.Protocol):
	def __init__(self):
		pass

	def connection_made(self, transport):
		self.transport = transport

	def data_received(self, data):
		flag=0
		print(data)
		data=data.decode()
		data=data.split('<EOL>')
		if flag==0:
			for i in data:
				isp=i.split('\n')
				isp=' '.join(isp)
				print(isp)
				if 'autograde' in isp:
					self.transport.write("SUBMIT,chengsiyang,soap27century@jhu.edu,7,6666<EOL>\n".encode())
				if ('SUBMIT' in isp) and ('OK' in isp):
					print('hhh')
                    
					#self.transport.write("look<EOL>\n".encode())
					flag=1
		else:
		    
			list=['look<EOL>\n','look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n','open chest<EOL>\n','get hammer in chest<EOL>\n','unlock door with hairpin<EOL>\n','open door<EOL>\n']
			if flag<len(list):
				self.transport.write(list[flag-1].encode())
				flag+=1
				print(list[flag-1])
				print('a')
			else:
				print(data)
				
				print('h')
					

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52',19003)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass
		client.close()
		loop.run_until_complete(client.close())
	loop.close()
