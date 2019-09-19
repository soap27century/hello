import asyncio

class EchoClient(asyncio.Protocol):
	def __init__(self):
		pass

	def connection_made(self, transport):
		self.transport = transport

    def data_received(self, data):
        print(data)
        data=data.decode()
        data=data.split('<EOL>')
        flag=0
        if flag==0:
            for i in data:
                time=i.split('\n')
                time=' '.join(time)
                print (time)
                if 'autograde' in time:
                   self.transport.write("SUBMIT,chengsiyang,soap27century@jhu.edu,7,6666<EOL>\n".encode())
                elif ('OK' in time)and('SUBMIT' in time):
                    print('hhh')
                    flag=1
                   # print(flag)
                    #self.transport.write("look<EOL>\n".encode())
                else:
                    print(flag)
                    str=['look<EOL>\n','look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n','open chest<EOL>\n','get hammer in chest<EOL>\n','unlock door with hairpin<EOL>\n','open door<EOL>\n']
                    if flag<len(str):
                        flag+=1
                        self.transport.write(str[flag-1].encode())
                        print(str[flag-1])
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
