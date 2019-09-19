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
        temp=0
        if temp==0:
            for i in data:
                t1=i.split('\n')
                t1=' '.join(t1)
                print (t1)
                if 'autograde' in t1:
                    self.transport.write("SUBMIT,Weichen Wang,wwang123@jhu.edu,7,3088<EOL>\n".encode())
                elif ('OK' in t1)and('SUBMIT' in t1):
                    print('hhh')
                    temp=1
                   # print(temp)
                    #self.transport.write("look<EOL>\n".encode())
                else:
                    print(temp)
                    str=['look<EOL>\n','look mirror<EOL>\n','get hairpin<EOL>\n','unlock chest with hairpin<EOL>\n','open chest<EOL>\n','get hammer in chest<EOL>\n','unlock door with hairpin<EOL>\n','open door<EOL>\n']
                    if temp<len(str):
                        temp+=1
                        self.transport.write(str[temp-1].encode())
                        print(str[temp-1])
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


