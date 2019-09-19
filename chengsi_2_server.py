
import time  
import chengsi_1
import asyncio


class server(asyncio.Protocol):
   
    def connection_made(self,transport):
        peername = transport.get_extra_info("peername")
        print(peername)
        self.transport = transport
        self.game = GM.EscapeRoomGame(output = self.write_func)
        self.game.create_game(cheat=True)
        self.game.start()
        
    def write_func(self,message):
        #socket.send()
        self.transport.write(message.encode())
        print(message)
    
    def data_received(self,message):
        print(message.decode())
        #print(s.recv(1024))
        if self.game.status == "playing":
            #command = input(">> ")
            #self.conn.send(b'>>')
            data = message# this could be multiple messages
            data_as_string = data.decode() # convert from bytes to string
            lines = data_as_string.split("<EOL>\n")
            print(lines)
            for line in lines:
                print(line)
                if line !="":
                    # process each line
                    command = line
                    output = self.game.command(command)
                
                   
        
        
if __name__=="__main__":
    loop = asyncio.get_event_loop()
    ok = loop.create_server(server, '', 6666)
    server = loop.run_until_complete(ok)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_close())
    loop.close()