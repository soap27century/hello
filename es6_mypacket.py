from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING
import playground

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = 'es6.gamecommand'# whatever you want
    DEFINITION_VERSION = '1.0'# whatever you want

    FIELDS = [
        ("commandd", STRING)
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(commandd=s)
    
    def command(self):
        return self.commandd
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = 'es6.gameresponse'# whatever you want
    DEFINITION_VERSION = '1.0'# whatever you want

    FIELDS = [
        ('gameresponse',STRING),
        ('statusgame',STRING)
    ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(gameresponse=response,statusgame=status)
    
    def game_over(self):
        return self.statusgame in ['escaped','dead'] # whatever you need to do to determine if the game is over
    
    def status(self):
        return self.statusgame# whatever you need to do to return the status
    
    def response(self):
        return self.gameresponse# whatever you need to do to return the response

if __name__=="__main__":
    lm=GameCommandPacket.create_game_command_packet('sa')
    #lm.commandd='fg'
    ls=GameResponsePacket.create_game_response_packet('b','ve')
    #ls=GameCommandPacket()statusgame
    #ls.commandd='fgerwr'
   # print(GameResponsePacket.response(lm))
    h=ls.status
    print(lm.commandd, ls.game_over(),h())
    pp=b'\x00\x00\x00\x00\x00\x00\x00.\xff\xff\xff\xff\xff\xff\xff\xd1\x0fes6.gamecommand\x031.0\x00\x01\x00\x00\x00\x04look'
    dd1=GameCommandPacket.Deserializer()
    dd1.update(pp)
    for recvpack in dd1.nextPackets():
        if recvpack.commandd=='':
            print('DDDD')
        print(recvpack.commandd)


