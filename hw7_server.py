"""
Escape Room Core
"""
import sys,os
# sys.path.insert(1,'/Users/enayat/Academics/JHU/SEM5/Network/inClass/BitPoints-Bank-Playground3/src/')
sys.path.insert(1,'../../BitPoints-Bank-Playground3/src/')
# sys.path.insert(1, '/Users/enayat/Academics/JHU/SEM5/Network/inClass/Playground3/src/playground/common/')
import random, asyncio,playground
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
from escape_room_006 import *
from game_packets import *
from autograder_ex6_packets import *
import time
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
from CipherUtil import loadCertFromFile

unique_id="xyzxyzxyzxyzxyzxyzxyz"
amount=7


testLocal = 0
server_ip = 'localhost'
server_port = 4242
bankconfig = OnlineBankConfig()
# TEST LOCALLY
if testLocal:
    bank_addr =  "20194.1.1.1"  
    bank_port = 700
    bank_username="user2"
    my_account="account2"
    password="user2"
    certPath = os.path.join(bankconfig.path(), "bank.cert")
    # bank_addr= bankconfig.get_parameter("CLIENT", "bank_addr")
# bank_port = int(bankconfig.get_parameter("CLIENT", "bank_port"))
# bank_stack     =     bankconfig.get_parameter("CLIENT", "stack","default")
# bank_username  =     bankconfig.get_parameter("CLIENT", "username")

# TEST GLOBAL
else:

    bank_addr = '20194.0.0.19000'
    bank_port = 777
    bank_username="mullah3"
    my_account="mullah3_account"
    password="j29%Q*/(xHd6Q>7#56~XK's_s489-2^P"
    certPath = "../../20194NetworkSecurity/certs/20194_online_bank.cert"

bank_cert = loadCertFromFile(certPath)
bank_client = BankClientProtocol(bank_cert, bank_username, password) 

def example_verify(bank_client, receipt_bytes, signature_bytes, dst, amount, memo):
    print("Verifying receipt")
    if not bank_client.verify(receipt_bytes, signature_bytes):
        raise Exception("Bad receipt. Not correctly signed by bank")
    ledger_line = LedgerLineStorage.deserialize(receipt_bytes)
    if ledger_line.getTransactionAmount(dst) != amount:
        raise Exception("Invalid amount. Expected {} got {}".format(amount, ledger_line.getTransactionAmount(dst)))
    elif ledger_line.memo(dst) != memo:
        raise Exception("Invalid memo. Expected {} got {}".format(memo, ledger_line.memo()))
    return True

class EchoServer(asyncio.Protocol):
    def __init__(self,game):
        self.game=game
        self.gameOff=1
        self.client_username=None


    def connection_made(self, transport):
        time.sleep(0.5)
        self.transport = transport      

    def data_received(self, data):
        print("Server receieves packets")
        d = PacketType.Deserializer()
        d.update(data)
        packets = list(d.nextPackets())
        packet = packets[0]
        print(packet)

        if isinstance(packet, AutogradeStartTest):
            print("SERVER RECIEVES PACKET: AutogradeStartTest packet")
            print("Server sends: test_id  = fake_id")
            self.transport.write(AutogradeTestStatus(test_id="fake_id",submit_status= 1,client_status=1,server_status= 1,error=False).__serialize__())
            
        elif isinstance(packet,BankPacket):
            print("Bank Packet Received")
            self.client_username = process_game_init(packet)
            print(self.client_username)
            print("Sending PayPacket")
            self.transport.write(create_game_require_pay_packet(unique_id, my_account, amount).__serialize__())
            print("Sent")

        elif isinstance(packet,ReceiptPacket):
            print("Receipt Packet Received")
            if example_verify(bank_client, packet.receipt, packet.receipt_signature, my_account, amount, unique_id):
                print("Receipt verified. Starting Game")
                self.game = EscapeRoomGame(output=self.my_send)
                self.game.create_game()
                self.game.start()
                asyncio.ensure_future(self.gameAgents())
                print("Server started the game")
                # self.gameOff=0
                # self.game = EscapeRoomGame(output=self.my_send)
                # self.game.create_game()
                # self.game.start()
                # asyncio.ensure_future(self.gameAgents())
                # print("Server started the game")
            else:
                self.transport.write(GameResponsePacket(res="dead").__serialize__())
        elif isinstance(packet, AutogradeResultRequest):
            print("SERVER RECIEVES PACKET: AutogradeResultRequest")
            print("Server sends: fake_id")
            self.transport.write(AutogradeResultResponse(test_id="fake_id",passed=False).__serialize__())

        elif isinstance(packet, GameCommandPacket):
            print("SERVER RECIEVES PACKET: GameCommandPacket")
            print(str(packet.cmd))
            lines = packet.cmd
            for line in lines.split('<EOL>\n'):
                l = line.strip('<EOL>\n')
                print('SERVER receieves:', l)
                output = self.playGame(l)

    def my_send(self,input):
        # input = input+"<EOL>\n"
        print("Server sends:"+input)
        game_packet = GameResponsePacket(res=input,st=str(self.game.status))
        game_packet_bytes  =game_packet.__serialize__()
        self.transport.write(game_packet_bytes)
        time.sleep(0.1)

    def playGame(self,data):
        if self.game.status == "playing":
            output =  self.game.command(data)

    async def gameAgents(self):
        for a in self.game.agents:
            asyncio.ensure_future(a)

if __name__ == "__main__":
    # EnablePresetLogging(PRESET_DEBUG)
    theGame=None
    loop = asyncio.get_event_loop()
    coro = playground.create_server(lambda: EchoServer(theGame),server_ip,server_port)
    server = loop.run_until_complete(coro)
    print("server started")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.run_until_complete(server.close())
    print("server closed")
    loop.close()