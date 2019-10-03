from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import  STRING, UINT8, BUFFER# whatever field types you need

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "my_command"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
    ("cmd",STRING)
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(cmd=s)

    def command(self):
        return self.cmd
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "response"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("res",STRING),
        ("st",STRING)
    ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(res=response,st=status)
         # whatever you need to construct the packet )

    def game_over(self):
        if self.st=="dead" or self.st=="escaped":
            return 1# whatever you need to do to determine if the game is 
        else:
            return 0
    def status(self):
        return self.st# whatever you need to do to return the status
    
    def response(self):
        return self.res# whatever you need to do to return the response

class BankPacket(PacketType):
    DEFINITION_IDENTIFIER = "bank"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
    ("username",STRING)
    ]

    @classmethod
    def create_bank_packet(cls, username):
        return cls(username=username)
  

class PayPacket(PacketType):
    DEFINITION_IDENTIFIER = "payment"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
    ("unique_id",STRING),
    ("account",STRING),
    ("amount",UINT8)
    ]

    @classmethod
    def create_game_require_pay_packet(cls,unique_id, account, amount):
        return cls(unique_id=unique_id, account = account, amount = amount)


class ReceiptPacket(PacketType):
    DEFINITION_IDENTIFIER = "reciept"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
    ("receipt",BUFFER),
    ("receipt_signature",BUFFER)
    ]

    @classmethod
    def create_receipt_packet(cls, receipt, receipt_signature):
        return cls(receipt=receipt, receipt_signature=receipt_signature)
    
# Game Command
def create_game_command(command):
    return GameCommandPacket(cmd=command)

def process_game_command(pkt):
    return pkt.cmd

# Game Response
def create_game_response(response, status):
    return GameResponsePacket(res=response,st=status)

def process_game_response(pkt):
    return pkt.res,pkt.st    

# Bank Packet
def create_game_init_packet(username):
    return BankPacket(username=username)

def process_game_init(pkt):
    return pkt.username

# Pay packet
def create_game_require_pay_packet(unique_id, account, amount):
    return PayPacket(unique_id=unique_id, account = account, amount = amount)

def process_game_require_pay_packet(pkt):
    return pkt.unique_id,pkt.account, pkt.amount

# Receipt Packet
def create_game_pay_packet(rec, rec_signature):
    return ReceiptPacket(receipt=rec,receipt_signature=rec_signature)


def process_game_pay_packet(pkt):
    return pkt.receipt, pkt.receipt_signature

