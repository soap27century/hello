import asyncio,time,playground
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
import queue, os, sys
from autograder_ex6_packets import *
from game_packets import *
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
# sys.path.insert(1, '/Users/enayat/Academics/JHU/SEM5/Network/inClass/Playground3/src/playground/common/')
sys.path.insert(1, '../../Playground3/src/playground/common/')
from CipherUtil import loadCertFromFile

flag=0
testLocally=0

ag_start_packet = AutogradeStartTest()

ag_start_packet.name = "Enayat Ullah"
ag_start_packet.team = 9
ag_start_packet.email = "enayat@jhu.edu"
ag_start_packet.port = 4242
file_name="game_packets.py"
username = "user1"

with open(file_name,"r") as f:
	ag_start_packet.packet_file = str.encode(f.read())

ag_start_packet_bytes = ag_start_packet.__serialize__()

test_id = "43929a54a239bab550c68bbf3ca843ee167774b9d064085732e268fcaa8bd821"
check_status=1


bankconfig = OnlineBankConfig()
if testLocally:
	bank_addr =  "20194.1.1.1"  
	bank_port = 700
	# bank_addr= bankconfig.get_parameter("CLIENT", "bank_addr")
	# bank_port = int(bankconfig.get_parameter("CLIENT", "bank_port"))
	# bank_stack     =     bankconfig.get_parameter("CLIENT", "stack","default")
	# bank_username  =     bankconfig.get_parameter("CLIENT", "username")
	bank_username="user1"
	my_account="account1"
	password="user1"
	certPath = os.path.join(bankconfig.path(), "bank.cert")

# TEST GLOBAL
else:
    bank_addr = '20194.0.0.19000'
    bank_port = 777
    bank_username="mullah3"
    my_account="mullah3_account"
    password="j29%Q*/(xHd6Q>7#56~XK’s_s489-2^P"
    password="random"
    certPath = "../../20194NetworkSecurity/certs/20194_online_bank.cert"


bank_cert = loadCertFromFile(certPath)
bank_client = BankClientProtocol(bank_cert, bank_username, password) 
# print("Bank client works?")

async def example_transfer(bank_client, src, dst, amount, memo):
	print(src)
	print("Initiating transfer")
	client_bank = await playground.create_connection(
    	lambda: bank_client,
    	bank_addr,
    	bank_port,
    	family='default'
    	)
	print("Connected. Logging in.")
	try:
		await bank_client.loginToServer()
	except Exception as e:
		print("Login error. {}".format(e))
		return False

	try:
		await bank_client.switchAccount(src)
	except Exception as e:
		print("Could not set source account as {} because {}".format(src,e))
		return False
	try:
		result = await bank_client.transfer(dst, amount, memo)
	except Exception as e:
		print("Could not transfer because {}".format(e))
		return False
	return result

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
# print(msg_count)
class EchoClient(asyncio.Protocol):
	def __init__(self):
		pass

	def connection_made(self, transport):
		self.transport = transport
		print('connected')
		if check_status:
			transport.write(AutogradeResultRequest(test_id=test_id).__serialize__())
		else:
			transport.write(ag_start_packet_bytes)
			print("Client sends: AutogradeStartTest")
			# transport.write(create_game_init_packet(username))
		self.msgs=['look mirror','get hairpin','unlock chest with hairpin','open chest','get hammer in chest', 'hit flyingkey with hammer','get key','unlock door with key','open door']

		self.count=0
		self.hit=0

	

	def data_received(self, data):
		print("Cleint: recieved something")
		d = PacketType.Deserializer()
		d.update(data)
		packets = d.nextPackets()

		packets_list = list(packets)
		for packet in packets_list:
			print(packet)
			if isinstance(packet,AutogradeTestStatus):
				print("Client receives: test_id = "+str(packet.test_id)+",submit status: "+str(packet.submit_status)+
					", client status: "+str(packet.client_status)+", server status: "+str(packet.server_status))
				print("Sending Bank Packet")
				self.transport.write(create_game_init_packet(bank_username).__serialize__())
				print("sent")
			elif isinstance(packet,PayPacket):
				print("Received pay packet")
				u_id, server_account, amount = process_game_require_pay_packet(packet)
				print("Transfer")
				pay_result = asyncio.ensure_future(example_transfer(bank_client,my_account,server_account,int(amount),u_id))

				def payment_done_callback(pay_result):
					rec_packet = create_game_pay_packet(pay_result.result().Receipt, pay_result.result().ReceiptSignature)
					print(rec_packet)
					self.transport.write(rec_packet.__serialize__())
					print("sent")
				pay_result.add_done_callback(payment_done_callback)

			elif isinstance(packet,GameResponsePacket):
				print("Client recieves Game Response: "+str(packet.res)+"status: "+str(packet.st))
				print(self.count)
				curr_msg=self.msgs[self.count]
				print("Print this:",curr_msg)

				if "hit flyingkey" in curr_msg: 
					if "to the wall" in packet.res:
						print("Client sends: ",curr_msg)
						gr_packet = GameCommandPacket(cmd=curr_msg).__serialize__()
						self.transport.write(gr_packet)
						self.count=self.count+1
						self.hit=1
						time.sleep(0.2)
				else:
					# print("No flyingkey zone")
					print("Client sends: ",curr_msg)
					gr_packet = GameCommandPacket(cmd=curr_msg).__serialize__()
					self.transport.write(gr_packet)
					self.count+=1
					time.sleep(0.2)
				print("Client sent")
		

			elif isinstance(packet,AutogradeResultResponse):
				print("Client recieves: Result Response packet: test_id : "+str(packet.test_id)+", passed?"+str(packet.passed))
			else:
				print("what happened?")			
			




if __name__ == "__main__":
	# EnablePresetLogging(PRESET_DEBUG)
	loop = asyncio.get_event_loop()
	if testLocally:
		coro = playground.create_connection(EchoClient,'localhost',4242)
	else:
		coro = playground.create_connection(EchoClient,'20194.0.0.19000',19007)
	client = loop.run_until_complete(coro)
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass
	loop.run_until_complete(client.close())
	print("client closed")
	loop.close()


