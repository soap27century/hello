#  all tests passed for test_id 3951dc02232243a823e6b1087384045e9f0b2942cb461e5f6ec7abc44c5aa748

# all tests passed for test_id 61216b7d21d5171c684a09fcbccda696037c7d2a2349ea8eb313037343767404

import numpy as np
import binascii
import logging
import asyncio
import time
import math
import sys
import subprocess
import hashlib

import os
sys.path.insert(1,'~/.playground/connectors/crap/')
from itertools import chain
from playground.network.packet import PacketType, FIELD_NOT_SET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER, LIST, STRING
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime,os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from os.path import exists, join
print(os.getcwd())
# from protocol_poop import *

print( __name__)
logger = logging.getLogger("playground.__connector__." + __name__)

CERT_DIR = "/home/student_20194/enayat/final/NetworkSecurityFall2019/labs/lab2/src/milestone2/certs/"
# CERT_DIR = "../certs/"
CERT_FILE = str(CERT_DIR+"ns.crt")
KEY_FILE = str(CERT_DIR+"ns.key")
CSR_FILE = str(CERT_DIR+"csr.pem")

SIGNED_CERT_FILE = str(CERT_DIR+"csr.pem_signed.cert")
SIGNING_KEY_FILE = str(CERT_DIR+"key.pem")


################################
# Packet Definitions:
################################

class CrapPacketType(PacketType):
   DEFINITION_IDENTIFIER = "crap"
   DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
   DEFINITION_IDENTIFIER = "crap.handshakepacket"
   DEFINITION_VERSION = "1.0"
   NOT_STARTED = 0
   SUCCESS     = 1
   ERROR       = 2
   FIELDS = [
       ("status", UINT8),
       ("nonce", UINT32({Optional:True})),
       ("nonceSignature", BUFFER({Optional:True})),
       ("signature", BUFFER({Optional:True})),
       ("pk", BUFFER({Optional:True})),
       ("cert", BUFFER({Optional:True})),
       ("certChain", LIST(BUFFER, {Optional:True}))
   ]

class DataPacket(CrapPacketType):
   DEFINITION_IDENTIFIER = "crap.datapacket"
   DEFINITION_VERSION = "1.0"
   FIELDS = [
        ("data", BUFFER)
    ]
class ErrorPacket(CrapPacketType):
        DEFINITION_IDENTIFIER = "crap.errorpacket"
        DEFINITION_VERSION = "1.0"
        FIELDS = [
           ("message", STRING)
        ]

################################
# Utility functions
################################


def createPacket(packet, *args, **kwargs):
    return packet(*args, **kwargs)

def generateCSR(key):
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
	# Provide various details about who we are.
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
		x509.NameAttribute(NameOID.COMMON_NAME, u"20191.10.20.30"),
	])).sign(key, hashes.SHA256(), default_backend())
	# Write our CSR out to disk.
	with open(CSR_FILE, "wb") as f:
		f.write(csr.public_bytes(serialization.Encoding.PEM))

def getCertFromCSR(key):
	if not os.path.exists(CERT_FILE):
        # print("Key file exists, loading..")
		bashCommand = str("openssl x509 -req -in "+CSR_FILE+" -CA " +SIGNED_CERT_FILE+ " -CAkey "+SIGNING_KEY_FILE+ " -CAcreateserial -out "+CERT_FILE)
	#	print(bashCommand)
		output = subprocess.check_output(['bash','-c', bashCommand])
		# child = pexpect.spawn(bashCommand)
	# child.logfile_read = sys.stdout
		# child.expect('Enter pass phrase*')
		# child.sendline('passphrase')
	# p = subprocess.Popen(['bash','-c', bashCommand], stdin=subprocess.PIPE)
	# out, err = p.communicate(input='passphrase')
	# print('From other process: ' + out)
	return getCertFromFile(CERT_FILE)

# openssl x509 -req -in example.org.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out example.org.crt
def serializeKey(key):
	# print(key)
    return key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(key):
    return load_pem_public_key(key,backend=default_backend())    

def getCertFromFile(CERT_FILE):
	print("Getting certificate signed by root")
	with open(CERT_FILE, "rb") as cert_file:
		print(CERT_FILE)
		cert_bytes = cert_file.read()
	# print("Got cert bytes?")
	cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
	# print("Got cert")
	return cert

def getKeyFromCert(cert):
	return cert.public_key()

def serializeCert(cert):
	return cert.public_bytes(serialization.Encoding.PEM)

def deserializeCert(certBytes):
	return x509.load_pem_x509_certificate(certBytes, default_backend())

def mySign(to_sign,key):
	print(key)
	return (key).sign(
            to_sign, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )

def generatekey():
    if os.path.exists(KEY_FILE):
        print("Key file exists, loading..")
        with open(KEY_FILE, "rb") as key_file:
          private_key = serialization.load_pem_private_key(key_file.read(), password=b'mypassword',backend=default_backend())
    else:
        print("Generating Key Please standby")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        )
        print("key generate..")
        with open(KEY_FILE, "wb") as f:
            f.write(pem)
    print("key generated")
    return private_key

def create_self_signed_cert(key):
	print(key)
	if os.path.exists(CERT_FILE):
		print("Certificate file exists, loading..")
		with open(CERT_FILE, "rb") as cert_file:
			cert_bytes = cert_file.read()
			cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
	else:
		print("Generating certificate")
		subject = issuer = x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, u"20191.9.100.200")
        ])
        # cert = x509.CertificateBuilder().subject_name(
        #     subject
        # ).issuer_name(
        #         issuer
        # ).public_key(
        #         key
        # ).serial_number(
        #         x509.random_serial_number()
        # ).not_valid_before(
        #         datetime.datetime.utcnow()
        # ).not_valid_after(
        #         datetime.datetime.utcnow() + datetime.timedelta(days=100)
        # ).sign(key, hashes.SHA256(), default_backend())
		cert = x509.CertificateBuilder().subject_name(
        	subject
        ).issuer_name(
        	issuer
        ).public_key(
        	key.public_key()
        ).serial_number(
        	x509.random_serial_number()
        ).not_valid_before(
        	datetime.datetime.utcnow()
        ).not_valid_after(
        	datetime.datetime.utcnow() + datetime.timedelta(days=100)
        ).add_extension(
        	x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        	critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

		with open(CERT_FILE, "wb") as f:
			f.write(cert.public_bytes(serialization.Encoding.PEM))
		return cert



################################
# Transport Definition
################################


class CrapTransport(StackingTransport):
    def __init__(self, key, mode=1, *args, **kwargs):
        # aesCipher = Cipher(algorithms.AES(test_key),modes.ECB(),backend = default_backend())
        # self.aesEnc = None
        # self.aesDec = None
        # aesCipher = Cipher(algorithms.AES(key),modes.ECB(),backend = default_backend())
        # self.aesEnc = aesCipher.encryptor()
        # self.aesDec = aesCipher.decryptor()
        print("Transport initialized")
        self.key = key
        self.closed = False
        self.called_close = False
        # m = hashlib.sha256()
        hash1 = hashlib.sha256(key).digest()
        hash2 = hashlib.sha256(hash1).digest()
        hash3 = hashlib.sha256(hash2).digest()

        print(self.key)
        # m.update(self.key)
        # hash1 = m.digest()

        if mode == 1: # Client
	        self.iv = hash1[:12]
	        self.iv_other = hash1[12:24]
        else: 
	        self.iv_other = hash1[:12]
	        self.iv = hash1[12:24]

        # m = hashlib.sha256()
        # m.update(hash1)
        # hash2 = m.digest()
        if mode==1:
        	# print("AESSGCM using enc key")
        	self.encKey = hash2[:16]
        	print(self.encKey)
	        # m = hashlib.sha256()
	        # m.update(hash2)
	        # hash3 = m.digest()
	        self.decKey = hash3[:16]
	        print("CLIENT: dec key - ", self.decKey)
	        print("CLIENT: enc key - ", self.encKey)
	        # print((self.encKey).decode("utf-8"))
	        print(str(self.encKey))

	        self.aesgcmEncrypt = AESGCM(self.encKey)
	        self.aesgcmDecrypt = AESGCM(self.decKey)
	        print("done with str keys.")
        else:
            # print("AESSGCM using dec key")
            self.decKey = hash2[:16]
            # self.aesgcm = AESGCM(str(self.decKey))
            print("SERVER: dec key - ", self.decKey)
            # m = hashlib.sha256()
            # m.update(hash2)
            # hash3 = m.digest()
            self.encKey = hash3[:16]
            print("SERVER: enc key - ", self.encKey)
            self.aesgcmEncrypt = AESGCM(self.encKey)
            self.aesgcmDecrypt = AESGCM(self.decKey)

        print("Done")
        super().__init__(*args, **kwargs)


    # def initializeCipher(self,key):
    #     print("Init cipher")
        # aesCipher = Cipher(algorithms.AES(key),modes.ECB(),backend = default_backend())
        # self.aesEnc = aesCipher.encryptor()
        # self.aesDec = aesCipher.decryptor()
    def write(self, data):
        print("crap write called",self.closed or self.called_close)
        if self.closed or self.called_close:
            return
        aesgcm = AESGCM(self.encKey)
        # print("w_init1")
        # encrypted_data = self.aesEnc.update(data) + self.aesEnc.finalize()
        # ct = aesgcm.encrypt(nonce, data, aad)
        # print(len(self.iv))
        print("Encrypting iv:",self.iv)
        print("Encrypting key:",self.encKey)
        # print(daya)
        encrypted_data = aesgcm.encrypt(nonce=self.iv, data=data, associated_data =None)
        # encrypted_data = self.aesgcmEncrypt.encrypt(self.iv, data, associated_data =None)
        # print("w_init2")
        # increment IV
        # iv = self.iv
        l = len(self.iv)
        temp = int.from_bytes(self.iv, "big") + 1
        # print(temp)
        # print("xyzsdfsdf")
        # x = iv.from_bytes(16, 'big')
        # print("xyzsdfsdf")
        # temp = int(iv.encode('hex'), 16)
        # print(temp)	
        # print("xyz")

        self.iv = temp.to_bytes(l, 'big')
        # self.iv = bytes(int(self.iv) + 1)
        # print("w_init3")
        # signature =  (self.key).sign(
        #     encrypted_data, 
        #     padding.PSS(
        #         mgf=padding.MGF1(hashes.SHA256()),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     ),hashes.SHA256()
        # )
        # print("w_init4")
        datapacket = createPacket(DataPacket, data=encrypted_data)
        self.lowerTransport().write(datapacket.__serialize__())
        print("done writing....")
        # print("crap write dont - poop wite called?") 
        # self.lowerTransport().write(datapacket.__serialize__())

    def close(self):
        print("crap: called close")
        # print("CALLED CLOSE at ", self.seq)
        if self.called_close or self.closed:
            return
        self.called_close = True
        self.closed = True
        self.lowerTransport().close()

    def other_closed(self):
        print("LOWER TRANSPORT CLOSED")
        # no need to wait for anything - other agent isn't listening anymore
        self.closed = True
        self.lowerTransport().close()

    def received(self, seq):
        # TODO: this should always be True, but sometimes seems not to be
        self.stop_qs[seq].put('stop')
        self.acks.add(seq)


################################
# Protocol Definition
################################


class CrapProtocol(StackingProtocol):
    def __init__(self, mode, timeout=3):
        print('NEW Crap', mode, 'MADE')
        super().__init__()
        self.mode = mode

        self.handshake = Handshaker()
        self.buffer = CrapPacketType.Deserializer()

        self.last_received = None
        self.received_data = {}


    def connection_made(self, transport):
        print(self.mode,"Crap connection_made")
        self.transport = transport
       
        if self.mode == "client":
            to_send = self.handshake.initialize()
            self.transport.write(to_send.__serialize__())

        # print("wut")

    def connection_lost(self, exc):
        # assume this gets called with close
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        print("---------------------------------------CRAP-----------------------------------",self.mode,"-------- recieved something")
        print (self.mode,"handsahek completete?",self.handshake.complete)
        self.buffer.update(data)
        # print(data)
        for packet in self.buffer.nextPackets():
            print("here")
            print(self.mode,"handsahek completete?",self.handshake.complete,"packet",packet)
            if isinstance(packet,ErrorPacket):
            	print("Error packet:",packet.message)
            if not self.handshake.complete and isinstance(packet, HandshakePacket):
                print(self.mode, "crap received handshakepacket")
                self.process_handshake(packet)

            elif self.handshake.complete and  isinstance(packet, DataPacket):
                print(self.mode, 'crap got data packet')
                # print(packet.data)
                aesgcm = AESGCM(self.higherProtocol().transport.decKey)
                # print("xxx")
                print("Decrypting iv:",self.higherProtocol().transport.iv_other)
                print("Decrytping key:",self.higherProtocol().transport.decKey)
                # print(packet.data)
                try:
                    print("Try decrypt")
                    aesgcm = AESGCM(self.higherProtocol().transport.decKey)
                    data = aesgcm.decrypt(nonce=self.higherProtocol().transport.iv_other, data=packet.data, associated_data=None)
                except Exception as e:
	                print("Exception decrypt")
	                aesgcm = AESGCM(self.higherProtocol().transport.encKey)
	                data = aesgcm.decrypt(nonce=self.higherProtocol().transport.iv, data=packet.data, associated_data=None)

                # data = self.higherProtocol().transport.aesgcmDecrypt.decrypt(self.higherProtocol().transport.iv_other, packet.data, associated_data =None)
                # print("done?")
                # except Exception as e:
                	# print(e)
                # print("xyz")
                # print(data)
                # self.higherProtocol().transport.iv_other+ = 1
                print(int.from_bytes(self.higherProtocol().transport.iv_other, "big"))
                l = len(self.higherProtocol().transport.iv_other)
                temp = int.from_bytes(self.higherProtocol().transport.iv_other, "big") + 1
                print(temp)
                temp = temp.to_bytes(l, 'big')
                print(temp)
                self.higherProtocol().transport.iv_other = temp[:16]
                print("passsint to higer..")
                self.higherProtocol().data_received(data)

            # elif isinstance(packet, DataPacket):
            #     print(self.mode, 'crap got data packet')
            #     # print(packet.data)
            #     self.higherProtocol().data_received(packet.data)

            elif self.handshake.complete and isinstance(packet, ShutdownPacket):
                print(self.mode, "crap received shutdownpacket")
                self.process_shutdown_packet(packet)

    def process_handshake(self, packet):
        to_send = self.handshake.process(packet)

    
            # # self.higherProtocol().connection_made(
            #     CrapTransport(
            #         lowerTransport=self.transport,key=self.handshake.shared_key
                # ))
            # self.higherProtocol().transport.initializeCipher(self.handshake.shared_key)
            
        # print(to_send)
        if to_send is not None:
            print(self.mode," to send is not none") 
            self.transport.write(to_send.__serialize__())

           
        if self.handshake.complete:
        	if self.mode=="client":
        		print(self.mode,"---------- creating transport and calling connection made")
        		# time.sleep(2)
        		self.higherProtocol().connection_made(
	                CrapTransport(
	                    lowerTransport=self.transport,mode=1,key=self.handshake.shared_key
	                ))
	        else:
	        	print(self.mode," ---------- creating transport and calling connection made")
	        	self.higherProtocol().connection_made(
	                CrapTransport(
	                    lowerTransport=self.transport,mode=2,key=self.handshake.shared_key
	                ))
	        print("connecion made called")


    # def process_data_packet(self, packet):
    #     self.higherProtocol().transport.data_received(packet)
    #     print("sent data packet")

        # if packet.ACK != FIELD_NOT_SET:
        #     if self.higherProtocol().transport.closed or self.higherProtocol().transport.called_close:
        #         if packet.ACK == self.higherProtocol().transport.seq:
        #             # THIS WAS THE SECTION WE NEEDED
        #             print("CORRECT SEQ FINAL DATAPACKET")
        #             self.higherProtocol().transport.other_closed()

        #     else:
        #         print(self.mode, 'treating as ack')
        #         self.higherProtocol().transport.received(packet.ACK)
        #         print("PACKET ack received ", packet.ACK)

        # if packet.data != FIELD_NOT_SET:
        #     print('treating as data')
        #     self.received_data[packet.seq] = packet.data
        #     self.pass_on_data()
        #     print("PACKET sending ack ", packet.seq)
        #     ack_packet = createPacket(DataPacket, ACK=packet.seq)
        #     self.transport.write(ack_packet.__serialize__())


    def process_shutdown_packet(self, packet):
        print(self.mode, 'got shutdownpacket packet')
        self.higherProtocol().transport.data_received(packet)

################################
# Handshaker Definition
################################


class Handshaker(object):
    def __init__(self):
    	# Generate key to sign with
        self.signing_key=generatekey()
        print("key generated")
        # Generate CSR using the key
        csr = generateCSR(self.signing_key)
        print("CSR generated")
        # Use certificate signed by Seth, private key, csr to get a certificate
        self.cert = getCertFromCSR(self.signing_key)


        # print("Done with cert generation")
        
        self.private_key=ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key=self.private_key.public_key()
      
        # self.cert= create_self_signed_cert(self.signing_key)

        self.root_signed_cert = getCertFromFile(SIGNED_CERT_FILE)
        # root_signed_signing_key = getKeyFromCert(root_signed_cert)

        # self.cert= create_self_signed_cert(signed_signing_key)
        # self.signing_key = getKeyFromCert(self.cert)
        # self.signed_cert =  mySign(serializeCert(self.cert),root_signed_signing_key)

        # print("got signed cert")
        self.certChain  = [serializeCert(self.root_signed_cert)]

        # self.nonce = np.random.randint(2**4)
        self.nonce = np.random.randint(0,2**32)
        # self.cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)
        print("Handshake initialze done")
        self.signature =  mySign(serializeKey(self.public_key),self.signing_key)
        self.shared_key=None
        self.complete = False
        self.received_init = False
        self.shared_secret = False
        self.received_key=None


    def initialize(self):
        # self.signature = self.signing_key.sign(self.public_key, hashes.SHA256(), default_backend())
        # private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        # signing_key = generatekey(KEY_FILE)

        # cert = create_self_signed_cert(CERT_FILE)
        # cert = cert.sign(private_key, hashes.SHA256(), default_backend())

        # client_public_key = client_private_key.public_key()
        # client_signature = client_public_key.sign(private_key, hashes.SHA256(), default_backend())
        # print("Handshake initialize called")
        serialized_client_public_key = serializeKey(self.public_key)
        # print("serialed key:",serialized_client_public_key)
        serialized_cert_bytes = serializeCert(self.cert)
        # serialized_cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)

        self.received_init = True
        print(self.certChain)
        # signed_client_public_key = 
        # same_shared_key = peer_private_key.exchange(ec.ECDH(), server_private_key.public_key())
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.NOT_STARTED,
            pk = serialized_client_public_key,
            cert = serialized_cert_bytes,
            signature = self.signature,
            nonce = self.nonce,
            certChain = self.certChain
        )

    def process(self, packet):
        print("Handshake Process")
        if not self.shared_secret:
            # print("shared secret not computed")
            received_public_key = deserializeKey(packet.pk)
            received_cert = deserializeCert(packet.cert)
            received_cert_key = getKeyFromCert(received_cert)
            self.received_key=received_cert_key

        if packet.nonceSignature is not FIELD_NOT_SET:
            # Verify nonce signature
            try:
                # print("Verifying nonce")
                self.received_key.verify(
                    packet.nonceSignature, str(self.nonce).encode(), 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                # print("Nonce not Verified?")
                # print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
           
        # Generate nonce signature
        if self.shared_secret:
            # print("crap Server got second packet")
            print("server handshake completed")
            self.complete=True
            return None

   
        # print(packet.pk)
        if packet.signature is not FIELD_NOT_SET:
            try:
                # print("verifying signature")
                self.received_key.verify(
                    packet.signature, packet.pk, 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                # print("Not Verified?")
                # print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
               
        # print("VERIFYING CERTIFICATE")
        for certBytes in packet.certChain:
        	cert = deserializeCert(certBytes)
        	print(received_cert)
        	received_cert_address = received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value
        	cert_address = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value
        	# print("received cert", received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value)
        	# print("chain cert", cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]._value)
        	if not cert_address.startswith("20194") and not received_cert_address.startswith(cert_address):
        		# print("CA verification failed")
        		return createPacket(HandshakePacket, status=HandshakePacket.ERROR)

        
        # print("nonce Verified. Signing nonce ")
        nonceSignature =  (self.signing_key).sign(
            str(packet.nonce).encode(), 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )
        self.shared_key = self.private_key.exchange(ec.ECDH(), received_public_key)
        self.shared_secret = True
        if self.received_init:
            self.complete=True
            print("client handshake completed")
            return self.send_success(nonceSignature)
        else:
            # print("crap Server got first packet")
            serialized_cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)
            serialized_server_public_key = serializeKey(self.public_key)
            return self.send_key(serialized_server_public_key,serialized_cert_bytes, nonceSignature)
            
     

    def send_key(self, serialized_key,cert_bytes,nonce_signature):
        # print("done3")
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.SUCCESS,
            pk=serialized_key,
            cert=cert_bytes,
            signature=self.signature,
            nonce=self.nonce,
            nonceSignature = nonce_signature,
            certChain = self.certChain
            )

    def send_success(self,nonceSignature):
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.SUCCESS,
            nonceSignature = nonceSignature
        )

# PoopClient= lambda: PoopProtocol(mode="client")
# PoopServer = lambda: PoopProtocol(mode="server")

CrapClient=lambda: CrapProtocol(mode="client")
CrapServer=lambda: CrapProtocol(mode="server") 

