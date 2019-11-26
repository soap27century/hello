# all tests passed for test_id 3951dc02232243a823e6b1087384045e9f0b2942cb461e5f6ec7abc44c5aa748

# all tests passed for test_id 61216b7d21d5171c684a09fcbccda696037c7d2a2349ea8eb313037343767404

import numpy as np
import binascii
import logging
import asyncio
import time
import math
import sys

import os
sys.path.insert(1,'~/.playground/connectors/crap/')
from itertools import chain
from playground.network.packet import PacketType, FIELD_NOT_SET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER
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

from os.path import exists, join
print(os.getcwd())
# from protocol_poop import *

print( __name__)
logger = logging.getLogger("playground.__connector__." + __name__)

CERT_FILE = "ns.crt"
KEY_FILE = "ns.key"



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
       ("cert", BUFFER({Optional:True}))
   ]

class DataPacket(CrapPacketType):
   DEFINITION_IDENTIFIER = "crap.datapacket"
   DEFINITION_VERSION = "1.0"
   FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER)
    ]


################################
# Utility functions
################################

def createPacket(packet, *args, **kwargs):
    return packet(*args, **kwargs)


def serializeKey(key):
    return key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)

def deserializeKey(key):
    return load_pem_public_key(key,backend=default_backend())    

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
        with open(KEY_FILE, "wb") as f:
            f.write(pem)
    print("key generated")
    return private_key

def create_self_signed_cert(key):
    if os.path.exists(CERT_FILE):
        print("Certificate file exists, loading..")
        with open(CERT_FILE, "rb") as cert_file:
            cert_bytes = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    else:
        print("Generating certificate")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com")
        ])
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

async def ensure_write(transport, data, timeout, stopq, timeoutq, wait=2, min_writes=1, seq=None):
    start = time.time()
    writes = 0
    while stopq.empty():
        if writes >= 1:
            print("PACKET resent ", seq, writes, "/", min_writes)
        transport.write(data)
        writes += 1

        if writes >= min_writes and time.time() - start > timeout:
            timeoutq.put('timeout')
            break

        await asyncio.sleep(min({wait, timeout}))



################################
# Transport Definition
################################


class CrapTransport(StackingTransport):
    def __init__(self, key,signing_key, timeout=1, *args, **kwargs):
        # aesCipher = Cipher(algorithms.AES(test_key),modes.ECB(),backend = default_backend())
        # self.aesEnc = None
        # self.aesDec = None
        # aesCipher = Cipher(algorithms.AES(key),modes.ECB(),backend = default_backend())
        # self.aesEnc = aesCipher.encryptor()
        # self.aesDec = aesCipher.decryptor()
        self.key =key
        self.signing_key =signing_key
        self.closed = False
        self.called_close = False

        super().__init__(*args, **kwargs)

    def initializeCipher(self,key):
        print("Init cipher")
        # aesCipher = Cipher(algorithms.AES(key),modes.ECB(),backend = default_backend())
        # self.aesEnc = aesCipher.encryptor()
        # self.aesDec = aesCipher.decryptor()
    def write(self, data):
        print("crap write called",self.closed or self.called_close)
        if self.closed or self.called_close:
            return

        # ct = self.aesEnc.update(data) + self.aesEnc.finalize()
        signature =  (self.signing_key).sign(
            data, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )
        datapacket = createPacket(DataPacket, data=data,signature=signature)
   
        self.lowerTransport().write(datapacket.__serialize__())
        print("crap write dont - poop wite called?") 
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
        print("---------------------------------------CRAP----------------------------------- recieved something")
        self.buffer.update(data)
        # print(data)
        for packet in self.buffer.nextPackets():
            # print("here")
            print(self.mode,"handsahek completete?",self.handshake.complete,"packet",packet)
            if not self.handshake.complete and isinstance(packet, HandshakePacket):
                print(self.mode, "crap received handshakepacket")
                self.process_handshake(packet)

            elif self.handshake.complete and  isinstance(packet, DataPacket):
                print(self.mode, 'crap got data packet')
                # print(packet.data)
                self.higherProtocol().data_received(packet.data)

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
            
        print(to_send)
        if to_send is not None:
            print(self.mode," to send is not none") 
            self.transport.write(to_send.__serialize__())

        if self.handshake.complete:
            if self.mode=="client":
                # time.sleep(2)
                print(self.mode," Waited and calling higher connection_made")
        if self.handshake.complete:
            self.higherProtocol().connection_made(
                CrapTransport(
                    lowerTransport=self.transport,key=self.handshake.shared_key, signing_key=self.handshake.signing_key
                ))


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
        self.signing_key=generatekey()
        self.private_key=ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key=self.private_key.public_key()
        self.cert= create_self_signed_cert(self.signing_key)
        # self.nonce = np.random.randint(2**4)
        self.nonce = np.random.randint(0,2**32)
        # self.cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)
        # print("here1")
        self.signature =  (self.signing_key).sign(
            serializeKey(self.public_key), 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),hashes.SHA256()
        )
        # print("here2")
        # self.syn = np.random.randint(2**32)
        # self.sent_ack = False
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
        print("Handshake initialize called")
        serialized_client_public_key = serializeKey(self.public_key)
        # print("serialed key:",serialized_client_public_key)
        serialized_cert_bytes=self.cert.public_bytes(serialization.Encoding.PEM)

        self.received_init = True
        # signed_client_public_key = 
        # same_shared_key = peer_private_key.exchange(ec.ECDH(), server_private_key.public_key())
        return createPacket(
            HandshakePacket,
            status=HandshakePacket.NOT_STARTED,
            pk = serialized_client_public_key,
            cert = serialized_cert_bytes,
            signature = self.signature,
            nonce = self.nonce 
        )

    def process(self, packet):
        print("Process")
        if not self.shared_secret:
            print("shared secret not computed")
            received_public_key = deserializeKey(packet.pk)
            received_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
            received_cert_key = received_cert.public_key()
            self.received_key=received_cert_key

        if packet.nonceSignature is not FIELD_NOT_SET:
            # Verify nonce signature
            try:
                print("Verifying nonce")
                self.received_key.verify(
                    packet.nonceSignature, str(self.nonce).encode(), 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                print("Nonce not Verified?")
                print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
           
        # Generate nonce signature
        if self.shared_secret:
            print("crap Server got second packet")
            print("server handshake completed")
            self.complete=True
            return None

   
        # print(packet.pk)
        if packet.signature is not FIELD_NOT_SET:
            try:
                print("verifying signature")
                self.received_key.verify(
                    packet.signature, packet.pk, 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                print("Not Verified?")
                print('There has been an error. Sending error.')
                return createPacket(HandshakePacket, status=HandshakePacket.ERROR)
               
        # print("Verified?")

        
        print("nonce Verified. Signing nonce ")
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
            print("crap Server got first packet")
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
            nonceSignature = nonce_signature
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

