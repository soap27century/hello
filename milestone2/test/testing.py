# import subprocess
# import pexpect,sys
# bc1 = "openssl x509 -req -in ../certs/csr.pem -CA ../certs/csr.pem_signed.cert -CAkey ../certs/key.pem -CAcreateserial -out ../certs/ns.crt"
# bc = "bash openssl x509 -req -in ../certs/csr.pem -CA ../certs/csr.pem_signed.cert -CAkey ../certs/key.pem -CAcreateserial -out ../certs/ns.crt"
# # output = subprocess.check_output(['bash','-c', bc1])
# child = pexpect.spawn(bc)
# # child.logfile_read = sys.stdout
# child.expect('Enter pass phrase*')
# child.sendline('passphrase')
# # print("Stopping the servers...")
# child.expect("#")
# child.sendline("whoami")
# child.expect("#")
# # output = subprocess.check_output(['bash','-c', bc])
# # p = subprocess.Popen(['bash','-c', bc], stdin=subprocess.PIPE,stdout=subprocess.PIPE)
# # out, err = p.communicate(input ='passphrase')
# # print('From other process: ' + out,err)



# # child = pexpect.spawn('Enter pass phrase for ../certs/key.pem:')
# # # child.expect_exact('Password:')

# # child.sendline('Enter pass phrase for ../certs/key.pem:')
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = b"a secret message"
aad = None
key = b'\rP\xd6\xc9%\xae\xe83\xf6\x8eI\x0e\xd9\xc9\xc1\xad'
# key =key.decode(encoding='UTF-8')
key = str(key)
# key = AESGCM.generate_key(bit_length=128)
print(key)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
print(aesgcm.decrypt(nonce, ct, aad))
# b'a secret message'
