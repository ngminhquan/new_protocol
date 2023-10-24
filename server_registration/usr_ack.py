from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys
#integer to byestring function
def int_to_bytes(n):
    if n == 0:
        return b'\x00'
    byte_size = (n.bit_length() + 7) // 8  # Calculate the required byte size
    byte_order = 'big'  # Use 'big' or 'little' endian

    # Convert the integer to bytes
    bytes_data = n.to_bytes(byte_size, byte_order)
    return bytes_data
#User import id and nonce n0
with open('ini_sr.txt', 'r') as ini:
    lines = ini.readlines()
    idu, n0 = int(lines[0]), int(lines[1])
idu, n0 = int_to_bytes(idu), int_to_bytes(n0)
#User reads publickey of server
with open('pus.txt', 'rb') as f:
    pus = RSA.import_key(f.read())
#Import publickey and private key of user
with open('pk_usr.txt', 'rb') as f:
    pku = RSA.import_key(f.read())
with open('pu_usr.txt', 'rb') as f:
    puu = RSA.import_key(f.read())
#print(pku.export_key(), puu.export_key())
#User reads msg sent from server
with open('response_sr.txt', 'r') as rp:
    lines = rp.readlines()
    c1, lids, ln1 = int(lines[0]), int(lines[1]),int(lines[2])
c1 = int_to_bytes(c1)
# Use the private key for "decryption"
decipher = PKCS1_OAEP.new(pku)
msg = decipher.decrypt(c1)
print('msg', msg)
#msg = H(idu|n0)|ids|n1
h_id = msg[:32]
ids = msg[32:32+lids]
n1 = msg[32+lids: 32+lids+ln1]
hash_check = SHA256.new(idu + n0).digest()
print('check', hash_check)
print('origin', h_id)
if hash_check != h_id:
    print('invalid hash')
    sys.exit()
