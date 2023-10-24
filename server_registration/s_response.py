from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

#integer to byestring function
def int_to_bytes(n):
    if n == 0:
        return b'\x00'
    byte_size = (n.bit_length() + 7) // 8  # Calculate the required byte size
    byte_order = 'big'  # Use 'big' or 'little' endian

    # Convert the integer to bytes
    bytes_data = n.to_bytes(byte_size, byte_order)
    return bytes_data
#Server read msg sent from user
with open('ini_sr.txt', 'r') as ini:
    lines = ini.readlines()
    idu, n0 = int(lines[0]), int(lines[1])
idu, n0 = int_to_bytes(idu), int_to_bytes(n0)
#Import public key of user
with open('pu_usr.txt', 'rb') as f:
    pu_usr = RSA.import_key(f.read())
# Generate RSA key pair
pks = RSA.generate(1024)  # You can also load an existing key with RSA.import_key()
print(pks.export_key())
pus = pks.publickey()
print(pus.export_key())
#Save the keys to text files
private_key_file = 'pks.txt'
public_key_file = 'pus.txt'
with open(private_key_file, 'wb') as f:
    f.write(pks.export_key('PEM'))
with open(public_key_file, 'wb') as f:
    f.write(pks.publickey().export_key('PEM'))

#Server enters its information
ids = input('Enter id server: ').encode('utf-8')
n1 = get_random_bytes(4)
# Server encrypt message with its privatekey
# then send to user c1, pus
#msg = H(idu|n0)|ids|n1
#c1 = E(pu_usr, msg)
h_obj = SHA256.new(idu + n0).digest()
msg = h_obj+ids+n1
print('msg', msg)
# Use the public key for "encryption"
cipher = PKCS1_OAEP.new(pu_usr)
c1 = cipher.encrypt(msg)

# The ciphertext is now ready for transmission or storage
print("Ciphertext:", c1)

#Save msg and send to user
c1 = str(int.from_bytes(c1))
lines = [c1,'\n',str(len(ids)),'\n',str(len(n1))]

with open('response_sr.txt', 'w') as rp:
    rp.writelines(lines)