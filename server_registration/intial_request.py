import random
from Crypto.PublicKey import RSA
#User send initial request to server
#message = idu||N0

# Generate RSA key pair
pku = RSA.generate(1024)  # You can also load an existing key with RSA.import_key()
print(pku.export_key())
puu = pku.publickey()
print(puu.export_key())
#Save the keys to text files
private_key_file = 'pk_usr.txt'
public_key_file = 'pu_usr.txt'
with open(private_key_file, 'wb') as f:
    f.write(pku.export_key('PEM'))
with open(public_key_file, 'wb') as f:
    f.write(puu.export_key('PEM'))
#User enter information
idu = input('User enter its id: ').encode()
n0 = random.randint(10**2, 10**5)

#Convert to string to save in txt
idu = str(int.from_bytes(idu))
n0 = str(n0)
lines = [idu,'\n',n0]
with open('ini_sr.txt', 'w') as ini:
    ini.writelines(lines)

#Save id user and nonce n0
#with open('user.txt', 'w') as usr:
#    usr.writelines([idu,'\n',n0])