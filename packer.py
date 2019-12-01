#!/usr/bin/python3
from sys import argv
from getpass import getpass
import hashlib
import base64

def parcour_string(string,line_len):
    ret = ""
    for i,e in enumerate(string):
        ret += e
        if (i+1)%line_len==0:
            yield ret
            ret = ""
    yield ret

def pms_crypt(data, key):
    rep = bytearray()
    key_len = len(key)
    for i,e in enumerate(data):
        rep.append((e + i*key[i%key_len])%255)
    return bytes(rep)

def encrypt_string(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

base_program = """
#!/usr/bin/python3
import base64
from getpass import getpass
from sys import argv
import hashlib
hashed_password="{}"
def encrypt_string(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature
def pms_decrypt(data, key):
    rep = bytearray()
    key_len = len(key)
    for i,e in enumerate(data):
        rep.append((e - i*key[i%key_len])%255)
    return bytes(rep)
file = open(argv[0],'r')
if len(argv)>2:
    password = argv[1]
else:
    password = ""
test2 = False
while encrypt_string(password)!=hashed_password:
    if test2:
        print('You enter wrong password')
    print('You need a password to open this python script')
    password = getpass('Password:')
    test2 = True
test = False
crypted_program = bytearray()
for line in file.readlines():
    if test:
        crypted_program += base64.b64decode(line[1:-1:].encode('utf-8'))
    if line[:-1] == '#begining':
        test = True
program = pms_decrypt(bytes(crypted_program),password.encode('utf-8')).decode('utf-8')
exec(program)
"""

max_len = 70
if len(argv)<3:
    print('Usage {} path_to_program path_to_packed_python password(optional)'.format(argv[0]))
    exit(-1)
if len(argv)!=4:
    password = getpass('Enter password:')
    while getpass('retype password:')!=password:
        print("Password don't match")
        password = getpass('Enter password:')
    print('Password is fine')
else:
    password = argv[3]

encoded = ""
with open(argv[1],'r') as file:
    encoded = base64.b64encode(pms_crypt(file.read().encode('utf-8'),password.encode('utf-8'))).decode('utf-8')
with open(argv[2],'w') as file:
    file.write(base_program.format(encrypt_string(password)))
    file.write('#begining\n')
    for line in parcour_string(encoded,max_len):
        file.write('#' + line + '\n')
print('Everything is okay enjoy')
