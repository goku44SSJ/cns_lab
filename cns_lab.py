#Deffie_Hellman
import random
import math

def isPrime(n):
	for i in range(2, int(math.sqrt(n)) + 1):
		if n%i==0:
			return False
	return True
p=89
print('Chosen prime number p=',p)
g=int(input('Enter the generator of order p-1:'))

x = random.randint(2, p-2)
R1 = pow(g,x) % p
print('Alice choosen a large random number x=',x, 'and computed R1=', R1)

y=random.randint(2, p-2)
R2= pow(g,y) & p
print('Bob choosen a large random number y=', y, 'and computed R2=',R2)

K_Alice = pow(R2,x) % p
K_Bob = pow(R1,y) % p 
print('Alice\'s Computed Shared Key is:',K_Alice) 
print('Bob\'s Computed Shared Key is:',K_Bob)

if K_Alice == K_Bob:
	print('Key Exchange Successful...')
else:
	print('Key Exchange not Successful...')

#RSA
import math 
import random 
def keygeneration(): 
	p=int(input('Enter first prime number: ')) 
	q=int(input('Enter second prime number: ')) 
	n=p*q 
	phi_n=(p-1)*(q-1) 
	e=int(input('Randomly choose a value for e between 1 and phi_n: ')) 
	while not (1 <e< phi_n and math.gcd(e, phi_n)==1): 
		e=int(input('Invalid choice. Choose a value for e between 1 and phi_n such that gcd(e, phi_n) 1:')) 
	k=random.randint(1, 1000) 
	while (k*phi_n+1) %e !=0:
		k=random.randint(1,1000)
	d=(k*phi_n+1)//e
	return e, n, d 

def encrypt_rsa(P, e, n): 
	C=pow(P, e, n) 
	return C

def decrypt_rsa(C, d, n): 
	P=pow(C, d, n) 
	return P
e=n=d=0
e, n, d = keygeneration()
print('Public key (e, n):', e, n) 
print('Private key (d):', d) 
P=int(input('Enter plaintext as an integer value: '))
C=encrypt_rsa(P, e, n) 
print('Ciphertext (as integer value) is:', C)
P_new=decrypt_rsa(C, d, n)
print('Decrypted plaintext value is:', P_new)

#AES
from Crypto.Cipher import AES
import binascii

def encryption (aes, P, key):
	while (len(P) % 16 != 0): 
		P=""
	P=P.encode()
	C = aes.encrypt(P)
	C = binascii.hexlify(C)
	C = C.decode()
	return C

def decryption(aes, C, key):
	C = binascii.unhexlify(C)
	P1 = aes.decrypt(C)
	P1=P1.decode().strip()
	return P1

key = input("Enter key: ")
P = input("Enter plaintext: ")
print("Plaintext is: ", P)
key = key.encode()
aes_cipher = AES.new(key, AES.MODE_ECB)

C = encryption(aes_cipher, P, key) 
print("Ciphertext after encryption: ", C)
P1 = decryption(aes_cipher, C, key)
print("Plaintext after decryption: ", P1)

##RSA-digital
import math
import random

def keyGeneration():
    p = int(input('Enter 1st large prime p: '))
    q = int(input('Enter 2nd large prime q: '))  
    n = p * q                                    
    phi_n = (p - 1) * (q - 1)                    
    e = int(input('Randomly choose e between 1 and phi_n: '))
    while (math.gcd(e, phi_n) != 1 or not (1 < e < phi_n)):
        e = int(input('Randomly choose e between 1 and phi_n: '))  # Ensure e is coprime with phi_n

    k=random.randint(1, 1000)
    while ((k * phi_n + 1) % e != 0):  # This loop randomly finds valid k
        k=random.randint(1, 1000)

    d = int((k * phi_n + 1) / e)  # Compute d
    return e, n, d

def generate_signature(M, d, n):
    S = pow(M, d, n)
    return S

def verify_signature(S, M, e, n):
    M1 = pow(S, e, n)
    print(f'The receiver is now verifying...... It generated the message M1 = {M1}')
    return M == M1

e=n=d=0
e, n, d = keyGeneration()
print('e =', e, ', n =', n, ', d =', d)

M = int(input('Enter message M to sign: '))
S = generate_signature(M, e, n)
print('Signature generated')
print(f'Sending signature S = {S}, and message M = {M}')

res = verify_signature(S, M, d, n)
if res:
    print('Message Accepted...')
else:
    print('Message Rejected...')

#DES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def des_encrypt(plain_text, key):
	if len(key) != 8:
		raise ValueError("Key must be exactly 8 bytes long.")
	cipher=DES.new(key, DES.MODE_ECB)
	padded_text=pad(plain_text.encode(), DES.block_size)
	encrypted_text = cipher.encrypt(padded_text)
	return encrypted_text

def des_decrypt(cipher_text, key):
	cipher=DES.new(key, DES.MODE_ECB)
	decrypted_padded_text = cipher.decrypt(cipher_text)
	plain_text=unpad(decrypted_padded_text, DES.block_size)
	return plain_text.decode()

key=b'12345678'
message="Hello"
print("Original Message:", message)
encrypted=des_encrypt(message, key)
print("Encrypted (in hex):", encrypted.hex())
decrypted=des_decrypt(encrypted, key)
print("Decrypted Message:", decrypted)

#Vignere_Cipher
def vigenere_cipher(text, key, encrypt=True):
    result = [] 
    key = key.lower() 
    key_length = len(key) 
    key_index = 0

    for char in text: 
        if char.isalpha(): 
            shift = ord(key[key_index % key_length]) - ord('a')  
            key_index += 1  
            if not encrypt:  # If decrypting, reverse the shift direction
                shift = -shift  

            if char.islower():  
                new_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                new_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

            result.append(new_char)  
        else:
            result.append(char) 

    return ''.join(result) 

plaintext = "HELLO WORLD"
key = "KEY"

# Encrypting
ciphertext = vigenere_cipher(plaintext, key, encrypt=True)
print("Encrypted Text:", ciphertext)

# Decrypting
decrypted_text = vigenere_cipher(ciphertext, key, encrypt=False)
print("Decrypted Text:", decrypted_text)

#Playfair_cipher
def create_key_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    for ch in key:
        if ch.isalpha() and ch not in matrix:
            matrix.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in matrix:
            matrix.append(ch)
    keymatrix = []
    for i in range(0, 25, 5):
        keymatrix.append(matrix[i:i+5])
    return keymatrix

def prepare_plaintext(plaintext):
    plaintext = plaintext.upper().replace("J", "I")
    plaintext = "".join(filter(str.isalpha, plaintext))
    pairs = []
    i = 0
    while i < len(plaintext):
        pair = plaintext[i:i + 2]
        if len(pair) == 2 and pair[0] == pair[1]:
            pairs.append(pair[0] + "X")
            i += 1
        else:
            pairs.append(pair)
            i += 2
    if len(pairs[-1]) % 2 != 0:
        pairs[-1] += 'X'
    return pairs

def find_char_position(matrix, ch):
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] == ch:
                return i, j
    return None

def encryption(plaintext, key):
    keymatrix = create_key_matrix(key)
    pairs = prepare_plaintext(plaintext)
    ciphertext = ""
    for pair in pairs:
        row1, col1 = find_char_position(keymatrix, pair[0])
        row2, col2 = find_char_position(keymatrix, pair[1])
        if row1 == row2:
            ciphertext += keymatrix[row1][(col1 + 1) % 5]
            ciphertext += keymatrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += keymatrix[(row1 + 1) % 5][col1]
            ciphertext += keymatrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += keymatrix[row1][col2]
            ciphertext += keymatrix[row2][col1]
    return ciphertext

def decryption(ciphertext, key):
    keymatrix = create_key_matrix(key)
    pairs = []
    for i in range(0, len(ciphertext), 2):
        pairs.append(ciphertext[i:i + 2])
    plaintext = ""
    for pair in pairs:
        row1, col1 = find_char_position(keymatrix, pair[0])
        row2, col2 = find_char_position(keymatrix, pair[1])
        if row1 == row2:
            plaintext += keymatrix[row1][(col1 - 1) % 5]
            plaintext += keymatrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += keymatrix[(row1 - 1) % 5][col1]
            plaintext += keymatrix[(row2 - 1) % 5][col2]
        else:
            plaintext += keymatrix[row1][col2]
            plaintext += keymatrix[row2][col1]
    return plaintext

key = input("Enter keyword: ")
plaintext = input("Enter plaintext: ")
ciphertext = encryption(plaintext, key)
print("Ciphertext:", ciphertext)
decrypted_plaintext = decryption(ciphertext, key)
print("Decrypted plaintext:", decrypted_plaintext)