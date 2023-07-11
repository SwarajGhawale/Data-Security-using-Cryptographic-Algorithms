from DES_Tables import *

# Hexadecimal to binary conversion
def hex2bin(hex):
    bin_string = bin(int(hex, 16))[2:]
    return bin_string.zfill(len(hex)*4)

# Binary to hexadecimal conversion
def bin2hex(bin):
    hex_string = hex(int(bin, 2))[2:]
    return hex_string.zfill(len(bin)//4).upper()

# Binary to decimal conversion
def bin2dec(binary):
    return int(str(binary), 2)

# Decimal to binary conversion
def dec2bin(num):
	return format(num, 'b').zfill(len(str(num))*4)

# A string to binary 
def str2bin(s):
    return ''.join([bin(ord(x))[2:].zfill(8) for x in s])

# Binary to string
def bin2str(b):
    return ''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)])

# hex to string
def hex2str(h):
	return bytes.fromhex(h).decode('utf-8')

# Permute function to rearrange the bits
def permute(k, arr, n):
    return "".join([k[i-1] for i in arr])


def substitute(xor_x):
    sbox_str = ""
    for j in range(0, 8):
        row = int(xor_x[j * 6] + xor_x[j * 6 + 5], 2)
        col = int(xor_x[j * 6 + 1: j * 6 + 5], 2)
        val = sbox[j][row][col]
        sbox_str += format(val, '04b')
    return sbox_str


# shifting the bits towards left by nth shifts
def shift_left(k, nth_shifts):
    k = list(k)
    for _ in range(nth_shifts):
        k.append(k.pop(0))
    return ''.join(k)

def swapper(left, right, i):
    # Swap except last round
    if(i != 15):
        left, right = right, left
    return left, right


def mixer(left, right, key, i):
    # Expansion D-box: 32 to 48 bits
    right_expanded = permute(right, exp_d, 48)

    # XOR: round key and right expanded
    xor_x = xor(right_expanded, key[i])

    # S-box
    sbox_str = substitute(xor_x)

    # Straight(permutatoin) D-box
    sbox_str = permute(sbox_str, per, 32)

    # XOR: left and sbox_str
    result = xor(left, sbox_str)

    return result

# calculating xow of two strings of binary number a and b
def xor(a, b):
    return ''.join(map(lambda x, y: str(int(x != y)), a, b))

def is_not_hex(s):
	# check if the entered text is in hex format
	for i in s:
		if i not in "0123456789abcdefABCDEF":
			return True
	return False
     
     
# Key generation
def key_generation(key):

	# key = hex2bin(key)

	# getting 56 bit key from 64 bit using the parity bits
	key = permute(key, keyp, 56)

	# Splitting
	left = key[0:28] # rkb for RoundKeys in binary
	right = key[28:56] # rk for RoundKeys in hexadecimal

	key = []
	for i in range(0, 16):
		# Shifting the bits by nth shifts by checking from shift table
		left = shift_left(left, shift_table[i])
		right = shift_left(right, shift_table[i])

		# Combination of left and right string
		combine_str = left + right

		# Compression of key from 56 to 48 bits
		round_key = permute(combine_str, key_comp, 48)

		key.append(round_key)
            
	return key


def DES(pt, key, result="HEX", TYPE="ENC", Report=True):
	
	# PlainText 2 binary
	# pt = hex2bin(pt)

	# key generation
	# Encryption
	key = key_generation(key)
	# Decryption
	if TYPE == "DEC": 
		key = key[::-1]

	# Initial Permutation
	pt = permute(pt, initial_perm, 64)
	if Report:
		if result == "Bianry":
			print("After initial permutation", pt)
		else:
			print("After initial permutation", bin2hex(pt))

	# Splitting PlainText
	left = pt[0:32]
	right = pt[32:64]

	# 16 rounds
	for round_num in range(0, 16):

		# mixer
		left = mixer(left, right, key, round_num)

		# Swapper
		left, right = swapper(left, right, round_num)

		# Printing
		if Report:
			if result == "Bianry":
				print("Round ", round_num + 1, " ", left," ", right, " ", key[round_num])
			elif result == "HEX":	
				print("Round ", round_num + 1, " ", bin2hex(left)," ", bin2hex(right), " ", bin2hex(key[round_num]))

	# Combination
	combined = left + right

	# Final permutation
	cipher_text = permute(combined, final_perm, 64)

	return cipher_text
