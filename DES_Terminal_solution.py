from DES_Tables import *
from DES_Helper import *


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


# Massage
pt = "372921BCF550E31781CCBBB880DB768A6AC49F0177367803"  # Enter a plain text
key = "123123123123123123123" # in Hex

# TODO:
# here i want the user to choose between binary and hex for the key and plain text
# str2bin for binary and hex2bin for hex so you have to add a radio button for that
# 4 options two for plain text and two for key
# HEX = True
# ptb = hex2bin(pt)
# keyb = hex2bin(key)

HEX = False
ptb = str2bin(pt)
keyb = str2bin(key)

pt_chunks = [ptb[i:i+64] for i in range(0, len(ptb), 64)]
# Pad the last chunk with zeros if needed
if len(pt_chunks[-1]) % 64 != 0:
    pt_chunks[-1] = pt_chunks[-1].ljust(64, '0')

cipher_text = ''
text = ''
print("Encryption")
for i in range(len(pt_chunks)):
	cipher_text += DES(pt_chunks[i], keyb, result="HEX", TYPE="ENC", Report=False)
print("Cipher Text (HEX): ", bin2hex(cipher_text))
print("Cipher Text (Binary): ", cipher_text)

print(hex2bin(bin2hex(cipher_text)))

print("Decryption")
cipher_text_chunks = [cipher_text[i:i+64] for i in range(0, len(cipher_text), 64)]
for i in range(len(cipher_text_chunks)):
	text += DES(cipher_text_chunks[i], keyb, result="HEX", TYPE="DEC", Report=False)

# if user choose binary for plain text then text = bin2str(text), 
# if user choose hex for plain text then text = bin2hex(text)
if HEX:
	print("Plain Text (HEX): ", bin2hex(text))
else:
	print("Plain Text : ", bin2str(text))

