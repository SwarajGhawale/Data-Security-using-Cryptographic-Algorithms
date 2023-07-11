"""
AES Encryption Algorithm

Author: Ahmed Alkhayal - 1945541
For: Cybersecurity EE490

This program is a raw implementation of the AES encryption algorithm. 
It supports the following modes of encryption:
    - CBC (Cipher Block Chaining)


Note: This implementation has not been thoroughly tested and may contain security vulnerabilities.
"""
import codecs

# S-Box: Look up table for substitution routine
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Inverse S-Box: Look up table for inverse substitution routine
inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# The Round Constant table for key expansion
r_con = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]

def sub_bytes(s):
    """
    Perform the substitution step (SubBytes) of the AES algorithm.

    Args:
    s: list[list[int]]
        State matrix of 4x4.

    Returns:
    new state
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]
    return s


def inv_sub_bytes(s):
    """
    Perform the inverse substitution step (InvSubBytes) of the AES algorithm.
    
    Args:
    s: list[list[int]]
        State matrix of 4x4.
        
    Returns:
    new state
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]
    return s        
    

def shift_rows(s):
    """
    Shift the rows of the state matrix to the left according to the row number.

    Args:
    s: list[list[int]]
        State matrix of 4x4.

    Returns:
    new state
    """
    if not isinstance(s, list): s = s.tolist()
    
    rows = len(s)
    for i in range(rows):
        shift = i
        s[i] =  s[i][shift:] + s[i][:shift]
    return s


def inv_shift_rows(s):
    """
    Shift the rows of the state matrix to the right according to the row number.

    Args:
    s: list[list[int]]
        State matrix of 4x4.

    Returns:
    new state
    """
    if not isinstance(s, list): s = s.tolist()
    
    rows = len(s)
    for i in range(rows):
        shift = i
        s[i] =  s[i][-shift:] + s[i][:-shift]
    return s


def add_round_key(s, k):
    """
    Perform an XOR operation between each element in the state matrix
    and the corresponding element in the round key matrix.
    
    Args:
    s: list[list[int]]
        State matrix of 4x4.
    k: list[list[int]]
        key matrix of 4x4.
    
    Returns:
    new state
    """
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]
    return s


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


# learned from Sec 4.1.2 in The Design of Rijndael
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    """
    # Sec 4.1.2 in The Design of Rijndael
    The mix_columns function takes a 4x4 state matrix as input and performs an in-place substitution, 
    transforming the columns of the state matrix according to a fixed matrix operation.
    
    s: list[list[int]]
        State matrix of 4x4.
    
    Returns:
    return: None (the list is modified in place)
    """
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def inv_mix_columns(s):
    """
    # Sec 4.1.3 in The Design of Rijndael
    The mix_columns function takes a 4x4 state matrix as input and performs an in-place substitution, 
    transforming the columns of the state matrix according to a fixed matrix operation.
    
    s: list[list[int]]
        State matrix of 4x4.
    
    Returns:
    return: None (the list is modified in place)
    """
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))


def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    from: https://github.com/GRISHNOV/PKCS7-Padding/blob/master/src/PKCS7.c
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text.
    from: https://github.com/GRISHNOV/PKCS7-Padding/blob/master/src/PKCS7.c
    """
    padding_len = plaintext[-1]
    message, _ = plaintext[:-padding_len], plaintext[-padding_len:]
    return message


def split_blocks(message, block_size=16):
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7 padding.
    This is a raw implementation of AES. Use `encrypt` and `decrypt`.
    """
    
    rounds_keySize = {16: 10, 24: 12, 32: 14}
    
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        self.n_rounds = AES.rounds_keySize[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        
        # Initialize round keys using master key
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # previous word at Wi-1.
            word = list(key_columns[-1])

            # finding the value of Ti
            if len(key_columns) % iteration_size == 0:
                # Circular right shift.
                word.append(word.pop(0))
                # S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            # XOR with previous word.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block (state) 16 byte plaintext.
        """
        assert len(plaintext) == 16

        # Convert text to matrix (state)
        plain_state = bytes2matrix(plaintext)

        # Pre-rounds Addkey
        add_round_key(plain_state, self._key_matrices[0])

        # Perform N-1 rounds
        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        # Perform round N
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        # return byte representation of plaintext
        return matrix2bytes(plain_state)

    
    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block (state) 16 byte ciphertext.
        """
        assert len(ciphertext) == 16

        # Convert text to matrix (state)
        cipher_state = bytes2matrix(ciphertext)

        # Perform inverse round N
        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        # Perform N-1 rounds
        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        # Add last round key
        add_round_key(cipher_state, self._key_matrices[0])

        # return byte representation of ciphertext
        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        # Pad plaintext to be 16 bytes
        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        # Perform CBC mode encryption
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        # Perform CBC mode decryption
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        # Pad plaintext to be 16 byte
        return unpad(b''.join(blocks))



def encrypt(plaintext, key, iv):
    """
    Encrypts `plaintext` with `key` and `IV` using AES-128 algorithm.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    # encode to hex
    ciphertext = codecs.encode(ciphertext, "hex")
    return ciphertext


def decrypt(ciphertext, key, iv):
    """
    Decrypts `ciphertext` with `key` and `IV` using AES-128 algorithm.
    """
    ciphertext = codecs.decode(ciphertext, "hex")
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')

        
    plaintext = AES(key).decrypt_cbc(ciphertext, iv).decode()

    return plaintext


# c = encrypt("ahmed", "lookatmenowahmed", "lookatmenowahmed")
# print(c)

# p = decrypt(c, "lookatmenowahmed", "lookatmenowahmed")
# print(p)