import random

def isPrime(num):
    """
    This function checks if the given number is prime or not.

    Parameters:
    num (int): The number to be checked.

    Returns:
    bool: Returns True if the number is prime, False otherwise.
    """
    isPrime = True
    if num == 1:
        isPrime = False
        return isPrime
    elif num > 1:
        # check for factors
        for i in range(2, num):
            if (num % i) == 0:
                isPrime = False
                return isPrime

    return isPrime

def mod_inv(a, m):
    """
    This function calculates the modular inverse of a given number 'a' with respect to modulus 'm'.

    Parameters:
    a (int): The number for which the modular inverse is to be calculated.
    m (int): The modulus.

    Returns:
    int: The modular inverse of 'a' with respect to 'm' if it exists, None otherwise.
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def gcd(a, b):
    """
    This function calculates the greatest common divisor (GCD) of two given numbers 'a' and 'b'.

    Parameters:
    a (int): The first number.
    b (int): The second number.

    Returns:
    int: The GCD of the two numbers.
    """
    while b != 0:
        a, b = b, a % b
    return a

def generate_keypair(p, q):
    """
    This function generates a public and private key pair for the RSA cryptography algorithm.

    Parameters:
    p (int): A prime number.
    q (int): Another prime number.

    Returns:
    tuple: A tuple containing two tuples, representing the public key (e, n) and private key (d, n).
    """
    n = p * q

    phi = (p-1) * (q-1)

    e = random.randrange(1, phi)

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = mod_inv(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    """
    This function encrypts the plaintext using the public key.

    Parameters:
    pk (tuple): A tuple containing the public key 'e' and modulus 'n'.
    plaintext (str): The plaintext message to be encrypted.

    Returns:
    list: A list of integers representing the encrypted message.
    """
    key, n = pk
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    """
    Decrypt the given ciphertext with the provided private key (pk).

    Arguments:
        pk (tuple): The private key, which consists of 2 elements, 
                    the decryption exponent (d) and modulus (n).
        ciphertext (list): The encrypted text as a list of integers.

    Returns:
        str: The decrypted plaintext as a string.
    """
    key, n = pk
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)
