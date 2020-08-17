# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------+
#
# Program:      RSA encryption 
# Author:       Laurent FERHI
# Version:      0.1
#
# ----------------------------------------------------------------------------+

import random
import time

def miller_rabin(n, k=40):
    '''
    https://gist.github.com/Ayrx/5884790
    Implementation uses the Miller-Rabin Primality Test
    The optimal number of rounds for this test is 40
    See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    for justification
    '''
    # If number is even, it's a composite number
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Otherwise, use Miller-Rabin test
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gcde(a, b): 
    '''
    https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
    extended Euclidean Algorithm 
    returns greatest common divisor from 2 numbers and x, y so that a*x+b*y = gcd (Bezout theroem)
    '''
    # Base Case  
    if a == 0 :   
        return b,0,1
             
    gcd, x1, y1 = gcde(b%a, a)  
     
    # Update x and y using results of recursive  
    x = y1 - (b//a) * x1  
    y = x1  
    
    return gcd, x, y
      

def generate_keys(min_boud=100, max_bound=1000):
    '''
    Generate the public and private keys according to RSA protocol
    '''
    # Generate 2 prime numbers and calculate modulus
    p = random.randint(min_boud,max_bound)
    while miller_rabin(p) is False:
        p = random.randint(min_boud,max_bound)
        
    q = random.randint(min_boud,max_bound)
    while miller_rabin(q) is False:
        q = random.randint(min_boud,max_bound)

    # calculate modulus
    n = p*q
    
    # Find e and d so that there is one m verifying e*d + m*(p-1)*(q-1) = 1
    # e is primal to (p-1)*(q-1), meaning gcd(e, (p-1)*(q-1)) = 1
    # d should verify e*d = 1 mod((p-1)*(q-1)). Then d is x in gcde output
    gcd = 0  # initial value of gcd (must be != 1)
    d = (p-1)*(q-1) #initial value of d < (p-1)*(q-1)
    while gcd != 1 or d >= (p-1)*(q-1) or d <= 2:
        e = random.randint(min_boud,max_bound)
        gcd, d, y = gcde(e, (p-1)*(q-1))
            
    return {"public_key":(n,e), "private_key":(n,d)}


def encryption(msg, n, e):
    '''
    Encryption of a message with the public key
    '''
    # conversion of msg in ascii code
    msg_ascii = [str(ord(character)) for character in msg]
    
    # adding '0' on the left of each code if code has less than 3 digits
    for ind, val in enumerate(msg_ascii):
        while len(val) < 3:
            val = '0' + val
        msg_ascii[ind] = val
    
    # split the joined str in groups of 4 digits and adding '0' right of last element if necessary
    str_msg = ''.join(msg_ascii)
    msg_ascii = [str_msg[i:i+4] for i in range(0, len(str_msg), 4)]
    while len(msg_ascii[-1]) < 4:
        msg_ascii[-1] = msg_ascii[-1] + '0'
    

    # encryption of the message: calculate the modulus of the division of i**e by n for each i in the ascii msg
    return [str(((int(i))**e)%n) for i in msg_ascii]


def decryption(encrypted_msg, n, d):
    '''
    Decryption of a message with the private key
    '''
    # decryption of the message: calculate the modulus of the division of i**d by n for each i in the encrypted msg
    decrypted_msg = [str((int(i)**d)%n) for i in encrypted_msg]
    
    # adding '0' left of each code to form groups of 4 digits
    for ind, val in enumerate(decrypted_msg):
        while len(val) < 4:
            val = '0' + val
        decrypted_msg[ind] = val
    
    # making groups of 3 digits from the whole joined str (remove 0 right of the chain if any)
    str_decrypted_msg = ''.join(decrypted_msg)
    decrypted_msg = [int(str_decrypted_msg[i:i+3]) for i in range(0, len(str_decrypted_msg), 3)]
    if decrypted_msg[-1] == 0:
        decrypted_msg = decrypted_msg[:-1]
    
    # converting ascii codes to corresponding characters
    res = [chr(i) for i in decrypted_msg]
    return ''.join(res)


def brute_force_private_key(n, e):
    '''
    Tries to find the private key from the public key
    '''
    # list all prime numbers <= n
    prime_n = [i for i in range(2,n) if miller_rabin(i)]
    
    # test all potential p and q the product of which is n
    for p in prime_n:
        for q in prime_n:
            if p*q == n:
                # find d so that e*d mod((p-1)*(q-1)) = 1
                for d in range(1,n):
                    if (e*d) % ((p-1)*(q-1)) == 1:
                        return (n, d)
    return False

if __name__ == '__main__':
    
    # Generate keys
    print("## Generating keys...")
    start = time.time()
    keys = generate_keys()
    end = time.time()
    print(round(end - start,2),'seconds')
    print(keys)

    # Message encryption
    msg = "This is a test message !"
    
    print("\n## Encryption...")
    start = time.time()
    crypt = encryption(msg, keys["public_key"][0], keys["public_key"][1])
    end = time.time()
    print(round(end - start,2),'seconds')
    print(crypt)
    
    # Decryption of message
    print("\n## Decryption...")
    start = time.time()
    print(decryption(crypt, keys["private_key"][0], keys["private_key"][1]))
    end = time.time()
    print(round(end - start,2),'seconds')
    
    # Try to brute force search the private key
    print("\n## Brute force search private key...")
    start = time.time()
    print(brute_force_private_key(keys["public_key"][0], keys["public_key"][1]))
    end = time.time()
    print(round(end - start,2),'seconds')
