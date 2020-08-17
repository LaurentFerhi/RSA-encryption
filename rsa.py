# -*- coding: utf-8 -*-
"""
RSA algorithm
https://interstices.info/nombres-premiers-et-cryptologie-lalgorithme-rsa/
"""

import random
import numpy as np

def miller_rabin(n, k=40):
    '''
    https://gist.github.com/Ayrx/5884790
    Implementation uses the Miller-Rabin Primality Test
    The optimal number of rounds for this test is 40
    See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    for justification
    '''
    # If number is even, it's a composite number
    if n == 2:
        return True

    if n % 2 == 0:
        return False

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
             
    gcd,x1,y1 = gcde(b%a, a)  
     
    # Update x and y using results of recursive  
    x = y1 - (b//a) * x1  
    y = x1  
    
    return gcd, x, y
      

def generate_keys(min_boud=10000, max_bound=1000000):
    # Generate 2 prime numbers and calculate modulus
    p = random.randint(min_boud,max_bound)
    while miller_rabin(p) is False:
        p = random.randint(min_boud,max_bound)
        
    q = random.randint(min_boud,max_bound)
    while miller_rabin(q) is False:
        q = random.randint(min_boud,max_bound)

    # modulus
    n = p*q
    
    # Find e and d so that there is one m verifying e*d + m*(p-1)*(q-1) = 1
    # e is primal to (p-1)*(q-1), meaning gcd(e, (p-1)*(q-1)) = 1
    # d should verify e*d = 1 mod((p-1)*(q-1)). Then d is x in gcde output
    gcd = 10  # initial value of gcd != 1
    d = (p-1)*(q-1) #initial value of d < (p-1)*(q-1)
    while gcd != 1 or d >= (p-1)*(q-1) or d <= 2:
        e = random.randint(min_boud,max_bound)
        gcd, d, y = gcde(e, (p-1)*(q-1))
            
    return {"public_key":(n,e), "private_key":(n,d)}



keys = generate_keys()
print(keys)


        
        
        
        
        
        
        