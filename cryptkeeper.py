#!/usr/bin/env python3
"""
Encrypt/Decrypt, Base64 Encode/Decode, 
totally need to make this crypt-keeper themed w/ figlet
pip3 install pwgen
"""

import subprocess
import logging as log
from logging import debug
from pwgen import pwgen
import crypt
import base64
import hashlib
import secrets
import pprint

log_level = log.ERROR
log.basicConfig(filename='myapp.log', level=log.INFO)
log.getLogger("my-logger")
log.info("logging config loaded")
program_log = log

def random_secret(secret_length, symbols_allowed, capitals_allowed):
    """
    Returns a random secret of <secret_length> with or without capitals/symbols
    """

    try:
        return pwgen(secret_length, symbols=symbols_allowed, capitalize=capitals_allowed) 
            
    except Exception:

        program_log.ERROR("failed to create random secret")

def hash_md5(my_string):
    """
    returns the md5 hash of a string
    """

    try: 
        encoded = my_string.encode()
        hashed = hashlib.md5(encoded)

        return hashed.hexdigest()
    
    except Exception:

        program_log.ERROR("failed to encode md5")

def hash_a_value(password, salt, iterations):
    """
    Produce a has using pbkdf2
    """

    try: 

        # Initial password presentation and salt generation
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
        )

        # Encode the hash as base64
        b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()

        return "{}${}${}${}".format('pbkdf2_sha256', iterations, salt, b64_hash)
    
    except Exception:

        program_log.ERROR("failed to hash the value")

def verify_hashed_value(password, password_hash):
    """
    Compare known hash against regenerated hash, return true if its a match
    """

    # split the password_hash into is separate parts
    try:

        algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
        iterations = int(iterations)
        assert algorithm == 'pbkdf2_sha256'
    
    except Exception:

        program_log.ERROR("failed to split the password hash")
    
    # regenerate the hash from the presented password
    regenerated_hash = hash_a_value(password, salt, iterations)

    # return the thre/false result of the comparison
    return secrets.compare_digest(password_hash, regenerated_hash)

def base64_encode(my_string):
    """
    Encode a value in base64
    """
    
    try:
        encoded = base64.urlsafe_b64encode(my_string.encode())

    except Exception:

        program_log.ERROR("failed to encode base64 string")

    return encoded

def base64_decode(my_encoded_string):
    """
    Decode a base64 value
    """

    try:   
        decodedBytes = base64.urlsafe_b64decode(my_encoded_string)
        decodedStr = str(decodedBytes, "utf-8")    

    except Exception:

        program_log.ERROR("failed to decode base64 string")
        
    return decodedStr

def main():
    """
    Demo Program that will run through the process of generating and verifying hashes.
    references:
        - https://til.simonwillison.net/python/password-hashing-with-pbkdf2
        - https://nitratine.net/blog/post/how-to-hash-passwords-in-python/

    """

    # security options: higher numbers == more secure but more cpu intensive
    secret_length=16
    salt_length=16
    hash_iterations=10000

    # authentication block object
    block = {
        "secret": base64_encode(random_secret(secret_length, False, True)),
        "salt": base64_encode(random_secret(salt_length, False, True)),
        "secret_length": secret_length,
        "salt_length": salt_length,
        "hash_iterations": hash_iterations
    }

    # cache these for convenience
    decoded_secret = base64_decode(block['secret'])
    decoded_salt = base64_decode(block['salt'])

    # generate the password hash
    hashed = hash_a_value(
        base64_decode(block['secret']), 
        base64_decode(block['salt']), 
        block['hash_iterations']
    )

    # add the password hash to the block
    block["hash"] = hash_a_value(decoded_secret, decoded_salt, block['hash_iterations'])

    # run a validity test against the known + generated hashes
    block['valid_hash'] = verify_hashed_value(decoded_secret, block["hash"])

    pp = pprint.PrettyPrinter(indent=4)
    string = f'{block}'
    
    encoded_block = base64_encode(string)
    pp.pprint(base64_decode(encoded_block))

    coin =  hash_a_value(string, decoded_salt, block['hash_iterations'])
    print(coin)


main()