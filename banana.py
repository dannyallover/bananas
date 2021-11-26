# AES 256 encryption/decryption using pycrypto library

import sys
import base64
import csv
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = AES.block_size
MODE = AES.MODE_CBC
PASSWORD_SIZE = 16
verify = b'\xe9\xec\x90\t\xfc\xe0\xe2\xf8\xbb\x10\x15c\xd5\x8c\xde\xcb_\x92\x8b8\xba\xe7\xf5\xcc:\xaf\x95da;\xef:'

def get_key(password):
    return hashlib.sha256(password.encode("utf-8")).digest()

def get_iv():
    return Random.new().read(BLOCK_SIZE)

def get_new_pass():
    new_pass = input("enter new password: ")
    if len(new_pass) > 16:
        sys.exit("password too long")
    return pad_pkcs7(new_pass, BLOCK_SIZE)

def get_cipher(key, nonce):
    return AES.new(key, MODE, nonce)

def get_accounts():
    with open('registered_accounts.csv') as f:
        reader = csv.reader(f)
        return list(reader)

def get_password_from_file(app):
    with open("passwords/"+ app + ".bin", 'rb') as f:
        return f.read(16)

def get_nonce_from_file(app):
    with open("nonces/"+ app + ".bin", 'rb') as f:
        return f.read(16)

def get_account(accounts, key):
    app = input("enter application: ")
    if [app] not in accounts:
        sys.exit("account doesn't exist")
    enc_pass = get_password_from_file(app)
    nonce = get_nonce_from_file(app)

    return decrypt(enc_pass, key, nonce)

def add_acount_file(app):
    with open('registered_accounts.csv', 'a') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([app])

def add_password_file(app, enc_pass):
    with open("passwords/"+ app + ".bin", 'wb') as f:
        f.write(enc_pass)

def add_nonce_file(app, nonce):
    with open("nonces/"+ app + ".bin", 'wb') as f:
        f.write(nonce)

def add_account(accounts, key):
    app = input("enter application: ")
    if [app] in accounts:
        sys.exit("account already exists")
    nonce = get_iv()
    new_pass = get_new_pass()
    add_acount_file(app)

    enc_pass = encrypt(new_pass, key, nonce)

    add_nonce_file(app, nonce)
    add_password_file(app, enc_pass)

def verify_key(key):
    hash_of_key = hashlib.sha256(key).digest()
    return hash_of_key == verify

def unpad(s):
    return s[:-ord(s[len(s) - 1])]

def pad_pkcs7(s, block_size):
    num_chars = block_size - len(s)
    char_num = chr(num_chars)
    return s + (char_num * num_chars)

def encrypt(s, key, nonce):
    cipher = get_cipher(key, nonce)
    enc = cipher.encrypt(s.encode())
    return enc

def decrypt(enc, key, nonce):
    cipher = get_cipher(key, nonce)
    dec = cipher.decrypt(enc)
    return dec

def main():
    master_pass = input("enter master password: ")
    sym_key = get_key(master_pass)

    enter = verify_key(sym_key)
    if not enter:
        sys.exit("wrong password")

    accounts = get_accounts()
    print("Here are your current accounts:")
    for acc in accounts:
        print(acc[0])
    print("\n")

    decision = input("(1) add acount \n(2) get account \nenter action: ")
    if decision == '1':
        add_account(accounts, sym_key)
    elif decision == '2':
        pwd = get_account(accounts, sym_key)
        print("Your account password: ", unpad(pwd.decode()))

if __name__ == "__main__":
    main()
    # to-do: write tests to show that
    # (0) you need the master password to enter
    # (1) a password can't be overwritten through the script
    # (2) retreive a password for an account that doesn't exist won't affect
    # the system
    # (3) you can't use a password that's greater than the block length
    # (since that would break the current script)
