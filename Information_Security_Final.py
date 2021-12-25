import hashlib, base64, datetime
from Crypto.Cipher import ARC4 as RC4cipher, AES
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

def get_hash(pwd):
    h = hashlib.sha256()
    h.update(pwd)
    return h.hexdigest()

def get_spwd_salt_pair(hashed_pwd):
    salt = get_random_bytes(8).hex()
    return hashed_pwd+salt

class Block:
    def __init__(self, previous_block_hash, transaction_list):

        self.previous_block_hash = previous_block_hash
        self.transaction_list = transaction_list

        self.block_data = f"{' - '.join(transaction_list)}\nPrevious hash: {previous_block_hash}"
        self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()

class BlockChain:
    def __init__(self):
        self.chain = []
        self.generate_first_block()

    def generate_first_block(self):
        self.chain.append(Block("0", ['Albert464121', 'withdraw 1000', '2021/11/15 17:42, ATM-B']))
    
    def create_block_from_transaction(self, transaction_list):
        previous_block_hash = self.last_block.block_hash
        self.chain.append(Block(previous_block_hash, transaction_list))

    def display_chain(self):
        for i in range(len(self.chain)):
            print(f"Data {i + 1}: {self.chain[i].block_data}")
            print(f"Hash {i + 1}: {self.chain[i].block_hash}\n")
    @property
    def last_block(self):
        return self.chain[-1]

def RC4(encrypt_or_decrypt, data, key1):
    if encrypt_or_decrypt == "encrypt":
        ICV = hashlib.sha256(data.encode()).hexdigest()
        key = bytes(key1, encoding='utf-8')
        enc = RC4cipher.new(key)
        res = enc.encrypt(data.encode('utf-8'))
        res = base64.b64encode(res)
        print('\nEncrypted data = ', res.hex()) #ciphertext
        res = str(res,'utf8')
        return [res, ICV]
    elif encrypt_or_decrypt == "decrypt":
        data = base64.b64decode(data)
        key = bytes(key1, encoding='utf-8')
        enc = RC4cipher.new(key)
        res = enc.decrypt(data)
        res = str(res,'utf-8')
        return res

BankA_users = {'Bob':'5eb7c0ec579d61dcc93b3f26123ab3904b9885b524983dd07725142b1d51c056ec44c2b171701685',
               'Alice':'b1e21850b2f11e932ba7ebdf53a0f9c6a89665cf038eaf72c8811c1cea12a7121c099817fea6439c',
               'Albert':'83bf4593b01c3c935d114eaa819eee572d53dbfc00a78db101e5d643dba692a411624e558221ac8c'}
Albert = BlockChain()
Albert.create_block_from_transaction(['Albert464121', 'withdraw 6000', '2021/12/25 15:21, ATM-A'])
salt = ''
KeyA_RC4 = 'key for bank A'
KeyA_AES = PBKDF2(KeyA_RC4, salt, dkLen=32)
KeyB_RC4 = 'key for bank B'
KeyB_AES = PBKDF2(KeyB_RC4, salt, dkLen=32)

#Step 1: Albert insert his card to ATM-B
ID = 'Albert464121'
password = 'potatoisgod'
hashed_pwd = get_hash(password.encode())
#Use the salted password to pass between banks and center
salted_pwd = get_spwd_salt_pair(hashed_pwd)

#Step 2: Use Key-B to encrypt ID and send it to center
encrypted_info = RC4('encrypt', ID, KeyB_RC4)
cipher, ICV = encrypted_info[0], encrypted_info[1]

#Step 3: Center decrypts and check integrity
decrypted_text = RC4('decrypt', cipher, KeyB_RC4)
if(hashlib.sha256(decrypted_text.encode()).hexdigest() == ICV): 
    #If success, send it to center
    print("Bank B ICV success") 
    #Step 4: Center encrypt using KeyA then send it to bank A
    encrypted_info = RC4('encrypt', ID, KeyA_RC4)
    cipher, ICV = encrypted_info[0], encrypted_info[1]
    #Step 5: Bank A decrypts the cipher and use it to search for user's hashed pwd,
    #        then compare with original hashed pwd
    decrypted_text = RC4('decrypt', cipher, KeyA_RC4)
    user_ID = decrypted_text[0:-6]
    # if success, encrypt message using AES CBC and send it to center
    if user_ID in BankA_users:
        if(BankA_users[user_ID][0:63] == salted_pwd[0:63]):
            message = b'Bank A authenticated'
            AES_key = AES.new(KeyA_AES, AES.MODE_CBC)
            IV = AES_key.iv
            encrypted_message = AES_key.encrypt(pad(message, AES.block_size))
            #print('Encrypted message =', encrypted_message.hex())
            #Step 6: Center encrypts the message using key b and send it to bank b
            decrypt_AES_key = AES.new(KeyA_AES, AES.MODE_CBC, iv=IV)
            decrypted_message = unpad(decrypt_AES_key.decrypt(encrypted_message), AES.block_size)
            AES_key = AES.new(KeyB_AES, AES.MODE_CBC)
            IV = AES_key.iv
            encrypted_message = AES_key.encrypt(pad(message, AES.block_size))
            #print("Decrypted message =", decrypted_message.decode())
            #print('Encrypted message =', encrypted_message.hex())
            #Step 7: bank b decrypts and check, if success, can withdraw
            decrypt_AES_key = AES.new(KeyB_AES, AES.MODE_CBC, iv=IV)
            decrypted_message = unpad(decrypt_AES_key.decrypt(encrypted_message), AES.block_size)
            if(decrypted_message == message):
                print("Check success, can withdraw")
                #Step 8: bank b send transaction data to center, then center add the data into block chain
                transaction = 'withdraw 5000'
                current_time = datetime.datetime.today().strftime("%Y/%m/%d %H:%M")
                Albert.create_block_from_transaction([ID, transaction, current_time + ', ATM-B'])
                Albert.display_chain()
            else:
                print("Check failed")
        else:
            print("Session failed")
    else:
        print("No such user")
else:
    print("failed")
