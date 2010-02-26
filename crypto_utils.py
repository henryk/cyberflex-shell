import sys, binascii, utils, random
from Crypto.Cipher import DES3

iv = '\x00' * 8
PADDING = '\x80' + '\x00' * 7

## *******************************************************************
## * Generic methods                                                 *
## *******************************************************************
def cipher(do_encrypt, cipherspec, key, data, iv = None):
    """Do a cryptographic operation.
    operation = do_encrypt ? encrypt : decrypt,
    cipherspec must be of the form "cipher-mode", or "cipher\""""
    from Crypto.Cipher import DES3, DES, AES
    cipherparts = cipherspec.split("-")
    
    if len(cipherparts) > 2:
        raise ValueError, 'cipherspec must be of the form "cipher-mode" or "cipher"'
    elif len(cipherparts) == 1:
        cipherparts[1] = "ecb"
    
    c_class = locals().get(cipherparts[0].upper(), None)
    if c_class is None: 
        raise ValueError, "Cipher '%s' not known, must be one of %s" % (cipherparts[0], ", ".join([e.lower() for e in dir() if e.isupper()]))
    
    mode = getattr(c_class, "MODE_" + cipherparts[1].upper(), None)
    if mode is None:
        raise ValueError, "Mode '%s' not known, must be one of %s" % (cipherparts[1], ", ".join([e.split("_")[1].lower() for e in dir(c_class) if e.startswith("MODE_")]))
    
    cipher = None
    if iv is None:
        cipher = c_class.new(key, mode)
    else:
        cipher = c_class.new(key, mode, iv)
        
    
    result = None
    if do_encrypt:
        result = cipher.encrypt(data)
    else:
        result = cipher.decrypt(data)
    
    del cipher
    return result

def hash(hashspec, data):
    """Do a cryptographic hash operation.
    hashspec must be of the form "cipher\""""
    from Crypto.Hash import SHA, RIPEMD, MD2, MD4, MD5
    
    if len(hashspec) != 3 and len(hashspec) != 6:
        raise ValueError, 'hashspec must be one of SHA, RIPEMD, MD2, MD4, MD5'
    
    h_class = locals().get(hashspec.upper(), None)
    if h_class is None: 
        raise ValueError, "Hash '%s' not known, must be one of %s" % (hashspec, ", ".join([e.lower() for e in dir() if e.isupper()]))
    
    hash = h_class.new()        
    hash.update(data)
    result = hash.digest()
    #m.hexdigest()
    
    del hash
    return result
    
def operation_on_string(string1, string2, op):
    if len(string1) != len(string2):
        raise ValueError, "string1 and string2 must be of equal length"
    result = []
    for i in range(len(string1)):
        result.append( chr(op(ord(string1[i]),ord(string2[i]))) )
    return "".join(result)


## *******************************************************************
## * Cyberflex specific methods                                      *
## *******************************************************************
def verify_card_cryptogram(session_key, host_challenge, 
    card_challenge, card_cryptogram):
    message = host_challenge + card_challenge
    expected = calculate_MAC(session_key, message, iv)
    
    print >>sys.stderr, "Original: %s" % binascii.b2a_hex(card_cryptogram)
    print >>sys.stderr, "Expected: %s" % binascii.b2a_hex(expected)
    
    return card_cryptogram == expected

def calculate_host_cryptogram(session_key, card_challenge, 
    host_challenge):
    message = card_challenge + host_challenge
    return calculate_MAC(session_key, message, iv)

def calculate_MAC(session_key, message, iv):
    print >>sys.stderr, "Doing MAC for: %s" % utils.hexdump(message, indent = 17)
    
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    block_count = len(message) / cipher.block_size
    for i in range(block_count):
        cipher.encrypt(message[i*cipher.block_size:(i+1)*cipher.block_size])
    
    last_block_length = len(message) % cipher.block_size
    last_block = (message[len(message)-last_block_length:]+PADDING)[:cipher.block_size]
    
    return cipher.encrypt( last_block )

def get_derivation_data(host_challenge, card_challenge):
    return card_challenge[4:8] + host_challenge[:4] + \
        card_challenge[:4] + host_challenge[4:8]

def get_session_key(auth_key, host_challenge, card_challenge):
    cipher = DES3.new(auth_key, DES3.MODE_ECB)
    return cipher.encrypt(get_derivation_data(host_challenge, card_challenge))

def generate_host_challenge():
    random.seed()
    return "".join([chr(random.randint(0,255)) for e in range(8)])

def andstring(string1, string2):
    return operation_on_string(string1, string2, lambda a,b: a & b)
    
if __name__ == "__main__":
    default_key = binascii.a2b_hex("404142434445464748494A4B4C4D4E4F")
    
    host_chal = binascii.a2b_hex("".join("89 45 19 BF BC 1A 5B D8".split()))
    card_chal = binascii.a2b_hex("".join("27 4D B7 EA CA 66 CE 44".split()))
    card_crypto = binascii.a2b_hex("".join("8A D4 A9 2D 9B 6B 24 E0".split()))
    
    session_key = get_session_key(default_key, host_chal, card_chal)
    print "Session-Key:  ", utils.hexdump(session_key)
    
    print verify_card_cryptogram(session_key, host_chal, card_chal, card_crypto)
    
    host_crypto = calculate_host_cryptogram(session_key, card_chal, host_chal)
    print "Host-Crypto:  ", utils.hexdump( host_crypto )

    external_authenticate = binascii.a2b_hex("".join("84 82 01 00 10".split())) + host_crypto
    print utils.hexdump(calculate_MAC(session_key, external_authenticate, iv))
