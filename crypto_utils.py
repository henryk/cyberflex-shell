import sys, binascii, utils, random
from Crypto.Cipher import DES3

iv = '\x00' * 8
PADDING = '\x80' + '\x00' * 7

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
    if len(string1) != len(string2):
        raise ValueError, "string1 and string2 must be of equal length"
    result = []
    for i in range(len(string1)):
        result.append( chr(ord(string1[i]) & ord(string2[i])) )
    return "".join(result)
    
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
