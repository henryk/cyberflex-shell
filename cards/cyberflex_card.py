import utils, crypto_utils, binascii
from java_card import *

KEY_AUTH = 0x01
KEY_MAC = 0x02
KEY_KEK = 0x03
DEFAULT_KEYSET = {
    KEY_AUTH: "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F",
    KEY_MAC: "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F",
    KEY_KEK: "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F"}
DEFAULT_CARD_MANAGER_AID = "\xA0\x00\x00\x00\x03\x00\x00"
SECURE_CHANNEL_NONE = -1
SECURE_CHANNEL_CLEAR = 0
SECURE_CHANNEL_MAC = 1
SECURE_CHANNEL_MACENC = 3
MAC_LENGTH = 8

class Cyberflex_Card(Java_Card):
    APDU_INITIALIZE_UPDATE = '\x80\x50\x00\x00\x08'
    APDU_EXTERNAL_AUTHENTICATE = '\x84\x82\x00\x00'
    APDU_GET_STATUS = '\x84\xF2\x00\x00\x02\x4f\x00'
    DRIVER_NAME = "Cyberflex"
    
    ATRS = [ 
        ## Cyberflex Access 32k v2 ???
        ("3B 75 13 00 00 9C 02 02 01 02",
         "FF FF FF FF FF FF FF FF FF FF"),
        ## Cyberflex Access Developer 32k
        ("3B 17 13 9C 12 00 00 00 00 00",
         "FF FF 00 FF 00 00 00 00 00 00"),
        ## Cyberflex Access e-gate 32K
        ("3B 75 94 00 00 62 02 02 00 80",
         "FF FF FF 00 00 FF FF FF 00 00"),
        ## Cyberflex Access 32K v4
        ("3b 76 00 00 00 00 9c 11 01 00 00",
         "FF FF FF FF FF FF FF FF FF FF FF"),
        ## Cyberflex Access 64K v1 (non-FIPS-compliant, softmask 1.1)
        ("3b 75 00 00 00 29 05 01 01 01",
         "FF FF 00 00 00 FF FF FF 00 00"),
        ## Cyberflex Access 64K v1 (FIPS-compliant, softmask 2.1)
        ("3b 75 00 00 00 29 05 01 02 01",
         "FF FF 00 00 00 FF FF FF 00 00")
    ]
    
    ## Will convert the ATRS to binary strings
    ATRS = [(binascii.a2b_hex("".join(_a.split())),
        binascii.a2b_hex("".join(_b.split()))) for (_a,_b) in ATRS]
    del _a, _b
    
    def __init__(self, card = None, keyset = None):
        Java_Card.__init__(self, card = card)
        
        if keyset is not None:
            self.keyset = keyset
        else:
            self.keyset = dict(DEFAULT_KEYSET)
        self.card_manager_aid = DEFAULT_CARD_MANAGER_AID
        
        self.session_key_enc = None
        self.session_key_mac = None
        self.last_mac = None
        self.secure_channel_state = SECURE_CHANNEL_NONE
    
    def before_send(self, apdu):
        """Will be called by send_apdu before sending a command APDU.
        Is responsible for authenticating/encrypting commands when needed."""
        if apdu[0] == '\x84':
            ## Need security
            if self.secure_channel_state == SECURE_CHANNEL_NONE:
                raise Exception, "Need security but channel is not established"
            if self.secure_channel_state == SECURE_CHANNEL_CLEAR:
                return apdu
            elif self.secure_channel_state == SECURE_CHANNEL_MAC:
                if len(apdu) < 4:
                    raise Exception, "Malformed APDU"
                elif len(apdu) == 4:
                    apdu = apdu + chr(MAC_LENGTH)
                else:
                    apdu = apdu[:4] + chr( ord(apdu[4]) + MAC_LENGTH ) + apdu[5:]
                
                mac = crypto_utils.calculate_MAC(self.session_key_mac, apdu, self.last_mac)
                self.last_mac = mac
                apdu = apdu + mac
            elif self.secure_channel_state == SECURE_CHANNEL_MACENC:
                raise Exception, "MAC+Enc Not implemented yet"
        return apdu

    def open_secure_channel(self, keyset_version = 0x0, key_index = 0x0, 
        security_level = SECURE_CHANNEL_MAC):
        """Opens a secure channel by sending an InitializeUpdate and 
        ExternalAuthenticate.
        keyset_version is either the explicit key set version or 0x0 for 
            the implicit key set version.
        key_index is either 0x0 for implicit or 0x1 for explicit key index.
        security_level is one of SECURE_CHANNEL_CLEAR, SECURE_CHANNEL_MAC 
            or SECURE_CHANNEL_MACENC.
            Note that SECURE_CHANNEL_CLEAR is only available for cards that 
            are not secured.
        
        Returns: True on success, generates an exception otherwise.
        Warning: Cyberflex Access 64k v2 cards maintain a failure counter 
            and will lock their key set if they receive 3 InitializeUpdate
            commands that are not followed by a successful 
            ExternalAuthenticate!
            If this function does not return True you should not retry 
            the call, but must closely inspect the situation."""
        
        if security_level not in (SECURE_CHANNEL_CLEAR, SECURE_CHANNEL_MAC, SECURE_CHANNEL_MACENC):
            raise ValueError, "security_level must be one of SECURE_CHANNEL_CLEAR, SECURE_CHANNEL_MAC or SECURE_CHANNEL_MACENC"
        
        apdu = self.APDU_INITIALIZE_UPDATE[:2] + \
            chr(keyset_version) + \
            chr(key_index)
        
        host_challenge = crypto_utils.generate_host_challenge()
        apdu = apdu + chr(len(host_challenge)) + \
            host_challenge
        
        self.secure_channel_state = SECURE_CHANNEL_NONE
        self.last_mac = '\x00' * 8
        self.session_key_enc = None
        self.session_key_mac = None
        
        result = self.send_apdu(apdu)
        if result[-2:] != self.SW_OK:
            raise Exception, "Statusword after InitializeUpdate was %s. Warning: No successful ExternalAuthenticate; keyset might be locked soon" % binascii.b2a_hex(result[-2:])
        
        card_challenge = result[12:20]
        card_cryptogram = result[20:28]
        
        self.session_key_enc = crypto_utils.get_session_key(
            self.keyset[KEY_AUTH], host_challenge, card_challenge)
        self.session_key_mac = crypto_utils.get_session_key(
            self.keyset[KEY_MAC], host_challenge, card_challenge)
        
        if not crypto_utils.verify_card_cryptogram(self.session_key_enc,
            host_challenge, card_challenge, card_cryptogram):
            raise Exception, "Validation error, card not authenticated. Warning: No successful ExternalAuthenticate; keyset might be locked soon"
        
        host_cryptogram = crypto_utils.calculate_host_cryptogram(
            self.session_key_enc, card_challenge, host_challenge)
        
        apdu = self.APDU_EXTERNAL_AUTHENTICATE[:2] + \
            chr(security_level) + '\x00' + chr(len(host_cryptogram)) + \
            host_cryptogram
            
        self.secure_channel_state = SECURE_CHANNEL_MAC
        result = self.send_apdu(apdu)
        self.secure_channel_state = security_level
        
        if result[-2:] != self.SW_OK:
            raise Exception, "Statusword after ExternalAuthenticate was %s. Warning: No successful ExternalAuthenticate; keyset might be locked soon" % binascii.b2a_hex(result[-2:])
            self.secure_channel_state = SECURE_CHANNEL_NONE
        
        return True
    
    def get_status(self, reference_control=0x20):
        """Sends a GetStatus APDU und returns the result.
        reference_control is either:
        0x20 Load files
        0x40 Applications
        0x60 Applications and load files
        0x80 Card manager
        0xA0 Card manager and load files
        0xC0 Card manager and applications
        0xE0 Card manager, applications and load files.
        
        Returns: the response APDU which can be parsed with 
        utils.parse_status()"""
        return self.send_apdu(self.APDU_GET_STATUS[:2] + chr(reference_control)
            + self.APDU_GET_STATUS[3:])
    
    def cmd_status(self, *args):
        if len(args) > 1:
            raise TypeError, "Can have at most one argument."
        if len(args) == 1:
            print args
            reference_control = int(args[0], 0)
        else:
            reference_control = 0x20
        result = self.get_status(reference_control)
        utils.parse_status(result[:-2])
    
    def cmd_secure(self, *args):
        self.open_secure_channel()
    
    _secname = {SECURE_CHANNEL_NONE: "",
        SECURE_CHANNEL_CLEAR: " [clear]",
        SECURE_CHANNEL_MAC: " [MAC]",
        SECURE_CHANNEL_MACENC: " [MAC+enc]"}
    def get_prompt(self):
        return "(%s)%s" % (self.DRIVER_NAME, 
            Cyberflex_Card._secname[self.secure_channel_state])
    
    
    COMMANDS = dict(Java_Card.COMMANDS)
    COMMANDS.update( {
        "status": (cmd_status, "status [reference_control]", 
            """Execute a GetStatus command and return the result."""),
        "open_secure_channel": (cmd_secure, "open_secure_channel",
            """Open a secure channel with the default parameters (FIXME).""")
        } )

if __name__ == "__main__":
    c = Cyberflex_Card()
    print utils.hexdump( c.select_application(DEFAULT_CARD_MANAGER_AID) )
    
    c.open_secure_channel(security_level = SECURE_CHANNEL_MAC)
    utils.parse_status(c.get_status(224)[:-2])
