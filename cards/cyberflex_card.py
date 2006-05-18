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
    APDU_INITIALIZE_UPDATE = C_APDU('\x80\x50\x00\x00')
    APDU_EXTERNAL_AUTHENTICATE = C_APDU('\x84\x82\x00\x00')
    APDU_GET_STATUS = C_APDU('\x84\xF2\x00\x00\x02\x4f\x00')
    APDU_DELETE = C_APDU('\x84\xe4\x00\x00')
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
        if apdu.cla == 0x84:
            ## Need security
            
            if self.secure_channel_state == SECURE_CHANNEL_NONE:
                raise Exception, "Need security but channel is not established"
            if self.secure_channel_state == SECURE_CHANNEL_CLEAR:
                return apdu
            elif self.secure_channel_state == SECURE_CHANNEL_MAC:
                apdu.lc = apdu.lc + MAC_LENGTH
                
                mac = crypto_utils.calculate_MAC(self.session_key_mac, apdu.render(), self.last_mac)
                self.last_mac = mac
                apdu.data = apdu.data + mac
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
        
        host_challenge = crypto_utils.generate_host_challenge()
        
        apdu = C_APDU(self.APDU_INITIALIZE_UPDATE,
            p1 = keyset_version, p2 = key_index,
            data = host_challenge)
        
        self.secure_channel_state = SECURE_CHANNEL_NONE
        self.last_mac = '\x00' * 8
        self.session_key_enc = None
        self.session_key_mac = None
        
        result = self.send_apdu(apdu)
        if result.sw != self.SW_OK:
            raise Exception, "Statusword after InitializeUpdate was %s. Warning: No successful ExternalAuthenticate; keyset might be locked soon" % binascii.b2a_hex(result[-2:])
        
        card_challenge = result.data[12:20]
        card_cryptogram = result.data[20:28]
        
        self.session_key_enc = crypto_utils.get_session_key(
            self.keyset[KEY_AUTH], host_challenge, card_challenge)
        self.session_key_mac = crypto_utils.get_session_key(
            self.keyset[KEY_MAC], host_challenge, card_challenge)
        
        if not crypto_utils.verify_card_cryptogram(self.session_key_enc,
            host_challenge, card_challenge, card_cryptogram):
            raise Exception, "Validation error, card not authenticated. Warning: No successful ExternalAuthenticate; keyset might be locked soon"
        
        host_cryptogram = crypto_utils.calculate_host_cryptogram(
            self.session_key_enc, card_challenge, host_challenge)
        
        apdu = C_APDU(self.APDU_EXTERNAL_AUTHENTICATE,
            p1 = security_level, p2 = 0,
            data = host_cryptogram)
            
        self.secure_channel_state = SECURE_CHANNEL_MAC
        result = self.send_apdu(apdu)
        self.secure_channel_state = security_level
        
        if result.sw != self.SW_OK:
            self.secure_channel_state = SECURE_CHANNEL_NONE
            raise Exception, "Statusword after ExternalAuthenticate was %s. Warning: No successful ExternalAuthenticate; keyset might be locked soon" % binascii.b2a_hex(result[-2:])
        
        return True
    
    def select_application(self, aid):
        result = Java_Card.select_application(self, aid)
        if self.last_sw == self.SW_OK and aid[:5] != DEFAULT_CARD_MANAGER_AID[:5]:
            self.secure_channel_state = SECURE_CHANNEL_NONE
        return result
    
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
        return self.send_apdu(
            C_APDU(self.APDU_GET_STATUS,
                p1 = reference_control)
            )
    
    def delete(self, aid):
        if aid[:5] == DEFAULT_CARD_MANAGER_AID[:5]:
            print "Cowardly refusing to delete the card manager."
            raise ValueError, "Undeletable object"
        tlvaid = chr(0x4f) + chr(len(aid)) + aid
        apdu = C_APDU(self.APDU_DELETE,
            data = tlvaid)
        result = self.send_apdu(apdu)
        
        return result.data[0] == 0x0
    
    def cmd_delete(self, aid):
        """Delete the object identified by aid."""
        aid = binascii.a2b_hex("".join(aid.split()))
        self.delete(aid)
    
    def cmd_status(self, reference_control = "0x20"):
        """Execute a GetStatus command and return the result."""
        reference_control = int(reference_control, 0)
        result = self.get_status(reference_control)
        utils.parse_status(result.data)
    
    def cmd_secure(self, keyset_version=None, key_index=None, security_level=None):
        """Open a secure channel. 
        If given, keyset_version and key_index must be integers while security_level can be one of 0, clear, 1, mac, 3, macenc, mac+enc."""
        if keyset_version is None and key_index is None and security_level is None:
            arg1 = 0
            arg2 = 0
            arg3int = SECURE_CHANNEL_MAC
        elif keyset_version is not None and key_index is not None and security_level is not None:
            arg1 = int(keyset_version,0)
            arg2 = int(key_index,0)
            
            if arg1 not in range(256):
                raise ValueError, "keyset_version must be between 0 and 255 (inclusive)."
            if arg2 not in (0,1):
                raise ValueError, "key_index must be 0 or 1."
            
            arg3 = security_level.strip().lower()
            try:
                arg3int = int(security_level,0)
            except:
                arg3int = None
            
            if arg3 == "clear":
               arg3int = SECURE_CHANNEL_CLEAR 
            elif arg3 == "mac":
                arg3int = SECURE_CHANNEL_MAC
            elif arg3 in ("macenc", "mac+enc"):
                arg3int = SECURE_CHANNEL_MACENC
        else:
            raise TypeError, "Must give none or three arguments."
        self.open_secure_channel(arg1, arg2, arg3int)
    
    def cmd_setkey(self, key_index, key):
        """Set a key in the current keyset. 
        key_index should be one of 0, all, 1, enc, auth, 2, mac, 3, kek."""
        arg1 = key_index.strip().lower()
        try:
            arg1int = int(arg1,0)
        except:
            arg1int = None
        
        if len(key) != 16:
            arg2 = binascii.a2b_hex("".join(key.split()))
        else:
            arg2 = key
        
        if len(arg2) != 16:
            raise TypeError, "Need either exactly 16 binary bytes or 16 hexadezimal bytes for the key argument."
        
        if arg1int == 0 or arg1 == "all":
            all = True
        else:
            all = False
        
        if all or arg1int == KEY_AUTH or arg1 in("auth","enc"):
            self.keyset[KEY_AUTH] = arg2
        if all or arg1int == KEY_MAC or arg1 == "mac":
            self.keyset[KEY_MAC] = arg2
        if all or arg1int == KEY_KEK or arg1 == "kek":
            self.keyset[KEY_KEK] = arg2
    
    def cmd_printkeyset(self):
        """Print the current keyset."""
        print "ENC,AUTH:", utils.hexdump(self.keyset[KEY_AUTH], short=True)
        print "MAC:     ", utils.hexdump(self.keyset[KEY_MAC], short=True)
        print "KEK:     ", utils.hexdump(self.keyset[KEY_KEK], short=True)
    
    def cmd_resetkeyset(self):
        """Reset the keyset to the default keyset for this card."""
        self.keyset = dict(DEFAULT_KEYSET)
    
    def cmd_savekeyset(self, filename):
        """Saves the keyset to the named file."""
        fd = file(filename, "w")
        fd.write(self.keyset[KEY_AUTH])
        fd.write(self.keyset[KEY_MAC])
        fd.write(self.keyset[KEY_KEK])
        fd.close()
    
    def cmd_loadkeyset(self, filename):
        """Loads the keyset from the named file."""
        fd = file(filename, "r")
        keys = fd.read(16*3)
        if len(keys) != 16*3:
            del keys
            fd.close()
            raise ValueError, "The file must must contain three keys of 16 bytes each."
        self.keyset[KEY_AUTH] = keys[:16]
        self.keyset[KEY_MAC] = keys[16:16*2]
        self.keyset[KEY_KEK] = keys[16*2:16*3]
        del keys
        fd.close()
    
    _secname = {SECURE_CHANNEL_NONE: "",
        SECURE_CHANNEL_CLEAR: " [clear]",
        SECURE_CHANNEL_MAC: " [MAC]",
        SECURE_CHANNEL_MACENC: " [MAC+enc]"}
    def get_prompt(self):
        return "(%s)%s" % (self.DRIVER_NAME, 
            Cyberflex_Card._secname[self.secure_channel_state])
    
    
    APPLICATIONS = dict(Java_Card.APPLICATIONS)
    APPLICATIONS.update( {
        "card_manager": DEFAULT_CARD_MANAGER_AID
        } )

    COMMANDS = dict(Java_Card.COMMANDS)
    COMMANDS.update( {
        "status": cmd_status,
        "open_secure_channel": cmd_secure,
        "set_key": cmd_setkey,
        "print_keyset": cmd_printkeyset,
        "reset_keyset": cmd_resetkeyset,
        "save_keyset": cmd_savekeyset,
        "load_keyset": cmd_loadkeyset,
        "delete": cmd_delete
        } )
    STATUS_WORDS = dict(Java_Card.STATUS_WORDS)
    STATUS_WORDS.update( {
        "\x62\x83": "The Card Manager is locked (SelectApplication).",
        "\x63\x00": "Authentication of the host cryptogram failed.",
        "\x63\x10": "More data is available for return than is specified in the Le value.",
        "\x64\x00": "Technical problem that has no specified diagnosis.",
        "\x65\x81": "Memory failure.",
        "\x67\x00": "The specified length of the input data (Lc) is incorrect.",
        "\x69\x81": "No key is specified (GetResponse, called internally).",
        "\x69\x82": "Security status not satisfied. For example, MAC verification failed, the authentication key is locked, or the current security domain requires DAP verification and no verification data was included with the command.",
        "\x69\x83": "The key is blocked (GetResponse, called internally).",
        "\x69\x85": """A requirement for using the command is not satisfied. For example:
+ Command issued outside of a secure channel.
+ Current application does not have the required application privilege
  or life cycle state.
+ The required preceding command was not present.
+ The object to delete is referenced by another object on the card.""",
        "\x69\x87": "The MAC or other verification data is missing (Install).",
        "\x69\x99": "Application selection failed (SelectApplication).",
        "\x6A\x80": """Invalid or inconsistent input data, including input data that is inconsistent with a command header parameter, and LV/TLV-format elements in the input data that are not self-consistent. For example:
+ Incorrect number of padding bytes, incorrect key used for
  encryption, or the specified key set or key index value is invalid.
+ Referenced AID is not found in the card registry or package, or the
  newly specified AID already exists in the registry.
+ Inappropriate application privilege byte value (installing security
  domain), or card already has a default selected application
  (specifying default selected application).
+ First block of input data for a load file is not preceded by the
  correct tag and/or valid length, or the load file refers to a
  nonexistent package.""",
        "\x6A\x81": "Target is locked (SelectApplication).",
        "\x6A\x82": "Registry contains no valid application (or no additional valid application) with the specified AID (SelectApplication).",
        "\x6A\x84": "Insufficient EEPROM memory available to add the object to the card.",
        "\x6A\x86": "Incorrect or unsupported value is specified for P1, P2, or both.",
        "\x6A\x88": "Data referred to in P1, P2, or both is not found.",
        "\x6D\x00": "Unsupported value entered for the INS byte.",
        "\x6E\x00": "Unsupported value entered for the CLA byte.",
        "\x6F\x00": "JVM error that has no specified diagnosis.",
        "\x90\x00": "Command succeeded.",
        "\x94\x81": "Target has an invalid life cycle state.",
        "\x94\x84": "Unsupported algorithm ID in input data (PutKey).",
        "\x94\x85": "Invalid key check value in input data (PutKey).",
        } )

if __name__ == "__main__":
    c = Cyberflex_Card()
    print utils.hexdump( c.select_application(DEFAULT_CARD_MANAGER_AID) )
    
    c.open_secure_channel(security_level = SECURE_CHANNEL_MAC)
    utils.parse_status(c.get_status(224)[:-2])
