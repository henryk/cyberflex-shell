import TLV_utils, crypto_utils, utils, pycsc, binascii, fnmatch, sre
from utils import C_APDU, R_APDU

DEBUG = True
#DEBUG = False

## Constants for check_sw()
PURPOSE_SUCCESS = 1 # Command executed successful
PURPOSE_RETRY = 2   # Command executed successful but needs retry with correct length
PURPOSE_SM_OK = 3   # Command not executed successful or with warnings, but response still contains SM objects

class Card:
    DRIVER_NAME = "Generic"
    APDU_GET_RESPONSE = C_APDU(ins=0xc0)
    APDU_VERIFY_PIN = C_APDU(ins=0x20)
    PURPOSE_SUCCESS, PURPOSE_RETRY, PURPOSE_SM_OK = PURPOSE_SUCCESS, PURPOSE_RETRY, PURPOSE_SM_OK
    ## Map for check_sw()
    STATUS_MAP = {
        PURPOSE_SUCCESS: ("\x90\x00", ),
        PURPOSE_RETRY: ("61??", ), ## If this is received then GET RESPONSE should be called with SW2
        PURPOSE_SM_OK: ("\x90\x00",)
    }
    ## Note: an item in this list must be a tuple of (atr, mask) where atr is a binary
    ##   string and mask a binary mask. Alternatively mask may be None, then ATR must be a regex
    ##   to match on the ATRs hexlify representation
    ATRS = []
    ## Note: a key in this dictionary may either be a two-byte string containing
    ## a binary status word, or a four-byte string containing a hexadecimal
    ## status word, possibly with ? characters marking variable nibbles. 
    ## Hexadecimal characters MUST be in uppercase. The values that four-byte
    ## strings map to may be either format strings, that can make use of the 
    ## keyword substitutions for SW1 and SW2 or a callable accepting two arguments 
    ## (SW1, SW2) that returns a string.
    STATUS_WORDS = { 
        '\x90\x00': "Normal execution",
        '61??': "%(SW2)i (0x%(SW2)02x) bytes of response data can be retrieved with GetResponse.",
        '6C??': "Bad value for LE, 0x%(SW2)02x is the correct value.",
        '63C?': lambda SW1,SW2: "The counter has reached the value '%i'" % (SW2%16)
    }
    ## For the format of this dictionary of dictionaries see TLV_utils.tags
    TLV_OBJECTS = {}
    
    ## Format: "AID (binary)": ("name", [optional: description, {more information}])
    APPLICATIONS = {
        "\xa0\x00\x00\x01\x67\x45\x53\x49\x47\x4e": ("DF.ESIGN", ),
        "\xa0\x00\x00\x00\x63\x50\x4b\x43\x53\x2d\x31\x35": ("DF_PKCS15", ),
        "\xD2\x76\x00\x01\x24\x01": ("DF_OpenPGP", "OpenPGP card",                             {"significant_length": 6} ),
        "\xa0\x00\x00\x02\x47\x10\x01": ("DF_LDS", "Machine Readable Travel Document",         {"alias": ("mrtd",)}),
        ## The following are from 0341a.pdf: BSI-DSZ-CC-0341-2006
        "\xD2\x76\x00\x00\x66\x01":             ("DF_SIG",            "Signature application", {"fid": "\xAB\x00"}),
        "\xD2\x76\x00\x00\x25\x5A\x41\x02\x00": ("ZA_MF_NEU",         "Zusatzanwendungen",     {"fid": "\xA7\x00"}),
        "\xD2\x76\x00\x00\x25\x45\x43\x02\x00": ("DF_EC_CASH_NEU",    "ec-Cash",               {"fid": "\xA1\x00"}),
        "\xD2\x76\x00\x00\x25\x45\x50\x02\x00": ("DF_BOERSE_NEU",     "Geldkarte",             {"fid": "\xA2\x00"}),
        "\xD2\x76\x00\x00\x25\x47\x41\x01\x00": ("DF_GA_MAESTRO",     "GA-Maestro",            {"fid": "\xAC\x00"}),
        "\xD2\x76\x00\x00\x25\x54\x44\x01\x00": ("DF_TAN",            "TAN-Anwendung",         {"fid": "\xAC\x02"}),
        "\xD2\x76\x00\x00\x25\x4D\x01\x02\x00": ("DF_MARKTPLATZ_NEU", "Marktplatz",            {"fid": "\xB0\x01"}),
        "\xD2\x76\x00\x00\x25\x46\x53\x02\x00": ("DF_FAHRSCHEIN_NEU", "Fahrschein",            {"fid": "\xB0\x00"}),
        "\xD2\x76\x00\x00\x25\x48\x42\x02\x00": ("DF_BANKING_20" ,    "HBCI",                  {"fid": "\xA6\x00"}),
        "\xD2\x76\x00\x00\x25\x4E\x50\x01\x00": ("DF_NOTEPAD",        "Notepad",               {"fid": "\xA6\x10"}),
    }
    # Alias for DF_BOERSE_NEU
    APPLICATIONS["\xA0\x00\x00\x00\x59\x50\x41\x43\x45\x01\x00"] = APPLICATIONS["\xD2\x76\x00\x00\x25\x45\x50\x02\x00"]
    # Alias for DF_GA_MAESTRO
    APPLICATIONS["\xA0\x00\x00\x00\x04\x30\x60"] = APPLICATIONS["\xD2\x76\x00\x00\x25\x47\x41\x01\x00"]
    
    ## Format: "RID (binary)": ("vendor name", [optional: {more information}])
    VENDORS = {
        "\xD2\x76\x00\x01\x24": ("OpenPGP", ),
        "\xD2\x76\x00\x00\x25": ("Bankenverlag", ),
        "\xD2\x76\x00\x00\x60": ("Wolfgang Rankl", ),
        "\xD2\x76\x00\x00\x05": ("Giesecke & Devrient", ),
        "\xD2\x76\x00\x00\x40": ("Zentralinstitut fuer die Kassenaerztliche Versorgung in der Bundesrepublik Deutschland", ), # hpc-use-cases-01.pdf
        "\xa0\x00\x00\x02\x47": ("ICAO", ),
    }
    
    def _decode_df_name(self, value):
        result = " " + utils.hexdump(value, short=True)
        info = None
        
        if self.APPLICATIONS.has_key(value):
            info = self.APPLICATIONS[value]
        else:
            for aid, i in self.APPLICATIONS.items():
                if not len(i) > 2 or not i[2].has_key("significant_length"):
                    continue
                if aid[ :i[2]["significant_length"] ] == value[ :i[2]["significant_length"] ]:
                    info = i
                    break
        
        result_array = []
        if info is not None:
            if info[0] is not None:
                result_array.append( ("Name", info[0]) )
            
            if len(info) > 1 and not info[1] is None:
                result_array.append( ("Description", info[1] ) )
        
        if self.VENDORS.has_key(value[:5]):
            result_array.append( ("Vendor", self.VENDORS[ value[:5] ][0]) )
        
        if len(result_array) > 0:
            max_len = max( [len(a) for a,b in result_array] + [11] ) + 1
            result = result + "\n" + "\n".join( [("%%-%is %%s" % max_len) % (a+":",b) for a,b in result_array] )
        return result
    
    def decode_df_name(value):
        # Static method for when there is no object reference
        return Card._decode_df_name(value)
    
    TLV_OBJECTS[TLV_utils.context_FCP] = {
        0x84: (decode_df_name, "DF name"),
    }
    TLV_OBJECTS[TLV_utils.context_FCI] = TLV_OBJECTS[TLV_utils.context_FCP]
    
    def __init__(self, card = None, reader = None):
        if card is None:
            if reader is None:
                self.card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
            else:
                self.card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY, reader = reader)
        else:
            self.card = card
        
        self._i = 0
        self.last_apdu = None
        self.last_sw = None
        self.last_result = None
        self.sw_changed = False
    
    def post_merge(self):
        ## Called after cards.__init__.Cardmultiplexer._merge_attributes
        self.TLV_OBJECTS[TLV_utils.context_FCP][0x84] = (self._decode_df_name, "DF name")
        self.TLV_OBJECTS[TLV_utils.context_FCI][0x84] = (self._decode_df_name, "DF name")
    
    def verify_pin(self, pin_number, pin_value):
        apdu = C_APDU(self.APDU_VERIFY_PIN, P2 = pin_number,
            data = pin_value)
        result = self.send_apdu(apdu)
        return self.check_sw(result.sw)
    
    def cmd_verify(self, pin_number, pin_value):
        """Verify a PIN."""
        pin_number = int(pin_number, 0)
        pin_value = binascii.a2b_hex("".join(pin_value.split()))
        self.verify_pin(pin_number, pin_value)
    
    def cmd_reset(self):
        """Reset the card."""
        self.card.reconnect(init=pycsc.SCARD_RESET_CARD)
    
    def cmd_parsetlv(self, start = None, end = None):
        "Decode the TLV data in the last response, start and end are optional"
        lastlen = len(self.last_result.data)
        if start is not None:
            start = (lastlen + (int(start,0) % lastlen) ) % lastlen
        else:
            start = 0
        if end is not None:
            end = (lastlen + (int(end,0) % lastlen) ) % lastlen
        else:
            end = lastlen
        print TLV_utils.decode(self.last_result.data[start:end], tags=self.TLV_OBJECTS)
    
    _SHOW_APPLICATIONS_FORMAT_STRING = "%(aid)-50s %(name)-20s %(description)-30s"
    def cmd_show_applications(self):
        "Show the list of known (by the shell) applications"
        print self._SHOW_APPLICATIONS_FORMAT_STRING % {"aid": "AID", "name": "Name", "description": "Description"}
        foo =  self.APPLICATIONS.items()
        foo.sort()
        for aid, info in foo:
            print self._SHOW_APPLICATIONS_FORMAT_STRING % {
                "aid": utils.hexdump(aid, short=True),
                "name": info[0],
                "description": len(info) > 1 and info[1] or ""
            }
    
    COMMANDS = {
        "reset": cmd_reset,
        "verify": cmd_verify,
        "parse_tlv": cmd_parsetlv,
        "show_applications": cmd_show_applications,
    }

    def _real_send(self, apdu):
        apdu_binary = apdu.render()
        
        if DEBUG:
            print ">> " + utils.hexdump(apdu_binary, indent = 3)
        
        result_binary = self.card.transmit(apdu_binary)
        result = R_APDU(result_binary)
        
        self.last_apdu = apdu
        self.last_sw = result.sw
        self.sw_changed = True
        
        if DEBUG:
            print "<< " + utils.hexdump(result_binary, indent = 3)
        return result
    
    def _send_with_retry(self, apdu):
        result = self._real_send(apdu)
        
        if self.check_sw(result.sw, PURPOSE_RETRY):
            ## Need to call GetResponse
            gr_apdu = C_APDU(self.APDU_GET_RESPONSE, le = result.sw2) # FIXME
            result = R_APDU(self._real_send(gr_apdu))
        
        return result
    
    def send_apdu(self, apdu):
        if DEBUG:
            print "%s\nBeginning transaction %i" % ('-'*80, self._i)
        
        if hasattr(self, "before_send"):
            apdu = self.before_send(apdu)
        
        result = self._send_with_retry(apdu)
        
        if hasattr(self, "after_send"):
            result = self.after_send(result)
        
        if DEBUG:
            print "Ending transaction %i\n%s\n" % (self._i, '-'*80)
        self._i = self._i + 1
        
        self.last_result = result
        return result
    
    def check_sw(self, sw, purpose = None):
        if purpose is None: purpose = Card.PURPOSE_SUCCESS
        return self.match_statusword(self.STATUS_MAP[purpose], sw)
    
    def can_handle(cls, card):
        """Determine whether this class can handle a given pycsc object."""
        ATR = card.status().get("ATR","")
        for (knownatr, mask) in cls.ATRS:
            if mask is None:
                if sre.match(knownatr, binascii.hexlify(ATR), sre.I):
                    return True
            else:
                if len(knownatr) != len(ATR):
                    continue
                if crypto_utils.andstring(knownatr, mask) == crypto_utils.andstring(ATR, mask):
                    return True
        return False
    can_handle = classmethod(can_handle)
    
    def get_prompt(self):
        return "(%s)" % self.DRIVER_NAME
    
    def match_statusword(swlist, sw):
        """Try to find sw in swlist. 
        swlist must be a list of either binary statuswords (two bytes), hexadecimal statuswords (four bytes) or fnmatch patterns on a hexadecimal statusword.
        Returns: The element that matched (either two bytes, four bytes or the fnmatch pattern)."""
        if sw in swlist:
            return sw
        sw = binascii.hexlify(sw).upper()
        if sw in swlist:
            return sw
        for value in swlist:
            if fnmatch.fnmatch(sw, value):
                return value
        return None
    match_statusword = staticmethod(match_statusword)
    
    def decode_statusword(self):
        if self.last_sw is None:
            return "No command executed so far"
        else:
            retval = None
            
            matched_sw = self.match_statusword(self.STATUS_WORDS.keys(), self.last_sw)
            if matched_sw is not None:
                retval = self.STATUS_WORDS.get(matched_sw)
                if isinstance(retval, str):
                    retval = retval % { "SW1": ord(self.last_sw[0]), 
                        "SW2": ord(self.last_sw[1]) }
                    
                elif callable(retval):
                    retval = retval( ord(self.last_sw[0]),
                        ord(self.last_sw[1]) )
            
            if retval is None:
                return "Unknown SW (SW %s)" % binascii.b2a_hex(self.last_sw)
            else:
                return "%s (SW %s)" % (retval, binascii.b2a_hex(self.last_sw))
    
    def get_protocol(self):
        return ((self.card.status()["Protocol"] == pycsc.SCARD_PROTOCOL_T0) and (0,) or (1,))[0]
    
    def close_card(self):
        "Disconnect from a card"
        del self.card # FIXME: anything else to do?
