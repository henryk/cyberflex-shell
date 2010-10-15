import smartcard
import TLV_utils, crypto_utils, utils, binascii, fnmatch, re, time
from generic_card import Card
from utils import C_APDU, R_APDU

class ISO_Card(Card):
    DRIVER_NAME = ["ISO"]
    COMMAND_GET_RESPONSE = C_APDU(ins=0xc0)
    COMMAND_CLASS = C_APDU
    
    APDU_VERIFY_PIN = C_APDU(ins=0x20)
    
    ## Map for check_sw()
    STATUS_MAP = {
        Card.PURPOSE_SUCCESS: ("\x90\x00", ),
        Card.PURPOSE_GET_RESPONSE: ("61??", ), ## If this is received then GET RESPONSE should be called with SW2
        Card.PURPOSE_SM_OK: ("\x90\x00",),
        Card.PURPOSE_RETRY: (), ## Theoretically this would contain "6C??", but I dare not automatically resending a command for _all_ card types
        ## Instead, card types for which this is safe should set it in their own STATUS_MAP
    }
    
    ATRS = list(Card.ATRS)
    STOP_ATRS = list(Card.STOP_ATRS)

    ## Note: a key in this dictionary may either be a one- or two-byte string containing
    ## a binary status word, or a two or four-byte string containing a hexadecimal
    ## status word, possibly with ? characters marking variable nibbles. 
    ## Hexadecimal characters MUST be in uppercase. The values that two- or four-byte
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
    TLV_OBJECTS = dict(Card.TLV_OBJECTS)
    DEFAULT_CONTEXT = None
    
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
        "\xD2\x76\x00\x00\x25\x45\x50\x02\x00": ("DF_BOERSE_NEU",     "Geldkarte",             {"fid": "\xA2\x00", "alias": ("geldkarte",)}),
        "\xD2\x76\x00\x00\x25\x47\x41\x01\x00": ("DF_GA_MAESTRO",     "GA-Maestro",            {"fid": "\xAC\x00"}),
        "\xD2\x76\x00\x00\x25\x54\x44\x01\x00": ("DF_TAN",            "TAN-Anwendung",         {"fid": "\xAC\x02"}),
        "\xD2\x76\x00\x00\x25\x4D\x01\x02\x00": ("DF_MARKTPLATZ_NEU", "Marktplatz",            {"fid": "\xB0\x01"}),
        "\xD2\x76\x00\x00\x25\x46\x53\x02\x00": ("DF_FAHRSCHEIN_NEU", "Fahrschein",            {"fid": "\xB0\x00"}),
        "\xD2\x76\x00\x00\x25\x48\x42\x02\x00": ("DF_BANKING_20" ,    "HBCI",                  {"fid": "\xA6\x00"}),
        "\xD2\x76\x00\x00\x25\x4E\x50\x01\x00": ("DF_NOTEPAD",        "Notepad",               {"fid": "\xA6\x10"}),
        
        "\xd2\x76\x00\x00\x85\x01\x00":         ("NFC_TYPE_4",        "NFC NDEF Application on tag type 4", {"alias": ("nfc",)}, ),
        
        # From TR-03110_v201_pdf.pdf
        "\xE8\x07\x04\x00\x7f\x00\x07\x03\x02": ("DF_eID", "eID application"),
        
        "\xd2\x76\x00\x00\x25\x4b\x41\x4e\x4d\x30\x31\x00": ("VRS_TICKET", "VRS Ticket", {"fid": "\xad\x00", "alias": ("vrs",)}, ),
        "\xd2\x76\x00\x01\x35\x4b\x41\x4e\x4d\x30\x31\x00": ("VRS_TICKET", "VRS Ticket", {"fid": "\xad\x00",}, ),
    }
    # Alias for DF_BOERSE_NEU
    APPLICATIONS["\xA0\x00\x00\x00\x59\x50\x41\x43\x45\x01\x00"] = APPLICATIONS["\xD2\x76\x00\x00\x25\x45\x50\x02\x00"]
    # Alias for DF_GA_MAESTRO
    APPLICATIONS["\xA0\x00\x00\x00\x04\x30\x60"] = APPLICATIONS["\xD2\x76\x00\x00\x25\x47\x41\x01\x00"]
    
    ## Format: "RID (binary)": ("vendor name", [optional: {more information}])
    VENDORS = {
        "\xD2\x76\x00\x01\x24": ("Free Software Foundation Europe", ),
        "\xD2\x76\x00\x00\x25": ("Bankenverlag", ),
        "\xD2\x76\x00\x00\x60": ("Wolfgang Rankl", ),
        "\xD2\x76\x00\x00\x05": ("Giesecke & Devrient", ),
        "\xD2\x76\x00\x00\x40": ("Zentralinstitut fuer die Kassenaerztliche Versorgung in der Bundesrepublik Deutschland", ), # hpc-use-cases-01.pdf
        "\xa0\x00\x00\x02\x47": ("ICAO", ),
        "\xa0\x00\x00\x03\x06": ("PC/SC Workgroup", ),
    }
    
    TLV_OBJECTS[TLV_utils.context_FCP] = {
        0x84: (Card.decode_df_name, "DF name"),
    }
    TLV_OBJECTS[TLV_utils.context_FCI] = TLV_OBJECTS[TLV_utils.context_FCP]
    
    def __init__(self, reader):
        Card.__init__(self, reader)
        self.last_sw = None
        self.sw_changed = False
    
    def post_merge(self):
        ## Called after cards.__init__.Cardmultiplexer._merge_attributes
        self.TLV_OBJECTS[TLV_utils.context_FCP][0x84] = (self._decode_df_name, "DF name")
        self.TLV_OBJECTS[TLV_utils.context_FCI][0x84] = (self._decode_df_name, "DF name")
    
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
    
    def _real_send(self, apdu):
        result = Card._real_send(self, apdu)
        
        self.last_sw = result.sw
        self.sw_changed = True
        
        return result

    def _send_with_retry(self, apdu):
        result = self._real_send(apdu)
        
        if self.check_sw(result.sw, self.PURPOSE_GET_RESPONSE):
            ## Need to call GetResponse
            gr_apdu = C_APDU(self.COMMAND_GET_RESPONSE, le = result.sw2, cla=apdu.cla) # FIXME
            result = R_APDU(self._real_send(gr_apdu))
        elif self.check_sw(result.sw, self.PURPOSE_RETRY) and apdu.Le == 0:
            ## Retry with correct Le
            gr_apdu = C_APDU(apdu, le = result.sw2)
            result = R_APDU(self._real_send(gr_apdu))
        
        return result
    
    
    
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
    
    COMMANDS = {
        "verify": cmd_verify,
    }
    
