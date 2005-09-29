import crypto_utils, utils, pycsc, binascii

DEBUG = True
#DEBUG = False

class Card:
    APDU_GET_RESPONSE = "\x00\xC0\x00\x00"
    APDU_VERIFY_PIN = "\x00\x20\x00\x00"
    SW_OK = '\x90\x00'
    ATRS = []
    DRIVER_NAME = "Generic"
    STATUS_WORDS = {
        SW_OK: "Normal execution"
    }

    def __init__(self, card = None):
        if card is None:
            self.card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
        else:
            self.card = card
        
        self._i = 0
        self.last_apdu = None
        self.last_sw = None
        self.sw_changed = False
    
    def verify_pin(self, pin_number, pin_value):
        apdu = self.APDU_VERIFY_PIN[:3] + chr(pin_number) + \
            chr(len(pin_value)) + pin_value
        result = self.send_apdu(apdu)
        return result == self.SW_OK
    
    def cmd_verify(self, *args):
        if len(args) != 2:
            raise TypeError, "Must give exactly two arguments: pin number and pin"
        pin_number = int(args[0], 0)
        pin_value = binascii.a2b_hex("".join(args[1].split()))
        self.verify_pin(pin_number, pin_value)
    
    COMMANDS = {
        "verify": (cmd_verify, "verify pin_number pin_value",
            """Verify a PIN.""")
    }

    def _check_apdu(apdu):
        if len(apdu) < 4 or ((len(apdu) > 5) and len(apdu) != (ord(apdu[4])+5)):
            print "Cowardly refusing to send invalid APDU:\n  ", utils.hexdump(apdu, indent=2)
            return False
        return True
    _check_apdu = staticmethod(_check_apdu)
    
    def _real_send(self, apdu):
        if not Card._check_apdu(apdu):
            raise Exception, "Invalid APDU"
        if DEBUG:
            print ">> " + utils.hexdump(apdu, indent = 3)
        result = self.card.transmit(apdu)
        self.last_apdu = apdu
        self.last_sw = result[-2:]
        self.sw_changed = True
        if DEBUG:
            print "<< " + utils.hexdump(result, indent = 3)
        return result
    
    def send_apdu(self, apdu):
        if not Card._check_apdu(apdu):
            raise Exception, "Invalid APDU"
        if DEBUG:
            print "%s\nBeginning transaction %i" % ('-'*80, self._i)
        
        if hasattr(self, "before_send"):
            apdu = self.before_send(apdu)
        
        result = self._real_send(apdu)
        
        if result[0] == '\x61':
            ## Need to call GetResponse
            gr_apdu = self.APDU_GET_RESPONSE + result[1]
            result = self._real_send(gr_apdu)
        
        if DEBUG:
            print "Ending transaction %i\n%s\n" % (self._i, '-'*80)
        self._i = self._i + 1
        
        return result
    
    def can_handle(cls, ATR):
        """Determine whether this class can handle a card with that ATR."""
        for (knownatr, mask) in cls.ATRS:
            if len(knownatr) != len(ATR):
                continue
            if crypto_utils.andstring(knownatr, mask) == crypto_utils.andstring(ATR, mask):
                return True
        return False
    can_handle = classmethod(can_handle)
    
    def get_prompt(self):
        return "(%s)" % self.DRIVER_NAME
    
    def decode_statusword(self):
        if self.last_sw is None:
            return "No command executed so far"
        elif self.last_sw[0] == "\x61":
            return "%i (0x%02x) bytes of response data can be retrieved with GetResponse." % ( (ord(self.last_sw[1])) * 2 )
        else:
            return self.STATUS_WORDS.get(self.last_sw, "Unknown SW: %s" % binascii.b2a_hex(self.last_sw))
