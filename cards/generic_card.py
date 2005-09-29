import crypto_utils, utils, pycsc

DEBUG = True

class Card:
    APDU_GET_RESPONSE = "\x00\xC0\x00\x00"
    SW_OK = '\x90\x00'
    ATRS = []
    DRIVER_NAME = "Generic"
    COMMANDS = []

    def __init__(self, card = None):
        if card is None:
            self.card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
        else:
            self.card = card
        
        self._i = 0
    
    def _check_apdu(apdu):
        if len(apdu) < 4 or ((len(apdu) > 5) and len(apdu) != (ord(apdu[4])+5)):
            print "Cowardly refusing to send invalid APDU:\n  ", utils.hexdump(apdu, indent=2)
            return False
        return True
    _check_apdu = staticmethod(_check_apdu)
    
    def send_apdu(self, apdu):
        if not Card._check_apdu(apdu):
            raise Exception, "Invalid APDU"
        if DEBUG:
            print "%s\nBeginning transaction %i" % ('-'*80, self._i)
        
        if hasattr(self, "before_send"):
            apdu = self.before_send(apdu)
            if not Card._check_apdu(apdu):
                raise Exception, "Invalid APDU"
        
        if DEBUG:
            print ">> " + utils.hexdump(apdu, indent = 3)
        result = self.card.transmit(apdu)
        if DEBUG:
            print "<< " + utils.hexdump(result, indent = 3)
        
        if result[0] == '\x61':
            ## Need to call GetResponse
            gr_apdu = self.APDU_GET_RESPONSE + result[1]
            if not Card._check_apdu(gr_apdu):
                raise Exception, "Invalid APDU"
            if DEBUG:
                print ">> " + utils.hexdump(gr_apdu, indent = 3)
            result = self.card.transmit(gr_apdu)
            if DEBUG:
                print "<< " + utils.hexdump(result, indent = 3)
        
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
