import smartcard
import TLV_utils, crypto_utils, utils, binascii, fnmatch, re, time
from utils import C_APDU, R_APDU

DEBUG = True
#DEBUG = False


_GENERIC_NAME = "Generic"
class Card:
    DRIVER_NAME = [_GENERIC_NAME]
    COMMAND_GET_RESPONSE = None
    
    ## Constants for check_sw()
    PURPOSE_SUCCESS = 1 # Command executed successful
    PURPOSE_GET_RESPONSE = 2   # Command executed successful but needs GET RESPONSE with correct length
    PURPOSE_SM_OK = 3   # Command not executed successful or with warnings, but response still contains SM objects
    PURPOSE_RETRY = 4   # Command would be executed successful but needs retry with correct length
    
    ## Map for check_sw()
    STATUS_MAP = {}
    
    ## Note: an item in this list must be a tuple of (atr, mask) where atr is a binary
    ##   string and mask a binary mask. Alternatively mask may be None, then ATR must be a regex
    ##   to match on the ATRs hexlify representation
    ATRS = []
    ## Note: A list of _not_ supported ATRs, overriding any possible match in ATRS. Matching
    ##   is done as for ATRS.
    STOP_ATRS = []
    
    ## Note: a key in this dictionary may either be a one- or two-byte string containing
    ## a binary status word, or a two or four-byte string containing a hexadecimal
    ## status word, possibly with ? characters marking variable nibbles. 
    ## Hexadecimal characters MUST be in uppercase. The values that two- or four-byte
    ## strings map to may be either format strings, that can make use of the 
    ## keyword substitutions for SW1 and SW2 or a callable accepting two arguments 
    ## (SW1, SW2) that returns a string.
    STATUS_WORDS = { 
    }
    ## For the format of this dictionary of dictionaries see TLV_utils.tags
    TLV_OBJECTS = {}
    DEFAULT_CONTEXT = None
    
    ## Format: "AID (binary)": ("name", [optional: description, {more information}])
    APPLICATIONS = {
    }
    
    ## Format: "RID (binary)": ("vendor name", [optional: {more information}])
    VENDORS = {
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
    
    def __init__(self, reader):
        self.reader = reader
        
        self._i = 0
        self.last_apdu = None
        self.last_result = None
        self._last_start = None
        self.last_delta = None
    
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
        print TLV_utils.decode(self.last_result.data[start:end], tags=self.TLV_OBJECTS, context = self.DEFAULT_CONTEXT)
    
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
    
    def cmd_reset(self):
        """Reset the card."""
        # FIXME
        raise NotImplementedException
    
    COMMANDS = {
        "reset": cmd_reset,
        "parse_tlv": cmd_parsetlv,
        "show_applications": cmd_show_applications,
    }
    
    def _real_send(self, apdu):
        apdu_binary = apdu.render()
        
        if DEBUG:
            print ">> " + utils.hexdump(apdu_binary, indent = 3)
        
        result_binary = self.reader.transceive(apdu_binary)
        result = apdu.RESPONSE_CLASS(result_binary)
        
        self.last_apdu = apdu
        
        if DEBUG:
            print "<< " + utils.hexdump(result_binary, indent = 3)
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
    
    def send_apdu(self, apdu):
        if DEBUG:
            print "%s\nBeginning transaction %i" % ('-'*80, self._i)
        
        self.last_delta = None
        self._last_start = time.time()
        
        if hasattr(self, "before_send"):
            apdu = self.before_send(apdu)
        
        result = self._send_with_retry(apdu)
        
        if hasattr(self, "after_send"):
            result = self.after_send(result)
        
        if self._last_start is not None:
            self.last_delta = time.time() - self._last_start
            self._last_start = None
        
        if DEBUG:
            print "Ending transaction %i\n%s\n" % (self._i, '-'*80)
        self._i = self._i + 1
        
        self.last_result = result
        return result
    
    def check_sw(self, sw, purpose = None):
        if purpose is None: purpose = Card.PURPOSE_SUCCESS
        return self.match_statusword(self.STATUS_MAP[purpose], sw)
    
    def _get_atr(reader):
        return reader.get_ATR()
    _get_atr = staticmethod(_get_atr)
    
    def get_atr(self):
        return self._get_atr(self.reader)
    
    def can_handle(cls, reader):
        """Determine whether this class can handle a given card/connection object."""
        ATR = cls._get_atr(reader)
        def match_list(atr, list):
            for (knownatr, mask) in list:
                if mask is None:
                    if re.match(knownatr, binascii.hexlify(atr), re.I):
                        return True
                else:
                    if len(knownatr) != len(atr):
                        continue
                    if crypto_utils.andstring(knownatr, mask) == crypto_utils.andstring(atr, mask):
                        return True
            return False
        
        if not match_list(ATR, cls.STOP_ATRS) and match_list(ATR, cls.ATRS):
            return True
        return False
        
    can_handle = classmethod(can_handle)
    
    def get_prompt(self):
        return "(%s)" % self.get_driver_name()
    
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
    
    def get_driver_name(self):
        if len(self.DRIVER_NAME) > 1:
            names = [e for e in self.DRIVER_NAME if e != _GENERIC_NAME]
        else:
            names = self.DRIVER_NAME
        return ", ".join(names)
    
    def close_card(self):
        "Disconnect from a card"
        self.reader.disconnect()
        del self.reader

