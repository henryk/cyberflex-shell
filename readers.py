try:
    import smartcard, smartcard.CardRequest
except ImportError:
    print >>sys.stderr, """Could not import smartcard module. Please install pyscard 
from http://pyscard.sourceforge.net/
If you can't install pyscard and want to continue using 
pycsc you'll need to downgrade to SVN revision 246.
"""
    raise

import sys, utils, getopt, binascii, time

class Smartcard_Reader(object):
    def list_readers(cls):
        "Return a list of tuples: (reader name, implementing object)"
        return []
    list_readers = classmethod(list_readers)
    
    
    _CONNECT_NO_CARD = object()
    _CONNECT_MUTE_CARD = object()
    _CONNECT_DONE = object()
    def _internal_connect(self):
        """Must implement the iterator protocol and yield 
        one of self._CONNECT_NO_CARD, self._CONNECT_MUTE_CARD or self._CONNECT_DONE.
        The iterator will not be called again after yielding _CONNECT_DONE, so it must
        clean itself up before that."""
        raise NotImplementedError, "Please implement in a sub-class"
    
    def connect(self):
        have_card = False
        printed = False
        for result in self._internal_connect():
            if result is self._CONNECT_DONE:
                have_card = True
                break
            elif result is self._CONNECT_MUTE_CARD:
                print "Card is mute or absent. Please retry."
            elif result is self._CONNECT_NO_CARD:
                if not printed:
                    print "Please insert card ..."
                    printed = True
        return have_card
    
    def get_ATR(self):
        "Get the ATR of the inserted card as a binary string"
        raise NotImplementedError, "Please implement in a sub-class"

    def transceive(self, data):
        "Send a binary blob, receive a binary blob"
        raise NotImplementedError, "Please implement in a sub-class"

    def disconnect(self):
        "Disconnect from the card and release all resources"
        raise NotImplementedError, "Please implement in a sub-class"

class PCSC_Reader(Smartcard_Reader):
    def __init__(self, reader):
        self._reader = reader
        self._name = str(reader)
        self._cardservice = None
    
    name = property(lambda self: self._name, None, None, "The human readable name of the reader")
    
    def list_readers(cls):
        try:
            return [ (str(r), cls(r)) for r in smartcard.System.readers() ]
        except smartcard.pcsc.PCSCExceptions.EstablishContextException:
            return []
    list_readers = classmethod(list_readers)
    
    def _internal_connect(self):
        unpatched = False
        while True:
            try:
                if not unpatched:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=0.1 )
                else:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=1 )
                
                self._cardservice = cardrequest.waitforcard()
                self._cardservice.connection.connect()
                del cardrequest
                yield self._CONNECT_DONE
            except TypeError:
                unpatched = True
            except (KeyboardInterrupt, SystemExit):
                raise
            except smartcard.Exceptions.CardRequestException:
                if sys.exc_info()[1].message.endswith("Command timeout."):
                    yield self._CONNECT_NO_CARD
                else:
                    raise
            except smartcard.Exceptions.CardRequestTimeoutException:
                yield self._CONNECT_NO_CARD
            except smartcard.Exceptions.NoCardException:
                yield self._CONNECT_MUTE_CARD
            except smartcard.Exceptions.CardConnectionException:
                yield self._CONNECT_MUTE_CARD
    
    def get_ATR(self):
        return smartcard.util.toASCIIString(self._cardservice.connection.getATR())
    
    def get_protocol(self):
        hresult, reader, state, protocol, atr = smartcard.scard.SCardStatus( self._cardservice.connection.component.hcard )
        return ((protocol == smartcard.scard.SCARD_PROTOCOL_T0) and (0,) or (1,))[0]

    PROTOMAP = {
        0: smartcard.scard.SCARD_PCI_T0,
        1: smartcard.scard.SCARD_PCI_T1,
    }
    
    def transceive(self, data):
        data_bytes = map(lambda x: ord(x), data)
        data, sw1, sw2 = self._cardservice.connection.transmit(data_bytes, protocol=self.PROTOMAP[self.get_protocol()])
        result_binary = map(lambda x: chr(x), data + [sw1,sw2])
        return result_binary
    
    def disconnect(self):
        self._cardservice.connection.disconnect()
        del self._cardservice
        self._cardservice = None
    
class ACR122_Reader(Smartcard_Reader):
    """This class implements ISO 14443-4 access through the
    PN532 in an ACR122 reader with firmware version 1.x"""
    def list_readers(cls):
        pcsc_readers = PCSC_Reader.list_readers()
        readers = []
        for name, obj in pcsc_readers:
            if name.startswith("ACS ACR 38U-CCID"):
                reader = cls(obj)
                readers.append( (reader.name, reader) )
        return readers
    list_readers = classmethod(list_readers)
    
    name = property(lambda self: self._name, None, None, "The human readable name of the reader")
    
    def __init__(self, parent):
        self._parent = parent
        self._name = self._parent.name+"-RFID"
        self._last_ats = None
    
    def pn532_transceive_raw(self, command):
        c_apdu = "\xff\x00\x00\x00" + chr(len(command)) + command
        r_apdu = self._parent.transceive(c_apdu)
        
        if len(r_apdu) == 2 and r_apdu[0] == "\x61":
            c_apdu = "\xff\xc0\x00\x00" + r_apdu[1]
            r_apdu = self._parent.transceive(c_apdu)
        
        return r_apdu
    
    def pn532_transceive(self, command):
        response = self.pn532_transceive_raw(command)
        
        if len(response) < 2 or response[-2:] != ["\x90", "\x00"]:
            raise IOError, "Couldn't communicate with PN532"
        
        if not (response[0] == "\xd5" and ord(response[1]) == ord(command[1])+1 ): 
            raise IOError, "Wrong response from PN532"
        
        return "".join(response[:-2])
    
    def pn532_acquire_card(self):
        # Turn antenna power off and on to forcefully reinitialize the card
        self.pn532_transceive("\xd4\x32\x01\x00")
        self.pn532_transceive("\xd4\x32\x01\x01")
        
        self._last_ats = []
        
        response = self.pn532_transceive("\xd4\x4a\x01\x00")
        r = utils.PN532_Frame(response)
        r.parse_result(0)
        if len(r.targets) > 0:
            self._last_ats = r.targets.values()[0].ats
            return True
        else:
            response = self.pn532_transceive("\xd4\x4a\x01\x03\x00")
            r = utils.PN532_Frame(response)
            r.parse_result(3)
            if len(r.targets) > 0:
                return True
    
    def _internal_connect(self):
        self._parent.connect()
        self.pn532_transceive("\xd4\x32\x05\x00\x00\x00")
        while True:
            if self.pn532_acquire_card():
                yield self._CONNECT_DONE
            else:
                yield self._CONNECT_NO_CARD
                time.sleep(1)
    
    def get_ATR(self):
        # FIXME Properly implement for PC/SC version 2
        if len(self._last_ats) == 0:
            return "\x3b\x80\x80\x01\x01"
        else:
            # Quick and dirty: Extract historical bytes from ATS
            hist_bytes = []
            if self._last_ats[0] > 1:
                interface_bytes = 0
                if self._last_ats[1] & 0x40: interface_bytes = interface_bytes + 1
                if self._last_ats[1] & 0x20: interface_bytes = interface_bytes + 1
                if self._last_ats[1] & 0x10: interface_bytes = interface_bytes + 1
                hist_bytes = self._last_ats[ (2+interface_bytes): ]
            if len(hist_bytes) > 15: hist_bytes = hist_bytes[:15]
            atr = [0x3b, 0x80 + len(hist_bytes), 0x80, 0x01] + hist_bytes
            atr.append( reduce(lambda a,b: a ^ b, atr) ^ 0x3b )
            return "".join(map(chr, atr))

    def transceive(self, data):
        # FIXME Properly determine target number
        response = self.pn532_transceive("\xd4\x40\x01" + data)
        if response[2] != "\x00":
            # FIXME Proper error processing
            raise IOError, "Error while transceiving"
        return response[3:]

    def disconnect(self):
        self._parent.disconnect()

def list_readers():
    "Collect readers from all known drivers"
    readers = PCSC_Reader.list_readers()
    readers.extend( ACR122_Reader.list_readers() )
    return readers

def connect_to(reader):
    "Open the connection to a reader"
    
    readerObject = None
    readers = list_readers()
    
    if isinstance(reader, int) or reader.isdigit():
        reader = int(reader)
        readerObject = readers[reader][1]
    else:
        for i, name, obj in readers:
            if str(name).startswith(reader):
                readerObject = obj
    
    if readerObject is None:
        readerObject = readers[0][1]
    
    print "Using reader: %s" % readerObject.name
    
    readerObject.connect()
    
    print "ATR:          %s" % utils.hexdump(readerObject.get_ATR(), short = True)
    return readerObject

class CommandLineArgumentHelper:
    OPTIONS = "r:l"
    LONG_OPTIONS = ["reader=", "list-readers"]
    exit_now = False
    reader = None
    
    def connect(self):
        "Open the connection to a card"
        
        if self.reader is None:
            self.reader = 0
        
        return connect_to(self.reader)
    
    def getopt(self, argv, opts="", long_opts=[]):
        "Wrapper around getopt.gnu_getopt. Handles common arguments, returns everything else."
        (options, arguments) = getopt.gnu_getopt(sys.argv[1:], self.OPTIONS+opts, self.LONG_OPTIONS+long_opts)
        
        unrecognized = []
        
        for (option, value) in options:
            if option in ("-r","--reader"):
                self.reader = value
            elif option in ("-l","--list-readers"):
                for i, (name, obj) in enumerate(list_readers()):
                    print "%i: %s" % (i,name)
                self.exit_now = True
            else:
                unrecognized.append( (option, value) )
        
        if self.exit_now:
            sys.exit()
        
        return unrecognized, arguments


if __name__ == "__main__":
    list_readers()
    
