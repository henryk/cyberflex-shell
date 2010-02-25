try:
    import smartcard, smartcard.CardRequest
except ImportError:
    print >>sys.stderr, """Could not import smartcard module. Please install pyscard 
from http://pyscard.sourceforge.net/
If you can't install pyscard and want to continue using 
pycsc you'll need to downgrade to SVN revision 246.
"""
    raise
class Smartcard_Reader(object):
    def list_readers():
        "Return a list of tuples: (reader name, implementing object)"
        return []
    
    def connect(self):
        "Create a connection to this reader"
        raise NotImplementedError, "Please implement in a sub-class"
    
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
        return [ (str(r), cls(r)) for r in smartcard.System.readers() ]
    list_readers = classmethod(list_readers)
    
    def connect(self):
        unpatched = False
        printed = False
        while True:
            try:
                if not unpatched:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=0.1 )
                else:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=1 )
                
                self._cardservice = cardrequest.waitforcard()
                self._cardservice.connection.connect()
                break
            except TypeError:
                unpatched = True
            except (KeyboardInterrupt, SystemExit):
                raise
            except smartcard.Exceptions.CardRequestException:
                if sys.exc_info()[1].message.endswith("Command timeout."):
                    if not printed:
                        print "Please insert card ..."
                        printed = True
                else:
                    raise
            except smartcard.Exceptions.CardRequestTimeoutException:
                if not printed:
                    print "Please insert card ..."
                    printed = True
            except smartcard.Exceptions.NoCardException:
                print "Card is mute or absent. Please retry."
    
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

def list_readers():
    "Collect readers from all known drivers"
    readers = PCSC_Reader.list_readers()
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
    
    from utils import hexdump

    print "ATR:          %s" % hexdump(readerObject.get_ATR(), short = True)
    return readerObject

if __name__ == "__main__":
    list_readers()
    
