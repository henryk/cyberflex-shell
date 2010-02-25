from generic_application import Application
import struct, binascii, os, datetime, sys, time
from iso_7816_4_card import ISO_7816_4_Card
import utils, TLV_utils, generic_card


class VRS_Application(Application):
    DRIVER_NAME = ["VRS"]
    
    AID_LIST = [
        "d2760000254b414e4d303100",
        "d2760001354b414e4d303100",
    ]

class VrsTicket(object):
    def __init__(self):
        self._birthdate = None
        self._maindata = []
        self._mainblob = None
        self._rawdata = None
        self._tlvdata = None
        self._card = None
    
    def from_card(cls, card, record_no = 1):
        if not isinstance(card, VRS_Application):
            if not isinstance(card, ISO_7816_4_Card):
                raise ValueError, "card must be a VRS_Application object or a ISO_7816_4_Card object, not %s" % type(card)
            else:
                result = card.select_application(binascii.a2b_hex(VRS_Application.AID_LIST[0]))
                if not card.check_sw(result.sw):
                    raise EnvironmentError, "card did not accept SELECT APPLICATION, sw was %02x %02x" % (result.sw1, result.sw2)
                assert isinstance(card, VRS_Application)
        
        c = cls()
        c._card = card
        
        result = card.open_file("\x0c\x05")
        if card.check_sw(result.sw):
            contents = card.read_record(record_no, 4)
            if len(contents) > 0:
                c._parse( contents )
            else:
                raise KeyError, "No ticket in record no. %i" % record_no
        else:
            raise EnvironmentError, "card did not accept SELECT FILE, sw was %02x %02x" % (result.sw1, result.sw2)
        
        return c
    
    def _parse(self, contents):
        self._rawdata = contents
        self._tlvdata = TLV_utils.unpack(contents)
        
        tmp = TLV_utils.tlv_find_tag(self._tlvdata, 0xEA, num_results = 1)
        if len(tmp) == 0:
            raise ValueError, "Can't parse information file, tag 0xEA not found"
        tmp = TLV_utils.tlv_find_tag(tmp, 0x85, num_results = 1)
        if len(tmp) == 0:
            raise ValueError, "Can't parse information file, tag 0x85 not found"
        self._mainblob = tmp[0][2]
        
        tmp = self._mainblob
        some_id, tmp = tmp[:4], tmp[4:]
        
        ascii_field_len = ord(tmp[0])
        tmp = tmp[1:]
        
        ascii_field, tmp = tmp[:ascii_field_len], tmp[ascii_field_len:]
        self._maindata = ascii_field.split(" ")
        
        if len(tmp) > 0:
            if tmp[0] == "\x01":
                tmp = tmp[1:]
                birthdate_bin, tmp = tmp[:4], tmp[4:]
                
                birthdate = binascii.b2a_hex(birthdate_bin)
                self._birthdate = datetime.date( int(birthdate[0:4]), int(birthdate[4:6]), int(birthdate[6:8]) )
        
        if len(tmp) > 0:
            print "Warning: unparsed data trailing: %r" % tmp
        
    from_card = classmethod(from_card)
    
    def getter(index, encoding=None):
        def g(self):
            if self._maindata is None or len(self._maindata) <= index:
                return None
            if encoding is None:
                return unicode( self._maindata[index] )
            else:
                return unicode( self._maindata[index], encoding = encoding )
        
        return g
    
    def _get_alter(self):
        now = datetime.date.fromtimestamp( time.time() )
        diff = now.year-self.geburtsdatum.year
        thisyearsbirthday = datetime.date( now.year, self.geburtsdatum.month, self.geburtsdatum.day )
        if now < thisyearsbirthday: diff = diff - 1
        return diff
    
    def __str__(self):
        return "%s: %s %s" % (self.tickettyp, self.name_klar, self.abonr)
    
    
    tickettyp = property(getter(0))
    rnummer = property(getter(1))
    gueltigkeit = property(getter(2))
    feld4 = property(getter(3))
    name_raw = property(getter(4))
    vorname = property(lambda self: self.name_raw and "".join(self.name_raw.split(",_")[1:]).replace("_", " "))
    nachname = property(lambda self: self.name_raw and "".join(self.name_raw.split(",_")[:1]).replace("_", " "))
    name_klar = property(lambda self: self.vorname + " " + self.nachname)
    schule = abonr = property(getter(5,'cp850'))
    geburtsdatum = property(lambda self: self._birthdate)
    alter = property(lambda self: self._birthdate and self._get_alter())
    
    
