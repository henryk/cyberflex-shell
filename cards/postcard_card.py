import utils, re
from iso_7816_4_card import *

class Postcard_Card(ISO_7816_4_Card):
    DRIVER_NAME = "Postcard"
    CLA = 0xbc
    APDU_GET_RESPONSE = C_APDU(cla=CLA,ins=0xc0)
    APDU_SELECT_FILE = C_APDU(cla=CLA,ins=0xa4)
    APDU_READ_BINARY = C_APDU(cla=CLA,ins=0xb0,le=0x80)

    
    ATRS = [ 
        ("3f65351002046c9000", None),
    ]

    def _get_binary(self, offset, length):
        command = C_APDU(self.APDU_READ_BINARY, p1 = offset >> 8, p2 = offset & 0xff, le = length)
        result = self.send_apdu(command)
        assert result.sw == self.SW_OK
        
        return result.data
    
    def _get_address(self, definition_data, offset):
        return ((ord(definition_data[offset]) * 256 + ord(definition_data[offset+1])) >> 5) << 3
    
    ZONE_ADDRESSES = [
        ("adl", 0x09C8),
        ("adt", 0x09CC),
        ("adc", 0x09D0),
        ("adm", 0x09D4),
        ("ad2", 0x09D8),
        ("ads", 0x09DC),
        ("ad1", 0x09E8),
    ]
    def cmd_calculate_zone_addresses(self):
        "Read the zone definitions and calculate the zone addresses"
        READSTART = 0x09c0
        definition_data = self._get_binary(READSTART, length=0x30)
        
        result = {}
        for name, offset in self.ZONE_ADDRESSES:
            result[name] = self._get_address(definition_data, (offset - READSTART)>>1)
        
        for name,_ in self.ZONE_ADDRESSES:
            print "%s: %04x" % (name, result[name])
    
    def cmd_read_identification_zone(self):
        "Read the identification zone"
        data = self._get_binary(0x0948, length=0x60)
        
        chaine_initiale = binascii.b2a_hex(data[4:])
        print "chaine initiale", chaine_initiale
        #suppression_des_3 = re.sub(r'x', '3', re.sub(r'3', '', re.sub(r'33', "x", chaine_initiale) ) )
        #suppression_des_3 = "".join(chaine_initiale.split("3")) + "0"
        suppression_des_3 = []
        still_there = True
        for index,char in enumerate(chaine_initiale):
            if still_there and index % 8 == 0:
                if char == "3":
                    continue
                else:
                    still_there = False
            suppression_des_3.append(char)
        suppression_des_3 = "".join(suppression_des_3)
        
        print "suppression des 3", suppression_des_3
        new_data = binascii.a2b_hex(suppression_des_3)
        print utils.hexdump(new_data)
        
    
    COMMANDS = {
        "calculate_zone_addresses": cmd_calculate_zone_addresses,
        "read_identification_zone": cmd_read_identification_zone,
    }
