import utils
from generic_card import *

class RFID_Card(Card):
    DRIVER_NAME = ["RFID"]
    APDU_GET_UID = utils.C_APDU(CLA=0xff, INS=0xCA, p1=0, p2=0, Le=0)
    
    ATRS = [
            # Contactless storage cards
            ("3b8f8001804f0ca000000306......00000000..", None),
            # All other cards that follow the general ATR format
            ("3b8.8001.*", None),
        ]
    
    STOP_ATRS = [
        # Mifare, handled below
        ("3b8f8001804f0ca000000306..000[1-3]00000000..", None),
    ]
    
    def get_uid(self):
        result = self.send_apdu(utils.C_APDU(self.APDU_GET_UID))
        return result.data
    
    def cmd_get_uid(self):
        uid = self.get_uid()
        print utils.hexdump(uid, short=True)
    
    COMMANDS = {
        "get_uid": cmd_get_uid,
    }

class RFID_Storage_Card(RFID_Card):
    STOP_ATRS = []
    ATRS = []

class Mifare_Card(RFID_Storage_Card):
    pass

class Mifare_Classic_Card(Mifare_Card):
    DRIVER_NAME = ["Mifare Classic"]
    
    ATRS = [
        # Classic 1k
        ("3b8f8001804f0ca000000306..000100000000..", None),
        # Classic 4k
        ("3b8f8001804f0ca000000306..000200000000..", None),
    ]

class Mifare_Ultralight_Card(Mifare_Card):
    DRIVER_NAME = ["Mifare Ultralight"]
    
    ATRS = [
        # Ultralight
        ("3b8f8001804f0ca000000306..000300000000..", None),
    ]
