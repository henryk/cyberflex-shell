import utils
from generic_card import *
import building_blocks

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
    
    STATUS_WORDS = dict(Card.STATUS_WORDS)
    STATUS_WORDS.update( {
        "\x67\x00": "Wrong Length",
        "\x68\x00": "Class byte is not correct",
        "\x6a\x81": "Function not supported",
        "\x6b\x00": "Wrong parameters P1-P2",
    } )

class RFID_Storage_Card(building_blocks.Card_with_read_binary,RFID_Card):
    STOP_ATRS = []
    ATRS = []
    STATUS_MAP = dict(RFID_Card.STATUS_MAP)
    STATUS_MAP.update( {
        Card.PURPOSE_RETRY: ("6C??", ),
    } )
    
    APDU_READ_BINARY = utils.C_APDU(CLA=0xff, INS=0xb0, Le=0)
    COMMANDS = dict(building_blocks.Card_with_read_binary.COMMANDS)
    COMMANDS.update(RFID_Card.COMMANDS)

class Mifare_Card(RFID_Storage_Card):
    DATA_UNIT_SIZE=4

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
