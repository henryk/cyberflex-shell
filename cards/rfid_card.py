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
        ("3B8180018080", None),
    ]
    
    def get_uid(self):
        result = self.send_apdu(utils.C_APDU(self.APDU_GET_UID))
        return result.data
    
    def cmd_get_uid(self):
        "Get the UID or SNR or PUPI of the currently connected card."
        uid = self.get_uid()
        print utils.hexdump(uid, short=True)
    
    COMMANDS = {
        "get_uid": cmd_get_uid,
    }
    
    STATUS_WORDS = dict(Card.STATUS_WORDS)
    STATUS_WORDS.update( {
        "\x62\x82": "End of file (or UID) reached before Le bytes",
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
    pass

class Mifare_Classic_1k_Card(Mifare_Classic_Card):
    DRIVER_NAME = ["Mifare Classic 1k"]
    
    ATRS = [
        # Classic 1k
        ("3b8f8001804f0ca000000306..000100000000..", None),
    ]
class Mifare_Classic_4k_Card(Mifare_Classic_Card):
    DRIVER_NAME = ["Mifare Classic 4k"]
    
    ATRS = [
        # Classic 4k
        ("3b8f8001804f0ca000000306..000200000000..", None),
    ]

class Mifare_Ultralight_Card(Mifare_Card):
    DRIVER_NAME = ["Mifare Ultralight"]
    HEXDUMP_LINELEN = 4
    
    ATRS = [
        # Ultralight
        ("3b8f8001804f0ca000000306..000300000000..", None),
    ]

class Mifare_DESfire_Card(RFID_Card):
    DRIVER_NAME = ["Mifare DESfire"]
    ATRS = [
        ("3B8180018080", None)
    ]
    STOP_ATRS = []
    
    STATUS_WORDS = {
        "\x91\x00": "Successful Operation",
        "\x91\x0C": "No changes done to backup files, CommitTransaction/AbortTransaction not necessary",
        "\x91\x0E": "Insufficient NV-Memory to complete command",
        "\x91\x1C": "Command code not supported",
        "\x91\x1E": "CRC or MAC does not match data. Padding bytes not valid",
        "\x91\x40": "Invalid key number specified",
        "\x91\x7E": "Length of command string invalid",
        "\x91\x9D": "Current configuration / status does not allow the requested command",
        "\x91\x9E": "Value of the parameter(s) invalid",
        "\x91\xA0": "Requested AID not present on PICC",
        "\x91\xA1": "Unrecoverable error within application, application will be disabled",
        "\x91\xAE": "Current authentication status does not allow the requested command",
        "\x91\xAF": "Additional data frame is expected to be sent",
        "\x91\xBE": "Attempt to read/write data from/to beyond the file's/record's limits. Attempt to exceed the limits of a value file.",
        "\x91\xC1": "Unrecoverable error within PICC, PICC will be disabled",
        "\x91\xCA": "Previous Command was not fully completed. Not all Frames were requested or provided by the PCD",
        "\x91\xCD": "PICC was disabled by an unrecoverable error",
        "\x91\xCE": "Number of Applications limited to 28, no additional CreateApplication possible",
        "\x91\xDE": "Creation of file/application failed because file/application with same number already exists",
        "\x91\xEE": "Could not complete NV-write operation due to loss of power, internal backup/rollback mechanism activated",
        "\x91\xF0": "Specified file number does not exist",
        "\x91\xF1": "Unrecoverable error within file, file will be disabled",
    }
    
    DEFAULT_CLA = 0x90
    
    def wrap_native(self, native_command):
        print repr(native_command)
        if len(native_command) > 1:
            apdu = utils.C_APDU(cla=self.DEFAULT_CLA, ins=native_command[0], data=native_command[1:], le=0)
        elif len(native_command) == 1:
            apdu = utils.C_APDU(cla=self.DEFAULT_CLA, ins=native_command[0], le=0)
        else:
            raise ValueError, "len(native_command) must be >= 1"
        
        result = self.send_apdu(apdu)
        
        return result.data, result.sw2
    
    def cmd_wrap_native(self, *args):
        "Wrap a native DESfire command into an ISO 7816 APDU"
        data, returncode = self.wrap_native( binascii.a2b_hex( "".join("".join(args).split()) ) )
        print utils.hexdump(data)
    
    COMMANDS = dict(RFID_Card.COMMANDS)
    COMMANDS.update({
        "wrap": cmd_wrap_native,
    })
