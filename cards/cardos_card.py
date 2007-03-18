import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class CardOS_Card(ISO_7816_4_Card,building_blocks.Card_with_ls):
    DRIVER_NAME = ["CardOS"]
    
    ATRS = [
            ("3bf2180002c10a31fe58c80874", None),
        ]

    APDU_LIST_X = C_APDU("\x80\x16\x01\x00\x00")
    LIST_X_DF = 0
    LIST_X_EF = 1
    LS_L_SIZE_TAG = 0x80

    STATUS_WORDS = ( {
        "6283": "File is deactivated",
        "6300": "Authentication failed",
        "6581": "EEPROM error, command aborted",
        "6700": "LC invalid",
        "6881": "Logical channel not supported",
        "6981": "Command can not be used for file structure",
        "6982": "Required access right not granted",
        "6983": "BS object blocked",
        "6984": "BS object has invalid format",
        "6985": "No random number available",
        "6986": "No current EF selected",
        "6987": "Key object for SM not found",
        "6988": "Key object used for SM has invalid format",
        "6A80": "Invalid parameters in data field",
        "6A81": "Function/mode not supported",
        "6A82": "File not found",
        "6A83": "Record/object not found",
        "6A84": "Not enough memory in file / in file system available",
        "6A85": "LC does not fit the TLV structure of the data field",
        "6A86": "P1/P2 invalid",
        "6A87": "LC does not fit P1/P2",
        "6A88": "Object not found (GET DATA)",
        "6C00": "LC does not fit the data to be sent (e.g. SM)",
        "6D00": "INS invalid",
        "6E00": "CLA invalid (Hi nibble)",
        "6F00": "Technical error:\n + It was tried to create more than 254 records in a file\n + Package uses SDK version which is not compatible to API version\n + Package contains invalid statements (LOAD EXECUTABLE)",
        "6F81": "File is invalidated because of checksum error (prop.)",
        "6F82": "Not enough memory available in XRAM",
        "6F83": "Transaction error (i.e. command must not be used in transaction)",
        "6F84": "General protection fault (prop.)",
        "6F85": "Internal failure of PK-API (e.g. wrong CCMS format)",
        "6F86": "Key Object not found",
        "6F87": "Chaining error",
        "6FFF": "Internal assertion (invalid internal error)\n + This error is no runtime error, but an internal error which can occur because of a programming error only.",
        "9000": "Command executed correctly",
        "9001": "Command exectued correctly; EEPROM weakness detected (EEPROM written with second trial; the EEPROM area overwritten has a limited lifetime only)",
        "9850": "Overflow using INCREASE / underflow using DECREASE"
    } )
    
    def list_x(self, x):
        "Get a list of x objects, where x is one of 0 (DFs) or 1 (EFs) or 2 (DFs and EFs)"
        ## FIXME I just guessed this information
        result = self.send_apdu(C_APDU(self.APDU_LIST_X, p1=x))
        
        files = []
        unpacked = TLV_utils.unpack(result.data)
        for tag, length, value in unpacked:
            if isinstance(value, list):
                for tag, length, value in value:
                    if tag == 0x86:
                        files.append(value)
            else:
                if tag == 0x86:
                    files.append(value)
        
        return files
    
    def cmd_listdirs(self):
        "List DFs in current DF"
        result = self.list_x(0)
        print "DFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    def cmd_listfiles(self):
        "List EFs in current DF"
        result = self.list_x(1)
        print "EFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    COMMANDS = {
        "list_dirs": cmd_listdirs,
        "list_files": cmd_listfiles,
        "ls": building_blocks.Card_with_ls.cmd_list,
        }
