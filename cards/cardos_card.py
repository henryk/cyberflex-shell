import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class CardOS_Card(ISO_7816_4_Card,building_blocks.Card_with_ls):
    DRIVER_NAME = "CardOS"
    
    ATRS = [
            ("3bf2180002c10a31fe58c80874", None),
        ]

    APDU_LIST_X = C_APDU("\x80\x16\x01\x00\x00")
    LIST_X_DF = 0
    LIST_X_EF = 1
    LS_L_SIZE_TAG = 0x80

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
