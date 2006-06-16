import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class TCOS_Card(ISO_7816_4_Card,building_blocks.Card_with_80_aa):
    DRIVER_NAME = "TCOS"
    APDU_LIST_X = C_APDU("\x80\xaa\x01\x00\x00")
        
    ATRS = [
            ("3bba96008131865d0064057b0203318090007d", None),
        ]
    
    COMMANDS = {
        "list_dirs": building_blocks.Card_with_80_aa.cmd_listdirs,
        "list_files": building_blocks.Card_with_80_aa.cmd_listfiles,
        "ls": building_blocks.Card_with_80_aa.cmd_list,
        }
