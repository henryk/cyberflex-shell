import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class TCOS_Card(ISO_7816_4_Card,building_blocks.Card_with_80_aa):
    DRIVER_NAME = "TCOS"
    
    ATRS = [
            ("3bba96008131865d0064........31809000..", None),
        ]
    
    COMMANDS = {
        "list_dirs": building_blocks.Card_with_80_aa.cmd_listdirs,
        "list_files": building_blocks.Card_with_80_aa.cmd_listfiles,
        "ls": building_blocks.Card_with_80_aa.cmd_list,
        }
