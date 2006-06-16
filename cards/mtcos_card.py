import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class MTCOS_Card(ISO_7816_4_Card,building_blocks.Card_with_80_aa):
    DRIVER_NAME = "MTCOS"
    
    ATRS = [
            ("3bfe9100ff918171fe40004120001177b1024d54434f537301cf", None),
        ]
    
    COMMANDS = {
        "list_dirs": building_blocks.Card_with_80_aa.cmd_listdirs,
        "list_files": building_blocks.Card_with_80_aa.cmd_listfiles,
        "ls": building_blocks.Card_with_80_aa.cmd_list,
        }
