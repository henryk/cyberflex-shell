import utils
from iso_7816_4_card import *

class SECCOS_Card(ISO_7816_4_Card):
    DRIVER_NAME = ["SECCOS"]
    SELECT_P2 = 0x04
    
    ATRS = [
            ("3BFF1800FF8131FE4565630D07630764000D........0615..", None),
            ("3BFF1800FF8131FE4565630D08650764000D........0616..", None),
            ("3BFF1800FF8131FE45656311064002500010........0500..", None),
            ("3BFF1800FF8131FE45656311066202800011........0613..", None),
            ("3BFF1800FF8131FE45656311076402800011........0619..", None),
            ("3BFF1800FF8131FE45656311084302500010........0530..", None),
            ("3BFF1800FF8131FE45656311086602800011........0620..", None),
            ("3BFF9600FF8131FE4565631901500280000F........5012..", None),
            ("3BEF00FF8131FE45656311086602800011284004070620BC", None),
            ("3bff1800ff8131fe4565630d08680764000d91088000062128", None),
            
            ("3b8780018031807396128040", None), # T=CL
        ]
    
    APPLICATIONS = {
        "\x52\x4F\x4F\x54": ("MF", "Master File ZKA-Chipkarte"),
    }

    def decode_sfi_path(value):
        return " SFI: 0x%02x, path: %s" % (ord(value[0]) >> 3, utils.hexdump(value[1:], short=True))
    
    TLV_OBJECTS = {
        TLV_utils.context_FMD: {
            0x85: (decode_sfi_path, "SFI with path"),
        },
    }
    TLV_OBJECTS[TLV_utils.context_FCI] = TLV_OBJECTS[TLV_utils.context_FMD]
