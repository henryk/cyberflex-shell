import utils
from iso_7816_4_card import *

class Starcos_Card(ISO_7816_4_Card):
    DRIVER_NAME = ["Starcos"]
    APDU_READ_BINARY = C_APDU(ins=0xb0,le=0xfe)
    
    def change_dir(self, fid = None):
        "Change to a child DF. Alternatively, change to MF if fid is None."
        if fid is None:
            return self.select_file(0x00, 0x0C, self.FID_MF)
        else:
            return self.select_file(0x00, 0x0C, fid)

    ATRS = list(ISO_Card.ATRS)
    ATRS.extend( [
            ("3bb794008131fe6553504b32339000d1", None),
        ] )
    
