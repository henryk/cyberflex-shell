import utils
from iso_7816_4_card import *

class ACOS6SAM_Card(ISO_7816_4_Card):
    DRIVER_NAME = ["ACOS6-SAM"]
    SELECT_FILE_P1 = 0x00
    
    ATRS = [
            ("3bbe9600004103000000000000000000029000", None),
        ]
