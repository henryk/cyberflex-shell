from iso_7816_4_card import *
from generic_card import Card

class BasicCard_Card(ISO_7816_4_Card):
    DRIVER_NAME = ["Basic Card"]
    
    ATRS = [
        ("3BBC1800813120755A43.*", None), 
    ]

    STATUS_MAP = dict(ISO_7816_4_Card.STATUS_MAP)
    STATUS_MAP[Card.PURPOSE_GET_RESPONSE] = ()
    
    STATUS_WORDS = dict(ISO_7816_4_Card.STATUS_WORDS)
    STATUS_WORDS.update( {
        '61??': "Command should have been called with Le equal to %(SW2)i (0x%(SW2)02x)",
    } )

    def post_merge(self):
        self.STATUS_MAP[Card.PURPOSE_GET_RESPONSE] = ()
