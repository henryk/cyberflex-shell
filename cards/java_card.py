import utils, binascii
from generic_card import *
from utils import C_APDU

class Java_Card(Card):
    DRIVER_NAME = ["Generic Java"]
    APPLICATIONS = {
        "\xa0\x00\x00\x00\x01\x01": ("muscle", "MUSCLE applet")
    }
    
    def __init__(self, card = None):
        Card.__init__(self, card = card)

