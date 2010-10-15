import utils, binascii
from iso_card import *
from utils import C_APDU

class Java_Card(ISO_Card):
    DRIVER_NAME = ["Generic Java"]
    APPLICATIONS = {
        "\xa0\x00\x00\x00\x01\x01": ("muscle", "MUSCLE applet")
    }

