import utils
from generic_card import *

class GSM_Card(Card):
    DRIVER_NAME = "GSM"
    APDU_GET_RESPONSE = C_APDU("\xa0\xC0\x00\x00")
    STATUS_MAP = {
        PURPOSE_RETRY: ("9F??", )
    }
    
    ATRS = [ 
        ("3bff9500ffc00a1f438031e073f62113574a334861324147d6", None),
    ]
    
    STATUS_WORDS = {
        '9F??': "Length '%(SW2)i (0x%(SW2)02x)' of the response data",
        '920?': lambda sw1, sw2: "Update successful but after using an internal retry routine '%i' times" % (sw2 % 16),
        '9240': "Memory problem",
        '9400': "No EF selected",
        '9402': "Out of range (invalid address)",
        '9404': "- File ID not found\n- Pattern not found",
        '9408': "File is inconsistent with the command",
        '9802': "No CHV initialized",
        '9804': "- Access condition not fulfilled\n- Unsuccessful CHV verification, at least one attempt left\n- unsuccesful UNBLOCK CHV verification, at least one attempt left\n- authentication failed",
        '9808': "In contradiction with CHV status",
        '9810': "In contradiction with invalidation status",
        '9840': "- Unsuccessful CHV verification, no attempt left\n- unsuccesful UNBLOCK CHV verification, no attempt left\n- CHV blocked\n- UNBLOCK CHV blocked",
        '9850': "Increase cannot be performed, Max value reached",
        "67??": "Incorrect parameter P3",
        "\x67\x00": "Incorrect parameter P3 (ISO:Wrong length)",
        "6B??": "Incorrect parameter P1 or P2",
        "\x6B\x00": "Incorrect parameter P1 or P2 (ISO:Wrong parameter(s) P1-P2)",
        "6D??": "Unknown instruction code given in the command",
        "\x6D\x00": "Unknown instruction code given in the command (ISO: Instruction code not supported or invalid)",
        "6E??": "Wrong instruction class given in the command",
        "\x6E\x00": "Wrong instruction class given in the command (ISO: Class not supported)",
        "6F??": "Technical problem with no diagnostic given",
        "\x6F\x00": "Technical problem with no diagnostic given (ISO: No precise diagnosis)",
        
    }
