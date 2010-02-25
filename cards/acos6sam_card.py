import utils, binascii
from iso_7816_4_card import *

class ACOS6SAM_Card(ISO_7816_4_Card):
    DRIVER_NAME = ["ACOS6-SAM"]
    SELECT_FILE_P1 = 0x00
    
    ATRS = [
            ("3bbe9600004103000000000000000000029000", None),
        ]
    STATUS_WORDS = dict(ISO_7816_4_Card.STATUS_WORDS)
    COMMANDS = dict(ISO_7816_4_Card.COMMANDS)

    # All of the following is for the PN532 and probably should go
    # in a separate class
    #################################################
    APDU_TRANSCEIVE_PN532 = C_APDU(cla=0xff, ins=0, p1=0, p2=0)
    
    def cmd_pn532(self, *cmd):
        "Transmit a command to the PN532 and receive the response"
        result = self.pn532_transceive(binascii.unhexlify("".join("".join(cmd).split())))
        print utils.hexdump(result.data)
        
        parsed = self.pn532_parse(result.data)
        if len(parsed) > 0:
            print "\n".join(parsed) + "\n"
    
    def cmd_pn532_poll(self):
        "Poll for cards in the field"
        self.cmd_pn532("d4 4a 01 00")
    
    def pn532_transceive(self, cmd):
        apdu = C_APDU(self.APDU_TRANSCEIVE_PN532, lc=len(cmd), data=cmd)
        response = self.send_apdu(apdu)
        return response
    
    def pn532_parse(self, response):
        result = []
        type = None
        cmd = None
        
        if len(response) == 0:
            pass
        elif response[0] == "\xd4":
            type="command"
        elif response[0] == "\xd5":
            type="response"
        else:
            result.append("Invalid PN532 direction header")
        
        if len(response) > 1: cmd = ord(response[1])
        
        if type is not None:
            desc = "PN532 %s (%s)" % (type, 
                self.PN532_COMMANDS.get(cmd & 0xfe, "Unknown command") )
            result.append(desc)
        
            if len(response) > 1:
                s = "pn532_parse_%s_%02X" % (type, cmd)
                if hasattr(self, s):
                    result.extend( getattr(self, s)(response[2:]) )
                elif len(response) > 2:
                    result.append( "No detailed decoding available" )
        
        return result
    
    def pn532_parse_response_03(self, response):
        return [ "Version: PN5%02X, firmware %i.%i (cap: %02X)" % tuple(map(ord, response)) ]
    
    def pn532_parse_response_05(self, response):
        result = ["Last error: %02X" % ord(response[0]),
            "External field: %s" % ( response[1] == "\x01" and "present" or "not present" ),
            "Number of targets: %i" % ord(response[2])]
        
        for i in range( (len(response)-4)/4 ):
            t = "Target %i: %i kbps receive, %i kbps send, type: %s" % (
                    ord(response[3+i*4]),
                    self.PN532_BIT_RATES.get( ord(response[3+i*4+1]), "XXX" ),
                    self.PN532_BIT_RATES.get( ord(response[3+i*4+2]), "XXX" ),
                    self.PN532_TAG_TYPES.get( ord(response[3+i*4+3]), "unknown" ),
                )
            result.append(t)
        
        result.append( "SAM status: %02X" % ord(response[-1]) )
        return result
    
    STATUS_WORDS.update( { 
        '\x63\x00': "Operation failed",
        '\x63\x01': "PN532 did not respond",
        '\x63\x27': "PN532 response checksum wrong",
        '\x63\x7f': "PN532 command wrong",
    } )

    COMMANDS.update( {
        "pn532": cmd_pn532,
        "pn532_poll": cmd_pn532_poll,
        } )
    
    PN532_COMMANDS = {
        0x00: "Diagnose",
        0x02: "GetFirmwareVersion",
        0x04: "GetGeneralStatus",
        0x06: "ReadRegister",
        0x08: "WriteRegister",
        0x0c: "ReadGPIO",
        0x0e: "WriteGPIO",
        0x10: "SetSerialBaudrate",
        0x12: "SetParameters",
        0x14: "SAMConfiguration",
        0x16: "PowerDown",
        0x32: "RFConfiguration",
        0x58: "RFRegulationTest",
        0x56: "InJumpForDEP",
        0x46: "InJumpForPSL",
        0x4A: "InListPassiveTarget",
        0x50: "InATR",
        0x4E: "InPSL",
        0x40: "InDataExchange",
        0x42: "InCommunicateThru",
        0x44: "InDeselect",
        0x52: "InRelease",
        0x54: "InSelect",
        0x60: "InPoll",
        0x8C: "TgInitAsTarget",
        0x92: "TgSetGeneralBytes",
        0x86: "TgGetData",
        0x8E: "TgSetData",
        0x94: "TgSetMetaData",
        0x88: "TgGetInitiatorCommand",
        0x90: "TgResponseToInitiator",
        0x8A: "TgGetTargetStatus",
    }
    
    PN532_BIT_RATES = {
        0x0: 106,
        0x1: 212,
        0x2: 424,
    }
    
    PN532_TAG_TYPES = {
        0x00: "Mifare, ISO 14443-3 A/B or ISO 18092 passive 106 kbps",
        0x10: "FeliCa or ISO 18092 passive 212/424 kbps",
        0x01: "ISO 18092 active",
        0x02: "Innovision Jewel",
    }
