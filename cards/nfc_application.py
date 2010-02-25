from generic_application import Application
import struct, binascii, os, datetime, sys, utils


class NFC_Application(Application):
    DRIVER_NAME = ["NFC Type 4"]
    SELECT_FILE_P1 = 0
    
    AID_LIST = [
        "d2760000850100"
    ]

    def cmd_parse_cc(self):
        "Read and parse the CC (Capability Container) EF"
        result = self.open_file("\xe1\x03")
        if self.check_sw(result.sw):
            contents, sw = self.read_binary_file()
            if len(contents) > 0:
                print utils.hexdump(contents,linelen=self.HEXDUMP_LINELEN)
                
                if len(contents) < 0xf:
                    print "Invalid CC EF, can't parse (too short: 0x%x bytes)" % len(contents)
                else:
                    cclen, version, MLe, MLc, ndef_control_tlv = struct.unpack('>HBHH8s', contents[:0xf])
                    
                    print "      CC length: %i (0x%x)%s" % (cclen, cclen, cclen == 0xffff and ", RFU" or "")
                    print "Mapping version: %i.%i" % (version >> 4, version & 0xf)
                    print "     Maximum Le: %i (0x%x)%s" % (MLe, MLe, MLe <= 0xe and ", RFU" or "")
                    print "     Maximum Lc: %i (0x%x)%s" % (MLc, MLc, MLc == 0x0 and ", RFU" or "")
                    
                    print "NDEF File Control TLV: %s" % utils.hexdump(ndef_control_tlv, short=True)
                    if len(contents) > 0xf:
                        print "More TLV blocks: %s" % utils.hexdump(contents[0xf:], short=True)
    
    COMMANDS = {
        "parse_cc": cmd_parse_cc,
    }
