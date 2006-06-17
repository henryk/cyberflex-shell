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

    def decode_auth_scheme(value):
        return " (0x%02x) " % ord(value) + { 
            0x1: "MaskTech scheme",
            0x2: "NETLINK compatible",
            0x4: "ICAO - basic access control",
        }.get(ord(value), "RFU")
    
    reset_retry_counter_byte_descriptions = (
        (0xFF, 0x00, None, "Retry counter is unused"),
        (0x80, 0x00, None, "Retry counter is reset upon successful both Authentication and RESET RETRY COUNTER"),
        (0x80, 0x80, None, "Retry counter can only be reset using RESET RETRY COUNTER"),
    )
    def decode_retry_counter(value):
        results = [" %s" % utils.hexdump(value, short=True)]
        results.append("Number of further allowed attempts: %i" % ord(value[0]))
        results.append("New value of the retry counter: %i\n\t%s" % (
            ord(value[1]) % 0x7F,
            "\n\t".join( utils.parse_binary( 
                ord(value[1]), MTCOS_Card.reset_retry_counter_byte_descriptions, True 
            ) )
        ) )
        return "\n".join(results)
    
    application_class_byte_descriptions = (
        (0x80, 0x80, None, "Secret file"),
        (0xC0, 0x80, None, "RFU"),
        (0xC0, 0xC0, None, "Keyfile"),
        (0xC8, 0xC8, None, "Possible application area: Signature"),
        (0xC4, 0xC4, None, "Possible application area: Encryption"),
        (0xC2, 0xC2, None, "Possible application area: Cryptographic checksum (Secure Messaging)"),
        (0xC1, 0xC1, None, "Possible application area: Authentication"),
    )
    cryptographic_algorithm_byte_descriptions = (
        (0x80, 0x00, None, "Symmetric Algorithm"),
        (0x8F, 0x08, None, "DES-Key"),
        (0x8E, 0x0C, None, "3DES-Key (Triple DES with 2 or 3 keys)"),
        (0x81, 0x00, None, " - ECB"),
        (0x81, 0x01, None, " - CBC"),
        (0x80, 0x80, None, "Asymmetric Algorithm"),
        (0xC0, 0x80, None, "Private Key"),
        (0xB0, 0x80, None, "RSA"),
        (0xB1, 0x81, None, " - Raw"),
        (0xB2, 0x82, None, " - PKCS#1 type 2 and 2"),
        (0xB4, 0x84, None, " - ISO/IEC 9796-2"),
    )
    def decode_83(value):
        ## 0x83 in 0xA5 is either "Cryptographic algorithm and allowed applications" or
        ##  "Default key reference for authentication commands in this environment"
        
        if len(value) >= 2:
            results = [" %s" % utils.hexdump(value, short=True)]
            results.append("Application class: 0x%02x\n\t%s" % (
                ord(value[0]),
                "\n\t".join( utils.parse_binary( 
                    ord(value[0]), MTCOS_Card.application_class_byte_descriptions, True 
                ) )
            ) )
            results.append("Cryptographic algorithm: 0x%02x\n\t%s" % (
                ord(value[1]),
                "\n\t".join( utils.parse_binary( 
                    ord(value[1]), MTCOS_Card.cryptographic_algorithm_byte_descriptions, True 
                ) )
            ) )
            return "\n".join(results)
        elif len(value) == 1:
            return "\nDefault key reference for authentication commands in this environment: 0x%02x" % ord(value[0])
    
    TLV_utils.identifier("context_A5")
    TLV_OBJECTS = {
        TLV_utils.context_FCP: {
            0xA5: (TLV_utils.recurse, "Proprietary security attributes", context_A5),
        },
        context_A5: {
            0x81: (decode_auth_scheme, "Authentication scheme"),
            0x82: (decode_retry_counter, "Retry counter"),
            0x83: (decode_83, "Cryptographic algorithm and allowed applications OR Default key reference"),
        }
    }
