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
    
    def decode_security_attributes(value):
        results = []
        if len(value) == 6:
            results.append( " " + utils.hexdump(value, short=True) )
        else:
            results.append("")
        
        for i in range(len(value)/6):
            part = value[i*6:i*6+6]
            partresponse = []
            if len(value) != 6:
                partresponse.append("Rule: %s\n" % utils.hexdump(part, short=True))
            
            if ord(part[0])&0xFE == 0x60:
                partresponse.append("Admin commands")
            else:
                partresponse.append("Command 0x%02X" % (ord(part[0])&0xFE) )
            all = not (ord(part[0])&0x01)
            
            secrets = []
            b2 = ord(part[1])
            for k in range(4):
                if b2 & (0x10<<k):
                    secrets.append("global password ID %s / SFID %s" % (hex(k+1), hex(k+0x11)) )
            for k in range(4):
                if b2 & (0x01<<k):
                    secrets.append("local password ID %s / SFID %s" % (hex(k+1), hex(k+0x11)) )
            
            b3 = ord(part[2])
            for k in range(8):
                if b3 & (0x01<<k):
                    secrets.append("global key SFID %s" % (k+1))
            
            b4 = ord(part[3])
            for k in range(8):
                if b4 & (0x01<<k):
                    secrets.append("local key SFID %s" % (k+1))
            
            if len(secrets) > 1:
                partresponse.append(
                    " needs\n\t    " + (all and "\n\tAND " or "\n\t OR ").join(secrets)
                )
            elif len(secrets) == 1:
                partresponse.append(" needs " + secrets[0])
            elif len(secrets) == 0:
                partresponse.append(" is always allowed")
            
            def decode_key(value):
                partresponse.append( (value&0x80) and "local" or "global" )
                partresponse.append(" key, ")
                partresponse.append( (value&0x40) and "random" or "any" )
                partresponse.append(" IV")
                if not (value & 0x20):
                    partresponse.append(", key number: ")
                    if (value & 0x1F) != 0x1F:
                        partresponse.append("0x%02x" % (value & 0x1F) )
                    else:
                        partresponse.append("RFU")
            
            b5 = ord(part[4])
            b6 = ord(part[5])
            if b5 == 0xff:
                partresponse.append("\nSecure messaging: no checksum required")
            else:
                partresponse.append("\nCryptographic checksum with ")
                decode_key(b5)
            
            if b6 == 0xff:
                partresponse.append("\nSecure messaging: no encryption required")
            elif not (b6 & 0x20):
                partresponse.append("\nEncryption with ")
                decode_key(b6)
            else:
                partresponse.append("\nEncryption: RFU")
            
            if len(value) != 6:
                results.append("\n\t".join("".join(partresponse).splitlines()))
            else:
                results.append("".join(partresponse))
        
        return "\n".join(results)
    
    physical_access_byte_descriptions = (
        (0xFF, 0x01, None, "Access by contacts according to ISO 7816-3"),
        (0xFF, 0x02, None, "Access by contactless (radio frequency) according to ISO 14443"),
        (0xFF, 0x03, None, "Dual interface"),
        (0xFC, 0x00, "RFU", None),
    )
    def decode_physical_access(value):
        return "\n"+"\n".join( 
            utils.parse_binary( 
                ord(value[0]), MTCOS_Card.physical_access_byte_descriptions, True 
            ) 
        )
    
    TLV_utils.identifier("context_A5")
    TLV_OBJECTS = {
        TLV_utils.context_FCP: {
            0x86: (decode_security_attributes, "Security attributes"),
            0x91: (decode_physical_access, "Following security attribute is valid for"),
            0xA1: (TLV_utils.recurse, "Security attribute template for physical access", TLV_utils.context_FCP),
            0xA5: (TLV_utils.recurse, "Proprietary security attributes", context_A5),
        },
        context_A5: {
            0x81: (decode_auth_scheme, "Authentication scheme"),
            0x82: (decode_retry_counter, "Retry counter"),
            0x83: (decode_83, "Cryptographic algorithm and allowed applications OR Default key reference"),
        }
    }
