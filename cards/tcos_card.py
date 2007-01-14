import utils, TLV_utils, crypto_utils, traceback
from iso_7816_4_card import *
import building_blocks

MODE_ECB = 0
MODE_CBC = 1
ALGO_IDEA = 0x1
ALGO_DES = 0x2
ALGO_DES3 = 0x3
SE_APDU = 1
SE_RAPDU = 2
SE_PSO = 3
TEMPLATE_CCT = 0xB4 # Template for Cryptographic Checksum
TEMPLATE_CT = 0xB8 # Template for Confidentiality
PI_ISO = 1 # Padding indicator for ISO padding (\x80\x00...)

class SE_Config:
    def __init__(self, config = None):
        self.algorithm = None
        self.mode = MODE_ECB
        self.keyref = 0
        self.keytype = 0
        self.iv = "\x00" * 8
        self.context = None
        self.operation = None
        if config is not None:
            self.parse(config)
    
    def parse(self, config):
        structure = TLV_utils.unpack(config)
        for data in structure:
            tag, length, value = data
            if tag == 0x80:
                self.mode = ord(value[0]) & 1
                algorithm = (ord(value[0]) >> 2) & 0x7
                self.algorithm = algorithm
            elif tag in (0x83, 0x84):
                self.keyref = ord(value)
                self.keytype = tag
            elif tag == 0x85:
                self.iv = "\x00" * 8
            elif tag == 0x87:
                self.iv = value
            elif tag == 0x88:
                self.iv = None ## FIXME
            else:
                print "Warning: Unknown MSE parameters: tag 0x%02x, length 0x%02x, value: %s" % (tag, length, utils.hexdump(value, short=True))

class TCOS_Security_Environment(object):
    MARK_ENCRYPT = "["
    
    def __init__(self, card):
        self.keys = {}
        self.card = card
        self.last_c_apdu = None
        self.last_r_apdu = None
        self.config = {}
    
    def have_config(self, context, operation):
        return self.config.has_key( (context, operation) )
    
    def get_config(self, context, operation):
        if not self.have_config(context, operation):
            self.set_config( context, operation, SE_Config() )
        return self.config[ context, operation ]
    
    def set_config(self, context, operation, config):
        self.config[ context, operation ] = config
        config.context = context
        config.operation = operation
    
    def before_send(self, apdu):
        self.last_c_apdu = apdu
        if apdu.cla & 0x0c in (0x08, 0x0c):
            apdu = self.process_apdu(apdu)
        return apdu
    
    def after_send(self, result):
        self.last_r_apdu = result
        if result.sw == self.card.SW_OK:
            if (self.last_c_apdu.cla & 0xf0) == 0x00:
                if self.last_c_apdu.ins == 0x22:
                    self.parse_mse(self.last_c_apdu)
            if (self.last_c_apdu.cla & 0x0c) in (0x08, 0x0c):
                result = self.process_rapdu(result)
        
        return result
    
    def process_apdu(self, apdu):
        if apdu.cla & 0x0c in (0x0c, 0x08):
            tlv_data = TLV_utils.unpack(apdu.data, with_marks = apdu.marks, include_filler=True)
            
            tlv_data = self.encrypt_command(tlv_data)
            tlv_data = self.authenticate_command(apdu, tlv_data)
            
            data = TLV_utils.pack(tlv_data, recalculate_length = True)
            new_apdu = C_APDU(apdu, data = data)
            
            return new_apdu
        else:
            return apdu
    
    def process_rapdu(self, rapdu):
        result = rapdu
        if self.last_c_apdu.cla & 0x0c in (0x0c, 0x08):
            tlv_c_data = TLV_utils.unpack(self.last_c_apdu.data)
            
            must_authenticate = False
            must_decrypt = False
            for data in tlv_c_data:
                if data[0] & ~0x01 == 0xBA:
                    for response_template in data[2]:
                        if response_template[0] == 0x8E:
                            must_authenticate = True
                        if response_template[0] & ~0x01 in (0x84, 0x86):
                            must_decrypt = True
            
            if must_authenticate or must_decrypt:
                tlv_data = TLV_utils.unpack(rapdu.data, include_filler=True)
                
                try:
                    if must_authenticate:
                        tlv_data = self.authenticate_response(tlv_data)
                    
                    if must_decrypt:
                        tlv_data = self.decrypt_response(tlv_data)
                    
                    #data = TLV_utils.pack(tlv_data, recalculate_length = True)
                    data = self.deformat_response(tlv_data)
                    new_apdu = R_APDU(rapdu, data = data)
                    
                    result = new_apdu
                except ValueError:
                    print "Warning: Can't authenticate/decrypt response due to exception being raised"
                    traceback.print_exc(limit=2)
            
        
        return result
    
    def deformat_response(self, tlv_data):
        WHITELIST = (0x84, 0x86)
        
        result = []
        is_ok = True
        for data in tlv_data:
            t = data[0] & ~0x01
            if t not in WHITELIST and t in range(0x80, 0xBF+1):
                is_ok = False # Unrecognized SM field present
        
        if is_ok:
            for data in tlv_data:
                t = data[0] & ~0x01
                value = data[2]
                if t in WHITELIST:
                    if t == 0x86:
                        result.append( value[1:] )
                    else:
                        result.append( value )
                else:
                    result.append( TLV_utils.pack( (data,), recalculate_length = True) )
        else:
            result.append( TLV_utils.pack( tlv_data, recalculate_length = True) )
        
        return "".join(result)

    def encrypt_command(self, tlv_data):
        config = self.get_config(SE_APDU, TEMPLATE_CT)
        
        if config.algorithm is None: ## FIXME: Find out the correct way to determine this
            return tlv_data
        
        result = []
        for data in tlv_data:
            tag, length, value, marks = data
            if self.MARK_ENCRYPT in marks and tag not in (0xff, 0x00):
                t = tag & ~(0x01)
                if t == 0x84:
                    value_ = self.pad(value)
                    print "| Tag 0x%02x, length 0x%02x, encrypting (with ISO padding): " % (tag, length)
                    print "|| " + "\n|| ".join( utils.hexdump( value_ ).splitlines() )
                    
                    value = crypto_utils.cipher( True, 
                        self.get_cipherspec(config),
                        self.get_key(config),
                        value_,
                        self.get_iv(config) )
                    
                    print "| Encrypted result of length 0x%02x:" % len(value)
                    print "|| " + "\n|| ".join( utils.hexdump(value).splitlines() )
                    print
                elif t == 0x86:
                    pi = value[0]
                    value_ = self.pad(value[1:], ord(pi))
                    print "| Tag 0x%02x, length 0x%02x, encrypting (with padding type %x): " % (tag, length, ord(pi))
                    print "|| " + "\n|| ".join( utils.hexdump( value_ ).splitlines() )
                    
                    value = pi + crypto_utils.cipher( True,
                        self.get_cipherspec(config),
                        self.get_key(config),
                        value_,
                        self.get_iv(config) )
                    
                    print "| Encrypted result of length 0x%02x:" % len(value)
                    print "|| " + "\n|| ".join( utils.hexdump(value).splitlines() )
                    print
                
                result.append( (tag, length, value) )
            else: # Ignore
                result.append(data[:3])
        
        return result
    
    def decrypt_response(self, tlv_data):
        config = self.get_config(SE_RAPDU, TEMPLATE_CT)
        
        if config.algorithm is None: ## FIXME: Find out the correct way to determine this
            return tlv_data
        
        result = []
        
        for data in tlv_data:
            tag, length, value = data[:3]
            marks = len(data) > 3 and data[3] or ()
            t = tag & ~(0x01)
            if t == 0x84:
                print
                print "| Tag 0x%02x, length 0x%02x, encrypted (with ISO padding): " % (tag, length)
                print "|| " + "\n|| ".join( utils.hexdump( value ).splitlines() )
                
                value_ = crypto_utils.cipher( False, 
                    self.get_cipherspec(config),
                    self.get_key(config),
                    value,
                    self.get_iv(config) )
                
                print "| Decrypted result of length 0x%02x:" % len(value_)
                print "|| " + "\n|| ".join( utils.hexdump(value_).splitlines() )
                
                value = self.unpad(value_)
                
                if False:
                    print "| Depadded result of length 0x%02x:" % len(value)
                    print "|| " + "\n|| ".join( utils.hexdump(value).splitlines() )
                marks = marks + (self.MARK_ENCRYPT,)
            elif t == 0x86:
                pi = value[0]
                print
                print "| Tag 0x%02x, length 0x%02x, decrypting (with padding type %x): " % (tag, length, ord(pi))
                print "|| " + "\n|| ".join( utils.hexdump( value[1:] ).splitlines() )
                
                value_ = crypto_utils.cipher( False,
                    self.get_cipherspec(config),
                    self.get_key(config),
                    value[1:],
                    self.get_iv(config) )
                
                print "| Decrypted result of length 0x%02x:" % len(value_)
                print "|| " + "\n|| ".join( utils.hexdump(value_).splitlines() )
                
                value = self.unpad(value_, ord(pi))
                
                if False:
                    print "| Depadded result of length 0x%02x:" % len(value)
                    print "|| " + "\n|| ".join( utils.hexdump(value).splitlines() )
                
                value = pi + value
                marks = marks + (self.MARK_ENCRYPT,)
            
            result.append( (tag, length, value, marks) )
        
        return result
    
    def calculate_cct(self, config, tlv_data, startblock = "", print_buffer=True):
        """Calculate the Cryptographic Checksum for some TLV data.
        tlv_data MUST be of the format generated by the include_filler=True parameter to unpack."""
        if print_buffer:
            print "| Calculating cryptographic checksum:"
        
        def do_block(buffer, block):
            block_ = self.pad("".join(block), pi = PI_ISO)
            offset = sum( [len(b) for b in buffer] )
            buffer.append(block_)
            del block[:]
            if print_buffer:
                print "|| " + "\n|| ".join( utils.hexdump( block_, offset = offset ).splitlines() )
        
        buffer = []
        if startblock != "":
            do_block(buffer, [startblock])
        
        block = []
        for data in tlv_data:
            tag, length, value = data[:3]
            if (tag & 0x01 == 0x01 or tag not in range(0x80, 0xbf+1)) and tag not in (0xff, 0x00):
                value_ = TLV_utils.pack( (data, ), recalculate_length=True )
                
                block.append( value_ )
            elif tag in (0xff, 0x00) and len(block) > 0:
                block.append( chr(tag) )
            else:
                if len(block) > 0:
                    do_block(buffer, block)
        
        if len(block) > 0:
            do_block(buffer, block)
        
        cct = crypto_utils.cipher( True, 
            self.get_cipherspec(config),
            self.get_key(config),
            "".join(buffer),
            self.get_iv(config) )[-8:]
        
        if print_buffer:
            print "| Result (Tag 0x8e, length: 0x%02x):" % len(cct)
            print "|| " + "\n|| ".join( utils.hexdump( cct ).splitlines() )
        
        return cct
    
    def authenticate_command(self, apdu, tlv_data):
        config = self.get_config(SE_APDU, TEMPLATE_CCT)
        
        if config.algorithm is None: ## FIXME: Find out the correct way to determine this
            return tlv_data
        
        result = []
        for data in tlv_data:
            if data[0] == 0x8e and data[1] == 0:
                startblock = ""
                if apdu.cla & 0x0c == 0x0c:
                    startblock = apdu.render()[:4]
                cct = self.calculate_cct(config, tlv_data, startblock)
                print
                
                data = tuple( (0x8e, len(cct), cct) + data[3:] )
            result.append(data)
        
        return result

    def authenticate_response(self, tlv_data):
        config = self.get_config(SE_RAPDU, TEMPLATE_CCT)
        
        if config.algorithm is None: ## FIXME: Find out the correct way to determine this
            return tlv_data
        
        print
        cct_claimed = None
        result = []
        
        for data in tlv_data:
            if data[0] == 0x8E:
                cct_claimed = data[2]
            else:
                result.append( data )
        
        if cct_claimed is None:
            print "| CRYPTOGRAPHIC CHECKSUM VERIFICATION ERROR"
            print "| No cryptographic checksum was included in the response"
            return tlv_data
        else:
            cct = self.calculate_cct(config, tlv_data)
        
        if len(cct_claimed) >= 4 and cct.startswith(cct_claimed):
            print "| Cryptographic checksum verifies OK"
            return result
        else:
            print "| CRYPTOGRAPHIC CHECKSUM VERIFICATION ERROR"
            print "| Is:"
            print "|| " + "\n|| ".join( utils.hexdump( cct_claimed ).splitlines() )
            print "| Should be:"
            print "|| " + "\n|| ".join( utils.hexdump( cct ).splitlines() )
            return tlv_data
    
    def get_cipherspec(self, config):
        g = globals()
        spec = ""
        for name in g.keys():
            if name.startswith("ALGO_") and config.algorithm == g[name]:
                spec = name.split("_",1)[1].lower()
        
        if spec == "":
            raise ValueError, "Unknown algorithm %s" % config.algorithm
        
        for name in g.keys():
            if name.startswith("MODE_") and config.mode == g[name]:
                spec = spec + "-" + name.split("_",1)[1].lower()
        
        if "-" not in spec:
            raise ValueError, "Unknown mode %s" % config.mode
        
        return spec
    
    def get_key(self, config):
        # FIXME stub for more intelligent key handling (e.g. asymmetric, session)
        return self.keys[config.keyref]
    
    def get_iv(self, config):
        # FIXME stub for more intelligent iv handling (e.g. last random)
        return config.iv
    
    def pad(self, data, pi = 1):
        if pi == 1:
            topad = 8 - len(data) % 8
            return data + "\x80" + ("\x00" * (topad-1))
        if pi == 2:
            return data
        else:
            raise ValueError, "Unknown padding indicator %s" % pi
    
    def unpad(self, data, pi = 1):
        if pi == 1:
            pos = len(data)-1
            while ord(data[pos]) != 0x80:
                if ord(data[pos]) != 0x00:
                    raise ValueError, "Padding error"
                pos = pos - 1
            return data[:pos]
        elif pi == 2:
            return data
        else:
            raise ValueError, "Unknown padding indicator %s" % pi
    
    def parse_mse(self, apdu):
        assert apdu.p1 & 0x0f == 1
        operation = apdu.p2
        
        if apdu.p1 & 0x10 == 0x10:
            self.set_config( SE_APDU,  operation, SE_Config(apdu.data) )
        if apdu.p1 & 0x20 == 0x20:
            self.set_config( SE_RAPDU, operation, SE_Config(apdu.data) )
        if apdu.p1 & 0xc0 == 0xc0:
            self.set_config( SE_PSO,   operation, SE_Config(apdu.data) )
    
    def set_key(self, keyref, keyvalue):
        self.keys[keyref] = keyvalue

class TCOS_Card(ISO_7816_4_Card,building_blocks.Card_with_80_aa):
    DRIVER_NAME = "TCOS 2.0"
    APDU_DELETE_FILE = C_APDU(cla=0x80,ins=0xe4)
    SELECT_P2 = 0x04
    
    ATRS = [
            ("3bba96008131865d0064........31809000..", None),
        ]
    
    file_status_descriptions = (
        (0xF9, 0x01, None, "Not invalidated"),
        (0xF9, 0x00, None, "Invalidated"),
        (0xFC, 0x04, None, "Not permanent"),
        (0xFC, 0x00, None, "Permanent"),
        (0xF2, 0x00, "RFU", None),
    )
    iftd_byte_1_descriptions = (
        (0x80, 0x00, None, "Data file"),
        (0xFC, 0x00, None, "RFU"),
        (0x83, 0x00, None, " - general data file"),
        (0x83, 0x01, None, " - system file EF_ATR"),
        (0x83, 0x02, None, " - system file EF_GDO"),
        (0x83, 0x03, None, " - system file EF_SIGLimit"),
        (0x80, 0x80, None, "Secret file"),
        (0xC0, 0x80, None, " - Password file"),
        (0xFF, 0x80, None, "RFU"),
        (0xC0, 0xC0, None, " - Key file"),
        (0xC8, 0xC8, None, "    - signature"),
        (0xC4, 0xC4, None, "    - encryption"),
        (0xC2, 0xC2, None, "    - mac"),
        (0xC1, 0xC1, None, "    - authenticate"),
        (0xCF, 0xC0, None, "RFU"),
    )
    iftd_byte_3_descriptions = (
        (0x10, 0x00, None, "Symmetric algorithm"),
        (0x1C, 0x00, None, " - RFU"),
        (0x1C, 0x04, None, " - IDEA"),
        (0x1C, 0x08, None, " - DES"),
        (0x1C, 0x0C, None, " - DES3"),
        (0x10, 0x10, None, "Asymmetric algorithm"),
        (0x9C, 0x10, None, " - RSA, Public Key"),
        (0x9C, 0x90, None, " - RSA, Private Key"),
        (0x63, 0x00, "RFU", None),
    )
    def decode_file_descriptor_extension(value):
        result = [" "+utils.hexdump(value, short=True)]
        if len(value) >= 1:
            result.append("File status: %s" % utils.hexdump(value[0], short=True))
            result.append("\t" + "\n\t".join(
                utils.parse_binary( 
                    ord(value[0]), TCOS_Card.file_status_descriptions, True 
                ) )
            )
        
        if len(value) >= 2:
            is_secret = (ord(value[1]) & 0x80 == 0x80)
            is_key = (ord(value[1]) & 0xC0 == 0xC0)
            
            if is_key:
                iftd = value[1:4]
            elif is_secret:
                iftd = value[1:3]
            else:
                iftd = value[1:2]
            
            result.append("Internal File Type Descriptor: %s" % utils.hexdump(iftd, short=True))
            if len(iftd) >= 1:
                result.append("\tFile Type: %s" % utils.hexdump(iftd[0], short=True))
                result.append("\t\t" + "\n\t\t".join(
                    utils.parse_binary( 
                        ord(iftd[0]), TCOS_Card.iftd_byte_1_descriptions, True 
                    ) )
                )
            
            if len(iftd) >= 2:
                result.append("\tNumber of secret: %i (0x%x)" % ((ord(iftd[1])&0x1F,)*2) )
            
            if len(iftd) >= 3:
                result.append("\tCryptographic algorithm: %s" % utils.hexdump(iftd[2], short=True))
                result.append("\t\t" + "\n\t\t".join(
                    utils.parse_binary( 
                        ord(iftd[2]), TCOS_Card.iftd_byte_3_descriptions, True 
                    ) )
                )
            
            fbz = value[1+len(iftd):]
            if len(fbz) == 2:
                result.append("\tVerification failure counter (FBZ): %s" % utils.hexdump(fbz, short=True))
                if fbz == "\x00\x00":
                    result.append("\t\tFBZ unused")
                else:
                    result.append("\t\tCurrent value: %i (0x%x)%s" % (
                        ord(fbz[0]), ord(fbz[0]),
                        ord(fbz[0]) == 0 and (ord(fbz[1]) != 0 and " (Secret locked)" or " (FBZ unused)") or "")
                    )
                    resetmode = ord(fbz[1])
                    result.append("\t\tReset value: %i (0x%x)%s" % (
                        resetmode & 0x7F, resetmode & 0x7F,
                        resetmode == 0 and " (FBZ unused)" or (
                            resetmode & 0x80 == 0x00 and " (reset with unblock password and successful verification)"
                            or " (reset only with unblock password)")
                        )
                    )
                
        
        return "\n".join(result)

    # This is similar to MTCOS_Card.decode_security_attributes but not identical
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
                    secrets.append("global password with number %s" % hex(k) )
            for k in range(4):
                if b2 & (0x01<<k):
                    secrets.append("local password with number %s" % hex(k) )
            
            b3 = ord(part[2])
            for k in range(8):
                if b3 & (0x01<<k):
                    secrets.append("global key with number %s" % k)
            
            b4 = ord(part[3])
            for k in range(8):
                if b4 & (0x01<<k):
                    secrets.append("local key with number %s" % k)
            
            if len(secrets) > 1:
                partresponse.append(
                    " needs\n\t    " + (all and "\n\tAND " or "\n\t OR ").join(secrets)
                )
            elif len(secrets) == 1:
                partresponse.append(" needs " + secrets[0])
            elif len(secrets) == 0:
                partresponse.append(" always allowed")
            
            def decode_key(value):
                partresponse.append( (value&0x80) and "local" or "global" )
                partresponse.append(" key, ")
                partresponse.append( (value&0x40) and "random" or "any" )
                partresponse.append(" IV")
                if not (value & 0x20):
                    partresponse.append(", key with number: ")
                    if (value & 0x1F) != 0x1F:
                        partresponse.append("0x%02x" % (value & 0x1F) )
                    else:
                        partresponse.append("RFU")
            
            b5 = ord(part[4])
            b6 = ord(part[5])
            if b5 == 0xff and b6 == 0xff and len(secrets) <= 1:
                partresponse.append(", No secure messaging required")
            else:
                if b5 == 0xff:
                    partresponse.append("\nSecure messaging: no MAC required")
                else:
                    partresponse.append("\nCryptographic MAC with ")
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

    def __init__(self, *args, **kwargs):
        ISO_7816_4_Card.__init__(self,*args,**kwargs)
        self.cmd_clear_se()
    
    def cmd_clear_se(self):
        "Reset the host security environment"
        self.se = TCOS_Security_Environment(self)
    
    def cmd_set_key(self, ref, key, *args):
        "Set a key in the host security environment"
        self.se.set_key( int(ref,0), binascii.a2b_hex( "".join( (key + "".join(args)).split() ) ) )
    
    def delete_file(self, fid):
        result = self.send_apdu(
            C_APDU(self.APDU_DELETE_FILE, data = fid) 
        )
        return result

    def cmd_delete(self, file):
        "Delete a file"
        fid = binascii.a2b_hex("".join(file.split()))
        
        self.delete_file(fid)

    def before_send(self, apdu):
        return self.se.before_send(apdu)
    
    def after_send(self, result):
        return self.se.after_send(result)
    
    TLV_OBJECTS = {
        TLV_utils.context_FCP: {
            0x86: (decode_security_attributes, "Security attributes"),
            0x85: (decode_file_descriptor_extension, "File descriptor extension"),
        },
    }
    TLV_OBJECTS[TLV_utils.context_FCI] = TLV_OBJECTS[TLV_utils.context_FCP]

    COMMANDS = {
        "list_dirs": building_blocks.Card_with_80_aa.cmd_listdirs,
        "list_files": building_blocks.Card_with_80_aa.cmd_listfiles,
        "ls": building_blocks.Card_with_80_aa.cmd_list,
        "delete": cmd_delete,
        "clear_se": cmd_clear_se,
        "set_key": cmd_set_key,
        }
    
class TCOS_3_Card(TCOS_Card):
    DRIVER_NAME = "TCOS 3.0"
    APDU_DELETE_FILE = C_APDU(cla=0x80,ins=0xe4)
    SELECT_P2 = 0x04
    LS_L_SIZE_TAG = 0x80
    
    ATRS = [
            ("3bbf96008131fe5d0064........31c073f701d00090007d", None),
        ]
