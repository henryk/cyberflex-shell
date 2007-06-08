from generic_application import Application
import struct, sha, binascii, os, datetime, sys
from utils import hexdump, C_APDU
from tcos_card import SE_Config, TCOS_Security_Environment
from generic_card import Card
from iso_7816_4_card import ISO_7816_4_Card
import crypto_utils, tcos_card, TLV_utils, generic_card
from TLV_utils import identifier

identifier("context_mrtd")
identifier("context_EFcom")
for _i in range(1,17):
    identifier("context_EFdg%i" % _i)
del _i
identifier("context_EFsod")

class Passport_Security_Environment(TCOS_Security_Environment):
    def __init__(self, card):
        TCOS_Security_Environment.__init__(self, card)
        self.last_vanilla_c_apdu = None
        
        # Set up a fake SE config to be able to reuse the TCOS code
        self.set_key( 1, self.card.KSenc)
        enc_config = "\x80\x01\x0d\x83\x01\x01\x85\x00"
        self.set_key( 2, self.card.KSmac)
        mac_config = "\x80\x01\x0d\x83\x01\x02\x85\x00"
        
        self.set_config( tcos_card.SE_APDU,  tcos_card.TEMPLATE_CCT, SE_Config(mac_config) )
        self.set_config( tcos_card.SE_RAPDU, tcos_card.TEMPLATE_CCT, SE_Config(mac_config) )
        
        self.set_config( tcos_card.SE_APDU,  tcos_card.TEMPLATE_CT, SE_Config(enc_config) )
        self.set_config( tcos_card.SE_RAPDU, tcos_card.TEMPLATE_CT, SE_Config(enc_config) )
    
    def before_send(self, apdu):
        self.last_vanilla_c_apdu = C_APDU(apdu)
        if (apdu.cla & 0x80 != 0x80) and (apdu.CLA & 0x0C != 0x0C):
            # Transform for SM
            apdu.CLA = apdu.CLA | 0x0C
            apdu_string = binascii.b2a_hex(apdu.render())
            new_apdu = [apdu_string[:8]]
            new_apdu.append("YY")
            
            if apdu.case() in (3,4):
                new_apdu.append("87[01")
                new_apdu.append(binascii.b2a_hex(apdu.data))
                new_apdu.append("]")
            
            if apdu.case() in (2,4):
                if apdu.Le == 0:
                    apdu.Le = 0xe7 # FIXME: Probably not the right way
                new_apdu.append("97(%02x)" % apdu.Le)
            
            new_apdu.append("8E()00")
            
            new_apdu_string = "".join(new_apdu)
            apdu = C_APDU.parse_fancy_apdu(new_apdu_string)
        
        return TCOS_Security_Environment.before_send(self, apdu)
    
    def after_send(self, result):
        if (self.last_vanilla_c_apdu.cla & 0x80 != 0x80) and (self.last_vanilla_c_apdu.CLA & 0x0C != 0x0C):
            # Inject fake response descriptor so that TCOS_Security_Environment.after_send sees the need to authenticate/decrypt
            response_descriptor = "\x99\x00\x8e\x00"
            if self.last_vanilla_c_apdu.case() in (2,4):
                response_descriptor = "\x87\x00" + response_descriptor
            response_descriptor = "\xba" + chr(len(response_descriptor)) + response_descriptor
            
            self.last_c_apdu.data = self.last_c_apdu.data + response_descriptor
        
        return TCOS_Security_Environment.after_send(self, result)

    
    def _mac(self, config, data):
        (ssc,) = struct.unpack(">Q", self.card.ssc)
        ssc = ssc + 1
        self.card.ssc = struct.pack(">Q", ssc)
        return Passport_Application._mac(self.card.KSmac, data, self.card.ssc, dopad=False)

class Passport_Application(Application):
    DRIVER_NAME = ["Passport"]
    APDU_GET_RANDOM = C_APDU(CLA=0, INS=0x84, Le=0x08)
    APDU_MUTUAL_AUTHENTICATE = C_APDU(CLA=0, INS=0x82, Le=0x28)
    APDU_SELECT_FILE = C_APDU(INS=0xa4)
    DEFAULT_CONTEXT = context_mrtd
    
    AID_LIST = [
        "a0000002471001"
    ]
    STATUS_MAP = {
        Card.PURPOSE_SM_OK: ("6282", "6982", "6A82")
    }
    
    INTERESTING_FILES = [
        ("COM", "\x01\x1e",),
        ("SOD", "\x01\x1d",),
    ] + [ ("DG%s" % e, "\x01"+chr(e)) for e in range(1,19) ]
    
    def __init__(self, *args, **kwargs):
        self.ssc = None
        self.KSenc = None
        self.KSmac = None
        self.se = None
    
    def derive_key(Kseed, c):
        """Derive a key according to TR-PKI mrtds ICC read-only access v1.1 annex E.1.
        c is either 1 for encryption or 2 for MAC computation.
        Returns: Ka + Kb
        Note: Does not adjust parity. Nobody uses that anyway ..."""
        D = Kseed + struct.pack(">i", c)
        H = sha.sha(D).digest()
        Ka = H[0:8]
        Kb = H[8:16]
        return Ka + Kb
    derive_key = staticmethod(derive_key)
    
    def derive_seed(mrz2, verbose=0):
        """Derive Kseed from the second line of the MRZ according to TR-PKI mrtds ICC read-only access v1.1 annex F.1.1"""
        if verbose:
            print "MRZ_information: '%s' + '%s' + '%s'" % (mrz2[0:10], mrz2[13:20], mrz2[21:28])
        MRZ_information = mrz2[0:10] + mrz2[13:20] + mrz2[21:28]
        H = sha.sha(MRZ_information).digest()
        Kseed = H[:16]
        if verbose:
            print "SHA1('%s')[:16] =\nKseed   = %s" % (MRZ_information, hexdump(Kseed))
        return Kseed
    derive_seed = staticmethod(derive_seed)
    
    def cmd_perform_bac(self, mrz2, verbose=1):
        "Perform the Basic Acess Control authentication and establishment of session keys"
        Kseed = self.derive_seed(mrz2, verbose)
        Kenc = self.derive_key(Kseed, 1)
        Kmac = self.derive_key(Kseed, 2)
        if verbose:
            print "Kenc    = %s" % hexdump(Kenc)
            print "Kmac    = %s" % hexdump(Kmac)
            
            print
        result = self.send_apdu(self.APDU_GET_RANDOM)
        if not self.check_sw(result.sw):
            raise BACError, "SW after GET RANDOM was %02x%02x. Card refused to send rcd_icc. Should NEVER happen." % (result.sw1, result.sw2)
        
        rnd_icc = result.data
        if verbose:
            print "RND.icc = %s" % hexdump(rnd_icc)
        
        rndtmp = self._make_random(8 + 16)
        rnd_ifd = rndtmp[:8]
        Kifd = rndtmp[8:]
        if verbose:
            print "RND.ifd = %s" % hexdump(rnd_ifd)
            print "Kifd    = %s" % hexdump(Kifd, indent=10)
        
        S = rnd_ifd + rnd_icc + Kifd
        Eifd = crypto_utils.cipher(True, "des3-cbc", Kenc, S)
        Mifd = self._mac(Kmac, Eifd)
        if verbose:
            print "Eifd    = %s" % hexdump(Eifd, indent=10)
            print "Mifd    = %s" % hexdump(Mifd)
            
            print
        auth_apdu = C_APDU(self.APDU_MUTUAL_AUTHENTICATE, data = Eifd + Mifd)
        result = self.send_apdu(auth_apdu)
        if not self.check_sw(result.sw):
            raise BACError, "SW after MUTUAL AUTHENTICATE was %02x%02x. Card did not accept our BAC attempt" % (result.sw1, result.sw2)
        
        resp_data = result.data
        Eicc = resp_data[:-8]
        Micc = self._mac(Kmac, Eicc)
        if not Micc == resp_data[-8:]:
            raise ValueError, "Passport authentication failed: Wrong MAC on incoming data during Mutual Authenticate"
        
        if verbose:
            print "Eicc    = %s" % hexdump(Eicc, indent=10)
            print "Micc    = %s" % hexdump(Micc)
            print "Micc verified OK"
        
        R = crypto_utils.cipher(False, "des3-cbc", Kenc, Eicc)
        if verbose:
            print "R       = %s" % hexdump(R, indent=10)
        if not R[:8] == rnd_icc:
            raise BACError, "Passport authentication failed: Wrong RND.icc on incoming data during Mutual Authenticate"
        if not R[8:16] == rnd_ifd:
            raise BACError, "Passport authentication failed: Wrong RND.ifd on incoming data during Mutual Authenticate"
        Kicc = R[16:]
        
        if verbose:
            print "Kicc    = %s" % hexdump(Kicc)
            print
        
        KSseed = crypto_utils.operation_on_string(Kicc, Kifd, lambda a,b: a^b)
        self.KSenc = self.derive_key(KSseed, 1)
        self.KSmac = self.derive_key(KSseed, 2)
        self.ssc = rnd_icc[-4:] + rnd_ifd[-4:]
        
        if False:
            self.KSenc = binascii.a2b_hex("979EC13B1CBFE9DCD01AB0FED307EAE5")
            self.KSmac = binascii.a2b_hex("F1CB1F1FB5ADF208806B89DC579DC1F8")
            self.ssc =   binascii.a2b_hex("887022120C06C226")
        
        if verbose:
            print "KSseed  = %s" % hexdump(KSseed)
            print "KSenc   = %s" % hexdump(self.KSenc)
            print "KSmac   = %s" % hexdump(self.KSmac)
            print "ssc     = %s" % hexdump(self.ssc)
        
        self.se = Passport_Security_Environment(self)
    
    def before_send(self, apdu):
        if self.se:
            apdu = self.se.before_send(apdu)
        return apdu
    
    def after_send(self, result):
        if self.se:
            result = self.se.after_send(result)
        return result
    
    def _mac(key, data, ssc = None, dopad=True):
        if ssc:
            data = ssc + data
        if dopad:
            topad = 8 - len(data) % 8
            data = data + "\x80" + ("\x00" * (topad-1))
        a = crypto_utils.cipher(True, "des-cbc", key[:8], data)
        b = crypto_utils.cipher(False, "des-ecb", key[8:16], a[-8:])
        c = crypto_utils.cipher(True, "des-ecb", key[:8], b)
        return c
    _mac = staticmethod(_mac)
    
    def _make_random(len):
        "Get len random bytes"
        return os.urandom(len)
    _make_random = staticmethod(_make_random)
    
    def get_prompt(self):
        return "(%s)%s" % (self.get_driver_name(), self.se and "[SM]" or "")
        
    def check_sw(self, sw, purpose = None):
        if purpose is not Card.PURPOSE_SM_OK:
            return Card.check_sw(self, sw, purpose)
        else:
            return sw not in ("\x69\x87", "\x69\x88")
    
    def cmd_parse_biometrics(self):
        "Parse the biometric information contained in the last result."
        cbeff = CBEFF.from_data(self.last_result.data)
        basename = datetime.datetime.now().isoformat()
        for index, biometric in enumerate(cbeff.biometrics):
            biometric.store(basename= "biometric_%s_%02i" % (basename, index))
    
    def cmd_parse_passport(self, mrz2=None):
        "Test the Passport class"
        if mrz2 is None:
            p = Passport.from_card(self)
        else:
            p = Passport.from_card(self, ["",mrz2])
    
    def _read_ef(self, name):
        fid = None
        for n, f in self.INTERESTING_FILES:
            if n == name: break
        if fid is None:
            return
        
        result = self.open_file(fid, 0x0c)
        if self.check_sw(result.sw):
            self.cmd_cat()
            self.cmd_parsetlv()
    
    def cmd_read_com(self):
        "Read EF.COM"
        return self._read_ef("COM")
    def cmd_read_sod(self):
        "Read EF.SOD"
        return self._read_ef("SOD")
    def cmd_read_dg(self, dg):
        "Read EF.DGx"
        return self._read_ef("DG%s" % int(dg,0))
    
    COMMANDS = {
        "perform_bac": cmd_perform_bac,
        "read_com": cmd_read_com,
        "read_sod": cmd_read_sod,
        "read_dg": cmd_read_dg,
        "parse_biometrics": cmd_parse_biometrics,
        "parse_passport": cmd_parse_passport,
    }
    
    DATA_GROUPS = {
        0x61: (1, "Machine readable zone information"),
        0x75: (2, "Encoded face"),
        0x63: (3, "Encoded finger(s)"),
        0x76: (4, "Encoded iris(s)"),
        0x65: (5, "Displayed portrait"),
        0x66: (6, "Reserved for future use"),
        0x67: (7, "Displayed signature or usual mark"),
        0x68: (8, "Data feature(s)"),
        0x69: (9, "Structure feature(s)"),
        0x6A: (10, "Substance feature(s)"),
        0x6B: (11, "Additional personal data elements"),
        0x6C: (12, "Additional document data elements"),
        0x6D: (13, "Discretionary data elements"),
        0x6E: (14, "Reserved for future use"),
        0x6F: (15, "Active authentication public key info"),
        0x70: (16, "Persons to notify data element(s)"),
    }
    
    TLV_OBJECTS = {
        context_mrtd: {
            0x60: (TLV_utils.recurse, "EF.COM - Common data elements", context_EFcom),
            0x77: (TLV_utils.recurse, "EF.SOD - Security Data", context_EFsod),
        }
    }
    
    for _key, (_a, _b) in DATA_GROUPS.items():
        TLV_OBJECTS[context_mrtd][_key] = (TLV_utils.recurse, "EF.DG%i - %s" % (_a, _b), globals()["context_EFdg%i" % _a])
    del _key, _a, _b
    
    def decode_version_number(value):
        result = []
        while len(value) > 0:
            v, value = value[:2], value[2:]
            result.append(str(int(v)))
        return " "+".".join(result)
    
    def decode_tag_list(value):
        result = []
        for t in value:
            e = Passport_Application.DATA_GROUPS.get(ord(t))
            if e is None:
                result.append("Error: '%02X' is an unknown Data Group tag" % ord(t))
            else:
                result.append("DG%-2i - %s" % e)
        return "\n" + "\n".join(result)
    
    TLV_OBJECTS[context_EFcom] = {
        0x5F01: (decode_version_number, "LDS version number"),
        0x5F36: (decode_version_number, "Unicode version number"),
        0x5C: (decode_tag_list, "List of all data groups present")
    }
    
    def decode_mrz(value):
        l = len(value)/2
        return "\n" + value[:l] + "\n" + value[l:]
    
    TLV_OBJECTS[context_EFdg1] = {
        0x5F1F: (decode_mrz, "Machine Readable Zone data"),
    }
    
    identifier("context_biometric_group")
    identifier("context_biometric")
    identifier("context_biometric_header")
    
    TLV_OBJECTS[context_EFdg2] = {
        0x7F61: (TLV_utils.recurse, "Biometric Information Group", context_biometric_group)
    }
    
    TLV_OBJECTS[context_biometric_group] = {
        0x02: (TLV_utils.number, "Number of instances of this biometric"),
        0x7f60: (TLV_utils.recurse, "Biometric Information Template", context_biometric),
    }
    
    TLV_OBJECTS[context_biometric] = {
        0xA1: (TLV_utils.recurse, "Biometric Header Template (BHT)", context_biometric_header),
        0x5F2E: (TLV_utils.binary, "Biometric data"),
    }
    
    TLV_OBJECTS[context_biometric_header] = {
        0x80: (decode_version_number, "ICAO header version"),
        0x81: (TLV_utils.binary, "Biometric type"), # FIXME parse these datafields
        0x82: (TLV_utils.binary, "Biometric feature"),
        0x83: (TLV_utils.binary, "Creation date and time"),
        0x84: (TLV_utils.binary, "Validity period"),
        0x86: (TLV_utils.binary, "Creator of the biometric reference data (PID)"),
        0x87: (TLV_utils.binary, "Format owner"), 
        0x88: (TLV_utils.binary, "Format type"),
    }
    
class FAC:
    class Face:
        HEADER_FIELDS = [
            ("length", "I"),
            ("number_of_feature_points", "H"),
            ("gender", "B"),
            ("eye_color", "B"),
            ("hair_color", "B"),
            ("feature_mask", "3s"),
            ("expression", "H"),
            ("pose_yaw", "B"),
            ("pose_pitch", "B"),
            ("pose_roll", "B"),
            ("pose_uy", "B"),
            ("pose_up", "B"),
            ("pose_ur", "B"),
        ]
        IMAGE_FIELDS = [
            ("facial_image_type", "B"),
            ("image_data_type","B"),
            ("width","H"),
            ("height","H"),
            ("image_color_space","B"),
            ("source_type","B"),
            ("device_type","H"),
            ("quality","H"),
        ]
        
        def __init__(self, data, offset_, type):
            self.type = type
            offset = offset_
            fib = data[offset:offset+20]
            
            fields = struct.unpack(">"+"".join([e[1] for e in self.HEADER_FIELDS]), fib)
            for index, value in enumerate(fields):
                setattr(self, self.HEADER_FIELDS[index][0], value)
            
            self.feature_mask = 256**2 * self.feature_mask[0] + 256 * self.feature_mask[1] + self.feature_mask[2]
            
            offset = offset+20
            for i in range(self.number_of_feature_points):
                offset = offset+8 # FUTURE Does anyone use these feature points?
            
            iib = data[offset:offset+12]
            
            fields = struct.unpack(">"+"".join([e[1] for e in self.IMAGE_FIELDS]), iib)
            for index, value in enumerate(fields):
                setattr(self, self.IMAGE_FIELDS[index][0], value)
                print "%s=%s" % (self.IMAGE_FIELDS[index][0], value)
            
            offset = offset+12
            
            self.data = data[offset:offset_+self.length]
        
        FILE_EXTENSIONS = {
            0: "jpg",
            1: "jp2",
        }
        def store(self, basename):
            name = "%s.%s" % (basename, self.FILE_EXTENSIONS.get(self.image_data_type, "bin"))
            fp = file(name, "w")
            try:
                fp.write(self.data)
            finally:
                fp.close()
    
    def __init__(self, data, type=0x008):
        assert data[0:4] == "FAC\x00"
        assert data[4:8] == "010\x00"
        self.record_length, self.number_of_facial_images = struct.unpack(">IH", data[8:14])
        
        assert len(data) == self.record_length
        offset = 14
        
        self.faces = []
        
        for index in range(self.number_of_facial_images):
            self.faces.append( self.Face(data, offset, type) )
            offset += self.faces[-1].length
    
    def store(self, basename):
        for index, face in enumerate(self.faces):
            face.store(basename="%s_%02i" % (basename, index))
    
# Note: Probably all of the code in this class is wrong. I'm just guessing from examples and parts of specifications I didn't fully read --Henryk
class CBEFF:
    def __init__(self, structure, top_tag = 0x7F60):
        "Create a new CBEFF instance from a nested TLV structure (as returned by TLV_utils.unpack)."
        
        self.biometrics = []
        self.unknown_biometrics = []
        
        blocks = TLV_utils.tlv_find_tag(structure, top_tag)
        for block in blocks:
            self.addbiometric(block[2])
    
    def addbiometric(self, value):
        bht = value[0]
        bdb = value[1]
        
        format_owner = None
        format_type = None
        for d in bht[2]:
            t,l,v = d[:3]
            if t == 0x87:
                format_owner = 256*ord(v[0]) + ord(v[1])
            elif t == 0x88:
                format_type = 256*ord(v[0]) + ord(v[1])
        
        if not hasattr(self, "addbiometric_%s_%s" % (format_owner, format_type)):
            print "Unknown Biometric owner/type: %s/%s" % (format_owner, format_type)
            self.unknown_biometrics.append( (bht, bdb) )
            return
        else:
            return getattr(self, "addbiometric_%s_%s" % (format_owner, format_type))(bht, bdb)
    
    def addbiometric_257_8(self, bht, bdb):
        if not bdb[0] == 0x5F2E:
            self.unknown_biometrics.append( (bht, bdb) )
            return
        
        self.biometrics.append( FAC( bdb[2], type=0x0008 ) )
    
    def addbiometric_257_1281(self, bht, bdb):
        if not bdb[0] == 0x5F2E:
            self.unknown_biometrics.append( (bht, bdb) )
            return
        
        self.biometrics.append( FAC( bdb[2], type=0x0501) )
    
    def from_data(cls, data, offset = 0, length = None, **kwargs):
        if length is None:
            length = len(data) - offset
        structure = TLV_utils.unpack(data[offset:offset+length])
        return cls(structure=structure, **kwargs)
    from_data = classmethod(from_data)

class PassportParseError(Exception):
    pass
class BACError(Exception):
    pass

_default_empty_mrz_data = ("","")
class Passport(object):
    "An ICAO compliant travel document"
    COUNTRY_CODES = {
        # Source: http://www.highprogrammer.com/alan/numbers/mrp.html#countrycodes
        "AFG": ("Afghanistan", ""),
        "ALB": ("Albania", ""),
        "DZA": ("Algeria", ""),
        "ASM": ("American Samoa", ""),
        "AND": ("Andorra", ""),
        "AGO": ("Angola", ""),
        "AIA": ("Anguilla", ""),
        "ATA": ("Antarctica", ""),
        "ATG": ("Antigua and Barbuda", ""),
        "ARG": ("Argentina", ""),
        "ARM": ("Armenia", ""),
        "ABW": ("Aruba", ""),
        "AUS": ("Australia", ""),
        "AUT": ("Austria", ""),
        "AZE": ("Azerbaijan", ""),
        "BHS": ("Bahamas", ""),
        "BHR": ("Bahrain", ""),
        "BGD": ("Bangladesh", ""),
        "BRB": ("Barbados", ""),
        "BLR": ("Belarus", ""),
        "BEL": ("Belgium", ""),
        "BLZ": ("Belize", ""),
        "BEN": ("Benin", ""),
        "BMU": ("Bermuda", ""),
        "BTN": ("Bhutan", ""),
        "BOL": ("Bolivia", ""),
        "BIH": ("Bosnia and Herzegovina", ""),
        "BWA": ("Botswana", ""),
        "BVT": ("Bouvet Island", ""),
        "BRA": ("Brazil", ""),
        "IOT": ("British Indian Ocean Territory", ""),
        "BRN": ("Brunei Darussalam", ""),
        "BGR": ("Bulgaria", ""),
        "BFA": ("Burkina Faso", ""),
        "BDI": ("Burundi", ""),
        "KHM": ("Cambodia", ""),
        "CMR": ("Cameroon", ""),
        "CAN": ("Canada", ""),
        "CPV": ("Cape Verde", ""),
        "CYM": ("Cayman Islands", ""),
        "CAF": ("Central African Republic", ""),
        "TCD": ("Chad", ""),
        "CHL": ("Chile", ""),
        "CHN": ("China", ""),
        "CXR": ("Christmas Island", ""),
        "CCK": ("Cocos (Keeling) Islands", ""),
        "COL": ("Colombia", ""),
        "COM": ("Comoros", ""),
        "COG": ("Congo", ""),
        "COK": ("Cook Islands", ""),
        "CRI": ("Costa Rica", ""),
        "CIV": ("Ct d'Ivoire", ""),
        "HRV": ("Croatia", ""),
        "CUB": ("Cuba", ""),
        "CYP": ("Cyprus", ""),
        "CZE": ("Czech Republic", ""),
        "PRK": ("Democratic People's Republic of Korea", ""),
        "COD": ("Democratic Republic of the Congo", ""),
        "DNK": ("Denmark", ""),
        "DJI": ("Djibouti", ""),
        "DMA": ("Dominica", ""),
        "DOM": ("Dominican Republic", ""),
        "TMP": ("East Timor", ""),
        "ECU": ("Ecuador", ""),
        "EGY": ("Egypt", ""),
        "SLV": ("El Salvador", ""),
        "GNQ": ("Equatorial Guinea", ""),
        "ERI": ("Eritrea", ""),
        "EST": ("Estonia", ""),
        "ETH": ("Ethiopia", ""),
        "FLK": ("Falkland Islands (Malvinas)", ""),
        "FRO": ("Faeroe Islands", ""),
        "FJI": ("Fiji", ""),
        "FIN": ("Finland", ""),
        "FRA": ("France", ""),
        "FXX": ("France, Metropolitan", ""),
        "GUF": ("French Guiana", ""),
        "PYF": ("French Polynesia", ""),
        "GAB": ("Gabon", ""),
        "GMB": ("Gambia", ""),
        "GEO": ("Georgia", ""),
        "D":   ("Germany", ""),
        "GHA": ("Ghana", ""),
        "GIB": ("Gibraltar", ""),
        "GRC": ("Greece", ""),
        "GRL": ("Greenland", ""),
        "GRD": ("Grenada", ""),
        "GLP": ("Guadeloupe", ""),
        "GUM": ("Guam", ""),
        "GTM": ("Guatemala", ""),
        "GIN": ("Guinea", ""),
        "GNB": ("Guinea-Bissau", ""),
        "GUY": ("Guyana", ""),
        "HTI": ("Haiti", ""),
        "HMD": ("Heard and McDonald Islands", ""),
        "VAT": ("Holy See (Vatican City State)", ""),
        "HND": ("Honduras", ""),
        "HKG": ("Hong Kong", ""),
        "HUN": ("Hungary", ""),
        "ISL": ("Iceland", ""),
        "IND": ("India", ""),
        "IDN": ("Indonesia", ""),
        "IRN": ("Iran, Islamic Republic of", ""),
        "IRQ": ("Iraq", ""),
        "IRL": ("Ireland", ""),
        "ISR": ("Israel", ""),
        "ITA": ("Italy", ""),
        "JAM": ("Jamaica", ""),
        "JPN": ("Japan", ""),
        "JOR": ("Jordan", ""),
        "KAZ": ("Kazakhstan", ""),
        "KEN": ("Kenya", ""),
        "KIR": ("Kiribati", ""),
        "KWT": ("Kuwait", ""),
        "KGZ": ("Kyrgyzstan", ""),
        "LAO": ("Lao People's Democratic Republic", ""),
        "LVA": ("Latvia", ""),
        "LBN": ("Lebanon", ""),
        "LSO": ("Lesotho", ""),
        "LBR": ("Liberia", ""),
        "LBY": ("Libyan Arab Jamahiriya", ""),
        "LIE": ("Liechtenstein", ""),
        "LTU": ("Lithuania", ""),
        "LUX": ("Luxembourg", ""),
        "MDG": ("Madagascar", ""),
        "MWI": ("Malawi", ""),
        "MYS": ("Malaysia", ""),
        "MDV": ("Maldives", ""),
        "MLI": ("Mali", ""),
        "MLT": ("Malta", ""),
        "MHL": ("Marshall Islands", ""),
        "MTQ": ("Martinique", ""),
        "MRT": ("Mauritania", ""),
        "MUS": ("Mauritius", ""),
        "MYT": ("Mayotte", ""),
        "MEX": ("Mexico", ""),
        "FSM": ("Micronesia, Federated States of", ""),
        "MCO": ("Monaco", ""),
        "MNG": ("Mongolia", ""),
        "MSR": ("Montserrat", ""),
        "MAR": ("Morocco", ""),
        "MOZ": ("Mozambique", ""),
        "MMR": ("Myanmar", ""),
        "NAM": ("Namibia", ""),
        "NRU": ("Nauru", ""),
        "NPL": ("Nepal", ""),
        "NLD": ("Netherlands, Kingdom of the", ""),
        "ANT": ("Netherlands Antilles", ""),
        "NTZ": ("Neutral Zone", ""),
        "NCL": ("New Caledonia", ""),
        "NZL": ("New Zealand", ""),
        "NIC": ("Nicaragua", ""),
        "NER": ("Niger", ""),
        "NGA": ("Nigeria", ""),
        "NIU": ("Niue", ""),
        "NFK": ("Norfolk Island", ""),
        "MNP": ("Northern Mariana Islands", ""),
        "NOR": ("Norway", ""),
        "OMN": ("Oman", ""),
        "PAK": ("Pakistan", ""),
        "PLW": ("Palau", ""),
        "PAN": ("Panama", ""),
        "PNG": ("Papua New Guinea", ""),
        "PRY": ("Paraguay", ""),
        "PER": ("Peru", ""),
        "PHL": ("Philippines", ""),
        "PCN": ("Pitcairn", ""),
        "POL": ("Poland", ""),
        "PRT": ("Portugal", ""),
        "PRI": ("Puerto Rico", ""),
        "QAT": ("Qatar", ""),
        "KOR": ("Republic of Korea", ""),
        "MDA": ("Republic of Moldova", ""),
        "REU": ("Ruion", ""),
        "ROM": ("Romania", ""),
        "RUS": ("Russian Federation", ""),
        "RWA": ("Rwanda", ""),
        "SHN": ("Saint Helena", ""),
        "KNA": ("Saint Kitts and Nevis", ""),
        "LCA": ("Saint Lucia", ""),
        "SPM": ("Saint Pierre and Miquelon", ""),
        "VCT": ("Saint Vincent and the Grenadines", ""),
        "WSM": ("Samoa", ""),
        "SMR": ("San Marino", ""),
        "STP": ("Sao Tome and Principe", ""),
        "SAU": ("Saudi Arabia", ""),
        "SEN": ("Senegal", ""),
        "SYC": ("Seychelles", ""),
        "SLE": ("Sierra Leone", ""),
        "SGP": ("Singapore", ""),
        "SVK": ("Slovakia", ""),
        "SVN": ("Slovenia", ""),
        "SLB": ("Solomon Islands", ""),
        "SOM": ("Somalia", ""),
        "ZAF": ("South Africa", ""),
        "SGS": ("South Georgia and the South Sandwich Island", ""),
        "ESP": ("Spain", ""),
        "LKA": ("Sri Lanka", ""),
        "SDN": ("Sudan", ""),
        "SUR": ("Suriname", ""),
        "SJM": ("Svalbard and Jan Mayen Islands", ""),
        "SWZ": ("Swaziland", ""),
        "SWE": ("Sweden", ""),
        "CHE": ("Switzerland", ""),
        "SYR": ("Syrian Arab Republic", ""),
        "TWN": ("Taiwan Province of China", ""),
        "TJK": ("Tajikistan", ""),
        "THA": ("Thailand", ""),
        "MKD": ("The former Yugoslav Republic of Macedonia", ""),
        "TGO": ("Togo", ""),
        "TKL": ("Tokelau", ""),
        "TON": ("Tonga", ""),
        "TTO": ("Trinidad and Tobago", ""),
        "TUN": ("Tunisia", ""),
        "TUR": ("Turkey", ""),
        "TKM": ("Turkmenistan", ""),
        "TCA": ("Turks and Caicos Islands", ""),
        "TUV": ("Tuvalu", ""),
        "UGA": ("Uganda", ""),
        "UKR": ("Ukraine", ""),
        "ARE": ("United Arab Emirates", ""),
        "GBR": ("United Kingdom of Great Britain and Northern Ireland", "Citizen"),
        "GBD": ("United Kingdom of Great Britain and Northern Ireland", "Dependent territories citizen"),
        "GBN": ("United Kingdom of Great Britain and Northern Ireland", "National (overseas)"),
        "GBO": ("United Kingdom of Great Britain and Northern Ireland", "Overseas citizen"),
        "GBP": ("United Kingdom of Great Britain and Northern Ireland", "Protected Person"),
        "GBS": ("United Kingdom of Great Britain and Northern Ireland", "Subject"),
        "TZA": ("United Republic of Tanzania", ""),
        "USA": ("United States of America", ""),
        "UMI": ("United States of America Minor Outlying Islands", ""),
        "URY": ("Uruguay", ""),
        "UZB": ("Uzbekistan", ""),
        "VUT": ("Vanuatu", ""),
        "VEN": ("Venezuela", ""),
        "VNM": ("Viet Nam", ""),
        "VGB": ("Virgin Islands (Great Britian)", ""),
        "VIR": ("Virgin Islands (United States)", ""),
        "WLF": ("Wallis and Futuna Islands", ""),
        "ESH": ("Western Sahara", ""),
        "YEM": ("Yemen", ""),
        "ZAR": ("Zaire", ""),
        "ZMB": ("Zambia", ""),
        "ZWE": ("Zimbabwe", ""),
        
        # Other
        "UTO": ("Utopia", ""),
        "BDR": ("Bundesdruckerei", ""),
    }    
    def __init__(self, mrz_data = _default_empty_mrz_data, ignore_mrz_parse_error = False):
        """Initialize an instance. 
        Optional argument mrz_data must be a sequence of strings representing the individual lines (at least 
        two) from the machine readable zone."""
        self.given_mrz = mrz_data
        self.dg1_mrz = self.dg2_cbeff = None
        self.parse_failed = False
        self.parse_error = ""
        self.card = None
        
        try:
            if mrz_data is not _default_empty_mrz_data:
                self._parse_mrz(mrz_data)
        except PassportParseError:
            if not ignore_mrz_parse_error:
                self.parse_failed = True
                self.parse_error = sys.exc_info()[1]
    
    def from_card(cls, card, mrz_data = _default_empty_mrz_data):
        """Initialize an instance and populate it from a card.
        Mandatory argument card must be a Passport_Application object or at least an ISO_7816_4_Card object 
        (to which a select_application() call will be issued). This card object will then be used to fetch
        all data before returning from the constructor. Note that for a BAC protected passport you will need
        to specify at least the second element in mrz_data."""
        
        if not isinstance(card, Passport_Application):
            if not isinstance(card, ISO_7816_4_Card):
                raise ValueError, "card must be a Passport_Application object or a ISO_7816_4_Card object, not %s" % type(card)
            else:
                result = card.select_application(card.resolve_symbolic_aid("mrtd"))
                if not card.check_sw(result.sw):
                    raise EnvironmentError, "card did not accept SELECT APPLICATION, sw was %02x %02x" % (result.sw1, result.sw2)
                assert isinstance(card, Passport_Application)
        
        p = cls(mrz_data, ignore_mrz_parse_error=True)
        p.card = card
        tried_bac = False
        p.result_map_select = {}
        p.result_map_read = {}
        
        for name, fid in card.INTERESTING_FILES:
            result = card.open_file(fid, 0x0C)
            if not card.check_sw(result.sw) and not tried_bac and not mrz_data is _default_empty_mrz_data:
                tried_bac = True
                card.cmd_perform_bac(mrz_data[1], verbose=0)
                result = card.open_file(fid, 0x0C)
            
            p.result_map_select[fid] = result.sw
            if card.check_sw(result.sw):
                contents, sw = card.read_binary_file()
                if not card.check_sw(sw) and not tried_bac and not mrz_data is _default_empty_mrz_data:
                    tried_bac = True
                    card.cmd_perform_bac(mrz_data[1], verbose=0)
                    contents, sw = card.read_binary_file()
                
                p.result_map_read[fid] = sw
                if contents != "":
                    setattr(p, "contents_%s" % name, contents)
                    if hasattr(p, "parse_%s" % name):
                        getattr(p, "parse_%s" % name)(contents)
        
        return p
    from_card = classmethod(from_card)
    
    def from_file(cls, filename):
        """Initialize an instance and populate it from a savefile.
        Mandatory argument filename must be the name of a file that was previously generated with
        the to_file() method (or be in the same format)."""
    from_file = classmethod(from_file)
    
    def from_files(cls, basename = None, filemap = None):
        """Initialize an instance and populate it from a number of files.
        basename must be the base name of a set of files that were generated with the to_files() method. The 
        format is the same one that is being used by the Golden Reader Tool. Alternatively you may give
        the filemap argument which must be a mapping to filenames with the keys "COM", "SOD", "DG1", "DG2", etc.
        (Only COM, SOD and DG1 are mandatory.)
        One of basename or filemap _must_ be specified."""
    from_files = classmethod(from_files)
    
    def parse_DG1(self, contents):
        structure = TLV_utils.unpack(contents)
        try:
            mrz = TLV_utils.tlv_find_tag(structure, 0x5F1F, 1)[0][2]
        except IndexError:
            raise PassportParseError, "Could not find MRZ information in DG1"
        mrz_data = (mrz[:44], mrz[44:88])
        self.dg1_mrz = mrz_data
        self._parse_mrz(mrz_data)
    
    def parse_DG2(self, contents):
        self.dg2_cbeff = CBEFF.from_data(contents)
    
    def calculate_check_digit(data, digit=None, field=None):
        """Calculate a check digit. If digit is not None then it will be compared to the calculated
        check digit and a PassportParseError will be raised on a mismatch. Optional argument field
        will be used for the description in the exception (and is ignored otherwise)."""
        numbers = [
            (e.isdigit() and (int(e),) or (e=="<" and (0,) or (e.isalpha() and (ord(e)-55,) or (0,) ) ) )[0]
            for e in data
        ]
        checksum = sum([ e * [7,3,1][i%3] for i,e in enumerate(numbers) ]) % 10
        if not digit is None and not (digit.isdigit() and checksum == int(digit)):
            raise PassportParseError, "Incorrect check digit%s. Is %s, should be %s." % ((field is not None and " in field '%s'" % field or ""), checksum, digit)
        return checksum
    calculate_check_digit = staticmethod(calculate_check_digit)
    
    def _parse_mrz(self, mrz_data):
        self.type, self.issuer, self.name = "", "", ("", "")
        self.document_no, self.nationality, self.date_of_birth, self.sex, self.expiration_date, self.optional = "", "", "", "", "", ""
        
        if mrz_data[0].strip() != "":
            try:
                mrz1 = mrz_data[0].replace("<", " ")
                self.type = mrz1[0:2].strip()
                self.issuer = mrz1[2:5].strip()
                n = mrz1[5:].strip().split("  ", 1)
                self.name = [n[0]]
                self.name = self.name + n[1].split(" ")
            except IndexError:
                raise PassportParseError, "Some index error while parsing mrz1"
            
        if mrz_data[1].strip() != "":
            try:
                mrz2 = mrz_data[1]
                self.document_no = mrz2[:9].strip("<")
                if mrz2[9] == "<": # document number check digit, or filler character to indicate document number longer than 9 characters
                    expanded_document_no = True
                else:
                    expanded_document_no = False
                    self.calculate_check_digit(mrz2[:9], mrz2[9], "Document number")
                self.nationality = mrz2[10:13].strip("<")
                
                self.date_of_birth = mrz2[13:19]
                self.calculate_check_digit(mrz2[13:19], mrz2[19], "Date of birth")
                
                self.sex = mrz2[20]
                
                self.expiration_date = mrz2[21:27]
                self.calculate_check_digit(mrz2[21:27], mrz2[27], "Date of expiration")
                
                opt_field = mrz2[28:-2]
                if not expanded_document_no:
                    self.optional = opt_field.strip("<")
                    if mrz2[-2] != "<":
                        self.calculate_check_digit(opt_field, mrz2[-2], "Optional data")
                else:
                    splitted_opt_field = opt_field.split("<", 1)
                    self.document_no = self.document_no + splitted_opt_field[0][:-1]
                    self.calculate_check_digit(self.document_no, splitted_opt_field[0][-1], "Expanded document number")
                    
                    if len(splitted_opt_field) > 1:
                        self.optional = splitted_opt_field[1].strip("<")
                        if mrz2[-2] != "<":
                            self.calculate_check_digit(splitted_opt_field[1], mrz2[-2], "Optional data")
                
                self.calculate_check_digit(mrz2[0:10]+mrz2[13:20]+mrz2[21:43], mrz2[-1], "Second line of machine readable zone")
            except:
                raise PassportParseError, "Some index error while parsing mrz2"


if __name__ == "__main__":
    mrz1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    mrz2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<14"
    
    seed = Passport_Application.derive_seed(mrz2)
    assert seed == binascii.a2b_hex("239AB9CB282DAF66231DC5A4DF6BFBAE")
    
    k = Passport_Application.derive_key(seed, 1)
    print hexdump(k)

    print "----------------------------------------------------"
    sniff_mrz2 = "S1234567D5SGP6001010M0512310<<<<<<<<<<<<<<02"
    sniffed_Eifd = binascii.a2b_hex("".join("f7 62 81 a3 eb 7c 87 eb 6d 89 1e ec d2 8d 43 7d bf ab a0 bc 20 20 fd c4 3a 76 2a b6 ff 0c f5 61".split()))
    sniffed_Mifd = binascii.a2b_hex("".join("e1 34 04 96  3e 1c ba c8".split()))
    
    seed = Passport_Application.derive_seed(sniff_mrz2)
    k = Passport_Application.derive_key(seed, 2)
    print hexdump(Passport_Application._mac(k, sniffed_Eifd))
    print hexdump(sniffed_Mifd)
    
##    dg2 = file("testdg2","r").read()
##    cbeff = CBEFF.from_data(dg2)
##    for index, biometric in enumerate(cbeff.biometrics):
##        biometric.store(basename= "biometric_testdg2_%02i" % index)
    
    p = Passport([mrz1, mrz2])
