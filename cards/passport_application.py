from generic_application import Application
import struct, sha, binascii
from utils import hexdump, C_APDU
from tcos_card import SE_Config, TCOS_Security_Environment
from generic_card import Card
import crypto_utils, tcos_card, TLV_utils
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
        assert self.check_sw(result.sw)
        
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
        assert self.check_sw(result.sw)
        
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
            raise ValueError, "Passport authentication failed: Wrong RND.icc on incoming data during Mutual Authenticate"
        if not R[8:16] == rnd_ifd:
            raise ValueError, "Passport authentication failed: Wrong RND.ifd on incoming data during Mutual Authenticate"
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
        "Get len random bytes from /dev/urandom"
        urand = file("/dev/urandom","r")
        try:
            r = urand.read(len)
        finally:
            urand.close()
        return r
    _make_random = staticmethod(_make_random)
    
    def get_prompt(self):
        return "(%s)%s" % (self.get_driver_name(), self.se and "[SM]" or "")
        
    def check_sw(self, sw, purpose = None):
        if purpose is not Card.PURPOSE_SM_OK:
            return Card.check_sw(self, sw, purpose)
        else:
            return sw not in ("\x69\x87", "\x69\x88")

    def _read_ef(self, fid):
        result = self.open_file(fid, 0x0c)
        if not result.sw == "\x6a\x82":
            self.cmd_cat()
            self.cmd_parsetlv()
    
    def cmd_read_com(self):
        "Read EF.COM"
        return self._read_ef("\x01\x1e")
    def cmd_read_sod(self):
        "Read EF.SOD"
        return self._read_ef("\x01\x1d")
    def cmd_read_dg(self, dg):
        "Read EF.DGx"
        return self._read_ef("\x01"+chr(int(dg,0)))
    
    COMMANDS = {
        "perform_bac": cmd_perform_bac,
        "read_com": cmd_read_com,
        "read_sod": cmd_read_sod,
        "read_dg": cmd_read_dg,
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
    
