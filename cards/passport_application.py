from generic_application import Application
import struct, sha, binascii
from utils import hexdump, C_APDU
import crypto_utils

class Passport_Application(Application):
    DRIVER_NAME = "Passport"
    APDU_GET_RANDOM = C_APDU(CLA=0, INS=0x84, Le=0x08)
    APDU_MUTUAL_AUTHENTICATE = C_APDU(CLA=0, INS=0x82, Le=0x28)
    SW_OK = "\x90\x00"
    
    AID_LIST = [
        "a0000002471001"
    ]
    
    def __init__(self, *args, **kwargs):
        self.ssc = None
        self.KSenc = None
        self.KSmac = None
    
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
        assert result.sw == self.SW_OK
        
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
        assert result.sw == self.SW_OK
        
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
        
        if verbose:
            print "KSseed  = %s" % hexdump(KSseed)
            print "KSenc   = %s" % hexdump(self.KSenc)
            print "KSmac   = %s" % hexdump(self.KSmac)
            print "ssc     = %s" % hexdump(self.ssc)
    
    def _mac(key, data, ssc = None):
        if ssc:
            data = ssc + data
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
    
    COMMANDS = {
        "perform_bac": cmd_perform_bac,
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
    
