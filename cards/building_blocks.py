"This module holds some commonly used card functionality that is not ISO"

from utils import C_APDU, R_APDU
import utils, TLV_utils

class Card_with_80_aa:
    APDU_LIST_X = C_APDU("\x80\xaa\x01\x00\x00")

    def list_x(self, x):
        "Get a list of x objects, where x is one of 1 (DFs) or 2 (EFs) or 3 (DFs and EFs)"
        result = self.send_apdu(C_APDU(self.APDU_LIST_X, p1=x))
        
        tail = result.data
        result_list = []
        while len(tail) > 0:
            head, tail = tail[:2], tail[2:]
            result_list.append(head)
        return result_list
    
    def cmd_listdirs(self):
        "List DFs in current DF"
        result = self.list_x(1)
        print "DFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    def cmd_listfiles(self):
        "List EFs in current DF"
        result = self.list_x(2)
        print "EFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    def _str_to_long(value):
        num = 0
        for i in value:
            num = num * 256
            num = num + ord(i)
        return num
    _str_to_long = staticmethod(_str_to_long)
    
    def _find_recursive(search_tag, data):
        while len(data) > 0:
            if ord(data[0]) in (0x00, 0xFF):
                data = data[1:]
                continue
            
            ber_class, constructed, tag, length, value, data = TLV_utils.tlv_unpack(data)
            if not constructed:
                if tag == search_tag:
                    return value
            else:
                ret = Card_with_80_aa._find_recursive(search_tag, value)
                if ret is not None: return ret
        return None
    _find_recursive = staticmethod(_find_recursive)

    _ls_l_template = "%(name)-12s\t%(type)3s\t%(size)4s"
    def cmd_list(self, *options):
        """List all EFs and DFs in current DF. Call with -l for verbose information (caution: deselects current file)"""
        dirs = self.list_x(1)
        files = self.list_x(2)
        
        if "-l" in options:
            response_DF = {}
            response_EF = {}
            for DF in dirs:
                response_DF[DF] = self.select_file(0x01, 0x00, DF)
                self.select_file(0x03, 0x00, "")
            for EF in files:
                response_EF[EF] = self.select_file(0x02, 0x00, EF)
        
        self.sw_changed = False
        
        if "-l" in options:
            print self._ls_l_template % {"name": "Name", "type": "Type", "size": "Size"}
            dirs.sort()
            files.sort()
            for FID in dirs:
                name = "[" + utils.hexdump(FID, short=True) + "]"
                type = "DF"
                size = ""
                print self._ls_l_template % locals()
            for FID in files:
                name = " " + utils.hexdump(FID, short=True) + " "
                type = "EF"
                size = self._str_to_long(self._find_recursive(0x81, response_EF[FID].data))
                print self._ls_l_template % locals()
        else:
            print "\n".join( ["[%s]" % utils.hexdump(a, short=True) for a in dirs]
                + [" %s " % utils.hexdump(a, short=True) for a in files] )
