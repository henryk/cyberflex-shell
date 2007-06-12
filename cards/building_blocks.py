"This module holds some commonly used card functionality that is not ISO"

from utils import C_APDU, R_APDU
import utils, TLV_utils

class Card_with_ls:
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
                ret = Card_with_ls._find_recursive(search_tag, value)
                if ret is not None: return ret
        return None
    _find_recursive = staticmethod(_find_recursive)

    _ls_l_template = "%(name)-12s\t%(type)3s\t%(size)4s"
    def cmd_list(self, *options):
        """List all EFs and DFs in current DF. Call with -l for verbose information (caution: deselects current file)"""
        dirs = self.list_x(self.LIST_X_DF)
        files = self.list_x(self.LIST_X_EF)
        
        if "-l" in options:
            response_DF = {}
            response_EF = {}
            for DF in dirs:
                response_DF[DF] = self.select_file(0x01, self.SELECT_P2, DF)
                self.select_file(0x03, 0x00, "")
            for EF in files:
                response_EF[EF] = self.select_file(0x02, self.SELECT_P2, EF)
        
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
                v = self._find_recursive(self.LS_L_SIZE_TAG, response_EF[FID].data)
                if v:
                    size = self._str_to_long(v)
                else:
                    size = "n/a"
                print self._ls_l_template % locals()
        else:
            print "\n".join( ["[%s]" % utils.hexdump(a, short=True) for a in dirs]
                + [" %s " % utils.hexdump(a, short=True) for a in files] )

class Card_with_80_aa(Card_with_ls):
    APDU_LIST_X = C_APDU("\x80\xaa\x01\x00\x00")
    LIST_X_DF = 1
    LIST_X_EF = 2
    LS_L_SIZE_TAG = 0x81

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

class Card_with_read_binary:
    DATA_UNIT_SIZE=1
    HEXDUMP_LINELEN=16
    
    def read_binary_file(self, offset = 0):
        """Read from the currently selected EF.
        Repeat calls to READ BINARY as necessary to get the whole EF."""
        
        if offset >= 1<<15:
            raise ValueError, "offset is limited to 15 bits"
        contents = ""
        had_one = False
        
        self.last_size = -1
        while True:
            command = C_APDU(self.APDU_READ_BINARY, p1 = offset >> 8, p2 = (offset & 0xff))
            result = self.send_apdu(command)
            if len(result.data) > 0:
                contents = contents + result.data
                offset = offset + (len(result.data) / self.DATA_UNIT_SIZE)
            
            if self.last_size == len(contents):
                break
            else:
                self.last_size = len(contents)
            
            if not self.check_sw(result.sw):
                break
            else:
                had_one = True
        
        if had_one: ## If there was at least one successful pass, ignore any error SW. It probably only means "end of file"
            self.sw_changed = False
        
        return contents, result.sw
    
    def cmd_cat(self):
        "Print a hexdump of the currently selected file (e.g. consecutive READ BINARY)"
        contents, sw = self.read_binary_file()
        self.last_result = R_APDU(contents + self.last_sw)
        print utils.hexdump(contents,linelen=self.HEXDUMP_LINELEN)
    
    COMMANDS = {
        "cat": cmd_cat,
    }
    
