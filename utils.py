import pycsc, string, binascii, sys

_myprintable = " " + string.letters + string.digits + string.punctuation
def hexdump(data, indent = 0, short = False):
    r"""Generates a nice hexdump of data and returns it. Consecutive lines will 
    be indented with indent spaces. When short is true, will instead generate 
    hexdump without adresses and on one line.
    
    Examples: 
    hexdump('\x00\x41') -> \
    '0000:  00 41                                             .A              '
    hexdump('\x00\x41', short=True) -> '00 41 (.A)'"""
    
    def hexable(data):
        return " ".join([binascii.b2a_hex(a) for a in data])
    
    def printable(data):
        return "".join([e in _myprintable and e or "." for e in data])
    
    if short:
        return "%s (%s)" % (hexable(data), printable(data))
    
    result = ""
    (head, tail) = (data[:16], data[16:])
    pos = 0
    while len(head) > 0:
        if pos > 0:
            result = result + "\n%s" % (' ' * indent)
        result = result + "%04x:  %-48s  %-16s" % (pos, hexable(head), printable(head))
        pos = pos + len(head)
        (head, tail) = (tail[:16], tail[16:])
    return result

LIFE_CYCLES = {0x01: "Load file = loaded",
    0x03: "Applet instance / security domain = Installed",
    0x07: "Card manager = Initialized; Applet instance / security domain = Selectable",
    0x0F: "Card manager = Secured; Applet instance / security domain = Personalized",
    0x7F: "Card manager = Locked; Applet instance / security domain = Blocked",
    0xFF: "Applet instance = Locked"}

def parse_status(data):
    """Parses the Response APDU of a GetStatus command."""
    def parse_segment(segment):
        def parse_privileges(privileges):
            if privileges == 0x0:
                return "N/A"
            else:
                privs = []
                if privileges & (1<<7):
                    privs.append("security domain")
                if privileges & (1<<6):
                    privs.append("DAP DES verification")
                if privileges & (1<<5):
                    privs.append("delegated management")
                if privileges & (1<<4):
                    privs.append("card locking")
                if privileges & (1<<3):
                    privs.append("card termination")
                if privileges & (1<<2):
                    privs.append("default selected")
                if privileges & (1<<1):
                    privs.append("global PIN modification")
                if privileges & (1<<0):
                    privs.append("mandated DAP verification")
                return ", ".join(privs)
        
        lgth = ord(segment[0])
        aid = segment[1:1+lgth]
        lifecycle = ord(segment[1+lgth])
        privileges = ord(segment[1+lgth+1])
        
        print "aid length:       %i (%x)" % (lgth, lgth)
        print "aid:              %s" % hexdump(aid, indent = 18, short=True)
        print "life cycle state: %x (%s)" % (lifecycle, LIFE_CYCLES.get(lifecycle, "unknown or invalid state"))
        print "privileges:       %x (%s)\n" % (privileges, parse_privileges(privileges))

    pos = 0
    while pos < len(data):
        lgth = ord(data[pos])+3
        segment = data[pos:pos+lgth]
        parse_segment(segment)
        pos = pos + lgth

def _unformat_hexdump(dump):
    hexdump = " ".join([line[7:54] for line in dump.splitlines()])
    return binascii.a2b_hex("".join([e != " " and e or "" for e in hexdump]))


class APDU(list):
    """Class for an APDU that mostly behaves like a list."""
    OFFSET_CLA = 0
    OFFSET_INS = 1
    OFFSET_P1 = 2
    OFFSET_P2 = 3
    OFFSET_P3 = 4
    OFFSET_LC = 4
    OFFSET_LE = 4
    OFFSET_CONTENT = 5
    
    LC_AUTO = None

    def __init__(self, *args, **kwargs):
        """Creates a new APDU instance. Can be given positional parameters which 
        must be sequences of either strings (or strings themselves) or integers
        specifying byte values that will be concatenated in order. Alternatively
        you may give exactly one positional argument that is an APDU instance.
        The keyword arguments can then be used to override those values.
        Keywords recognized are: cla, ins, p1, p2, p3, lc, le, content.
        Note: only set the le parameter if you don't send data."""
        
        if len(args) == 1 and type(args[0]) == APDU:
            self.extend(args[0])
        else:
            for arg in args:
                if type(arg) == str:
                    self.extend(arg)
                elif hasattr(arg, "__iter__"):
                    for elem in arg:
                        if hasattr(elem, "__iter__"):
                            self.extend(elem)
                        else:
                            self.append(elem)
                else:
                    self.append(arg)
        
        if len(self) < 4:
            self.extend([0] * (4-len(self)))
        if len(self) < self.OFFSET_LC+1:
            self[self.OFFSET_LC:self.OFFSET_LC+1] = [self.LC_AUTO]
        
        le = None
        for (kw, arg) in kwargs.items():
            if kw == "cla":
                self[self.OFFSET_CLA] = arg
            elif kw == "ins":
                self[self.OFFSET_INS] = arg
            elif kw == "p1":
                self[self.OFFSET_P1] = arg
            elif kw == "p2":
                self[self.OFFSET_P2] = arg
            elif kw == "p3":
                self[self.OFFSET_P3:self.OFFSET_P3+1] = (arg,)
            elif kw == "lc":
                self[self.OFFSET_LC:self.OFFSET_LC+1] = (arg,)
            elif kw == "le":
                le = arg
            elif kw == "content":
                self[self.OFFSET_CONTENT:self.OFFSET_CONTENT+len(arg)] = arg
            else:
                raise TypeError, "Got an unexpected keyword argument '%s'" % kw
        
        if le is not None:
            if len(self) > self.OFFSET_CONTENT:
                raise TypeError, "le can't be set when there is data to send"
            else:
                self[self.OFFSET_LE:self.OFFSET_LE+1] = (le,)
        
        if self[self.OFFSET_LC] == self.LC_AUTO:
            if len(self) > self.OFFSET_CONTENT:
                self[self.OFFSET_LC] = len(self)-self.OFFSET_CONTENT
            else:
                del self[self.OFFSET_LC]
        
        for i in range(len(self)):
            t = type(self[i])
            if t == str:
                self[i] = ord(self[i])
            elif t != int:
                raise TypeError, "APDU must consist of ints or one-byte strings, not %s (index %s)" % (t, i)
    
    def __str__(self):
        result = "APDU(CLA=0x%x, INS=0x%x, P1=0x%x, P2=0x%x" % (
            self[self.OFFSET_CLA], self[self.OFFSET_INS],
            self[self.OFFSET_P1], self[self.OFFSET_P2])
        if len(self) == self.OFFSET_CONTENT:
            result = result + ", LE=0x%x)" % self[self.OFFSET_LE]
        elif len(self) > self.OFFSET_CONTENT:
            result = result + ", LC=0x%x) with %i(0x%x) bytes of contents" % (
                self[self.OFFSET_LC], len(self)-self.OFFSET_CONTENT, len(self)-self.OFFSET_CONTENT)
        else:
            result = result + ")"
        return result + ":\n" + hexdump(self.get_string())
    
    def __repr__(self):
        result = "APDU(cla=0x%x, ins=0x%x, p1=0x%x, p2=0x%x" % (
            self[self.OFFSET_CLA], self[self.OFFSET_INS],
            self[self.OFFSET_P1], self[self.OFFSET_P2])
        if len(self) == self.OFFSET_CONTENT:
            result = result + ", le=0x%x)" % self[self.OFFSET_LE]
        elif len(self) > self.OFFSET_CONTENT:
            result = result + ", lc=0x%x, content=%s)" % (
                self[self.OFFSET_LC], self[self.OFFSET_CONTENT:])
        else:
            result = result + ")"
        return result
    
    def get_string(self):
        """Return the contents of this APDU as a binary string."""
        return "".join([i is not None and chr(i) or "?" for i in self])

if __name__ == "__main__":
    response = """
0000:  07 A0 00 00 00 03 00 00 07 00 07 A0 00 00 00 62  ...............b
0010:  00 01 01 00 07 A0 00 00 00 62 01 01 01 00 07 A0  .........b......
0020:  00 00 00 62 01 02 01 00 07 A0 00 00 00 62 02 01  ...b.........b..
0030:  01 00 07 A0 00 00 00 03 00 00 01 00 0E A0 00 00  ................
0040:  00 30 00 00 90 07 81 32 10 00 00 01 00 0E A0 00  .0.....2........
0050:  00 00 30 00 00 90 07 81 42 10 00 00 01 00 0E A0  ..0.....B.......
0060:  00 00 00 30 00 00 90 07 81 41 10 00 00 07 00 0E  ...0.....A......
0070:  A0 00 00 00 30 00 00 90 07 81 12 10 00 00 01 00  ....0...........
0080:  09 53 4C 42 43 52 59 50 54 4F 07 00 90 00        .SLBCRYPTO....  
""" # 64kv1 vorher
    response = """
0000:  07 A0 00 00 00 03 00 00 0F 00 07 A0 00 00 00 62  ...............b
0010:  00 01 01 00 07 A0 00 00 00 62 01 01 01 00 07 A0  .........b......
0020:  00 00 00 62 01 02 01 00 07 A0 00 00 00 62 02 01  ...b.........b..
0030:  01 00 07 A0 00 00 00 03 00 00 01 00 08 A0 00 00  ................
0040:  00 30 00 CA 10 01 00 0E A0 00 00 00 30 00 00 90  .0..........0...
0050:  07 81 32 10 00 00 01 00 0E A0 00 00 00 30 00 00  ..2..........0..
0060:  90 07 81 42 10 00 00 01 00 0E A0 00 00 00 30 00  ...B..........0.
0070:  00 90 07 81 41 10 00 00 07 00 0E A0 00 00 00 30  ....A..........0
0080:  00 00 90 07 81 12 10 00 00 01 00 09 53 4C 42 43  ............SLBC
0090:  52 59 50 54 4F 07 00 90 00                       RYPTO....       
""" # komische Karte
    response = """
0000:  07 A0 00 00 00 03 00 00 07 00 07 A0 00 00 00 62  ...............b
0010:  00 01 01 00 07 A0 00 00 00 62 01 01 01 00 07 A0  .........b......
0020:  00 00 00 62 01 02 01 00 07 A0 00 00 00 62 02 01  ...b.........b..
0030:  01 00 07 A0 00 00 00 03 00 00 01 00 0E A0 00 00  ................
0040:  00 30 00 00 90 07 81 32 10 00 00 01 00 0E A0 00  .0.....2........
0050:  00 00 30 00 00 90 07 81 42 10 00 00 01 00 0E A0  ..0.....B.......
0060:  00 00 00 30 00 00 90 07 81 41 10 00 00 07 00 0E  ...0.....A......
0070:  A0 00 00 00 30 00 00 90 07 81 12 10 00 00 01 00  ....0...........
0080:  09 53 4C 42 43 52 59 50 54 4F 07 00 05 A0 00 00  .SLBCRYPTO......
0090:  00 01 01 00 90 00                                ......          
""" # 64kv1 nachher
    response = """
0000:  07 A0 00 00 00 03 00 00 07 00 07 A0 00 00 00 62  ...............b
0010:  00 01 01 00 07 A0 00 00 00 62 01 01 01 00 07 A0  .........b......
0020:  00 00 00 62 01 02 01 00 07 A0 00 00 00 62 02 01  ...b.........b..
0030:  01 00 07 A0 00 00 00 03 00 00 01 00 0E A0 00 00  ................
0040:  00 30 00 00 90 07 81 32 10 00 00 01 00 0E A0 00  .0.....2........
0050:  00 00 30 00 00 90 07 81 42 10 00 00 01 00 0E A0  ..0.....B.......
0060:  00 00 00 30 00 00 90 07 81 41 10 00 00 07 00 0E  ...0.....A......
0070:  A0 00 00 00 30 00 00 90 07 81 12 10 00 00 01 00  ....0...........
0080:  09 53 4C 42 43 52 59 50 54 4F 07 00 05 A0 00 00  .SLBCRYPTO......
0090:  00 01 01 00 06 A0 00 00 00 01 01 07 02 90 00     ............... 
""" # 64k1 nach setup
    #response = sys.stdin.read()
    #parse_status(_unformat_hexdump(response)[:-2])
    
    print APDU((1,2,3), cla=0x23, content="hallo", lc=None)
    print APDU(1,2,3,4,None,4,6)
    
    
