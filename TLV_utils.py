import binascii, utils, re, sys

class identifier:
    """An identifier, because I'm too lazy to use quotes all over the place.
    Instantiating an object of this type registers a name in the current scope, essentially
    making each instantiation of this class equal to
        foo = identifier("foo")
    even when you only write
        identifier("foo")
    """
    def __init__(self,name):
        self.name = name
        sys._getframe(1).f_locals[name] = self
    def __str__(self):
        return self.name
    def __repr__(self):
        return "identifier(%r)" % self.name

identifier("context_FCP")
identifier("context_FMD")
identifier("context_FCI")
identifier("recurse")
identifier("binary")
identifier("number")
identifier("ascii")
identifier("utf8")

file_descriptor_byte_descriptions = [
    #mask  byte  no match match
    (0x80, 0x80, None,    "RFU"),
    (0xC0, 0x40, "non shareable", "shareable"),
    
    (0xB8, 0x00, None,    "working EF"),
    (0xB8, 0x08, None,    "internal EF"),
    (0xB8, 0x10, None,    "Reserved for proprietary uses"),
    (0xB8, 0x18, None,    "Reserved for proprietary uses"),
    (0xB8, 0x20, None,    "Reserved for proprietary uses"),
    (0xB8, 0x28, None,    "Reserved for proprietary uses"),
    (0xB8, 0x30, None,    "Reserved for proprietary uses"),
    (0xB8, 0x38, None,    "DF"),
    
    (0x87, 0x00, None,    "No file structure information given"),
    (0x87, 0x01, None,    "Transparent"),
    (0x87, 0x02, None,    "Linear fixed, no further info"),
    (0x87, 0x03, None,    "Linear fixed, SIMPLE-TLV"),
    (0x87, 0x04, None,    "Linear variable, no further info"),
    (0x87, 0x05, None,    "Linear variable, SIMPLE-TLV"),
    (0x87, 0x06, None,    "Cyclic, no further info"),
    (0x87, 0x07, None,    "Cyclic, SIMPLE-TLV"),
]

data_coding_byte_descriptions = [
    (0x60, 0x00, None,    "one-time write"),
    (0x60, 0x20, None,    "proprietary"),
    (0x60, 0x40, None,    "write OR"),
    (0x60, 0x60, None,    "write AND"),
]

life_cycle_status_byte_descriptions = [
    (0xF0, 0x00, "Proprietary", None),
    (0xFF, 0x00, None,    "No information given"),
    (0xFF, 0x01, None,    "Creation state"),
    (0xFF, 0x03, None,    "Initialisation state"),
    (0xFD, 0x05, None,    "Operational state (activated)"),
    (0xFD, 0x04, None,    "Operational state (deactivated)"),
    (0xFC, 0x0C, None,    "Termination state"),
]

def decode_file_descriptor_byte(value, verbose = True):
    result = " %s" % utils.hexdump(value, short=True)
    
    if not verbose:
        attributes = utils.parse_binary(ord(value[0]), file_descriptor_byte_descriptions, False)
        if len(value) > 1:
            attributes.append(
                "data coding byte, behavior of write functions: %s, data unit size in in nibbles: %i" % (
                    "".join( utils.parse_binary(ord(value[1]), data_coding_byte_descriptions) ),
                    2 ** (ord(value[1])&0x07)
                )
            )
        
        if len(value) > 2:
            i = 0
            for j in value[2:4]:
                i = i * 256 + ord(j)
            attributes.append(
                "maximum record length: %s" % i
            )
            if len(value) > 4:
                i = 0
                for j in value[4:6]:
                    i = i * 256 + ord(j)
                attributes.append(
                    "number of records: %s" % i
                )
        
        return result + " (%s)" % "; ".join(attributes)
    else:
        result = result + "\nFile descriptor byte:\n"
        result = result + "\t" + "\n\t".join(
            utils.parse_binary(ord(value[0]), file_descriptor_byte_descriptions, True)
        )
        if len(value) > 1:
            result = result + "\nData coding byte (0x%02X):\n" % ord(value[1])
            result = result + "\tBehavior of write functions: %s\n\tData unit size in in nibbles: %i" % (
                    "".join( utils.parse_binary(ord(value[1]), data_coding_byte_descriptions) ),
                    2 ** (ord(value[1])&0x07)
                )
        if len(value) > 2:
            i = 0
            for j in value[2:4]:
                i = i * 256 + ord(j)
            result = result + "\nMaximum record length: %s" % i
            if len(value) > 4:
                i = 0
                for j in value[4:6]:
                    i = i * 256 + ord(j)
                result = result + "\nNumber of records: %s" % i
        return result

def parse_oid(value):
    result = []
    def next_arc(data):
        bits = ord(data[0]) & 0x7F
        while ord(data[0]) & 0x80 != 0:
            data = data[1:]
            bits = (bits << 7) + (ord(data[0]) & 0x7F)
        data = data[1:]
        return bits, data
    
    arc, value = next_arc(value)
    if arc < 40:
        result.append( 0 )
        result.append( arc )
    elif arc < 80:
        result.append( 1 )
        result.append( arc-40 )
    else:
        result.append( 2 )
        result.append( arc-80 )
    
    while len(value) > 0:
        arc,value = next_arc(value)
        result.append( arc )
    
    return tuple(result)
    
oidCache = {}
def loadOids(filename="oids.txt"):
    try:
        fp = file(filename, "r")
    except (SystemExit,KeyboardInterrupt):
        raise
    except:
        pass
    else:
        try:
            lines = fp.readlines()
        finally:
            fp.close()
        for line in lines:
            if line.strip() == "" or line[0] == "#":
                continue
            parts = line.strip().split(None,2)
            if len(parts) < 3:
                parts.append(parts[1])
            oidCache[parts[0]] = tuple(parts[1:])
    
def decode_oid(value):
    oid = parse_oid(value)
    str_rep = ".".join([str(a) for a in oid])
    
    if len(oidCache) == 0:
        loadOids()
    description = oidCache.get(str_rep, None)
    if description is None:
        steps = [oid[:e] for e in range(len(oid)-1, 0, -1)]
        for step in steps:
            new_str_rep = ".".join([str(a) for a in step])
            if oidCache.has_key(new_str_rep):
                description = ("%s %s" % (oidCache[new_str_rep][0], ".".join([str(a) for a in oid[len(step):]])),)
                break
        if description is None:
            description = ("No description available",)

    return " %s (%s)" % (str_rep, description[0])

_gtimere = re.compile(r'(\d{4})(\d\d)(\d\d)(\d\d)(?:(\d\d)(\d\d(?:[.,]\d+)?)?)?(|Z|(?:[+-]\d\d(?:\d\d)?))$')
def decode_generalized_time(value):
    matches = _gtimere.match(value)
    if not matches:
        return " "+value
    else:
        matches = matches.groups()
        result = [" %s-%s-%s %s:" % matches[:4]]
        if matches[4] is not None:
            result.append("%s:" % matches[4])
            if matches[5] is not None:
                result.append("%s" % matches[5])
            else:
                result.append("00")
        else:
            result.append(":00:00")
        
        if matches[6] == "Z":
            result.append(" UTC")
        elif matches[6] != "":
            result.append(" ")
            result.append(matches[6])
            if len(matches[6]) < 5:
                result.append("00")
        
        return "".join(result)

_utimere = re.compile(r'(\d\d)(\d\d)(\d\d)(\d\d)(?:(\d\d))?(Z|(?:[+-]\d\d(?:\d\d)?))$')
def decode_utc_time(value):
    matches = _utimere.match(value)
    if not matches:
        return " "+value
    else:
        matches = matches.groups()
        result = [" %s-%s-%s %s:" % matches[:4]]
        if matches[4] is not None:
            result.append("%s:" % matches[4])
            if matches[5] is not None:
                result.append("%s" % matches[5])
            else:
                result.append("00")
        else:
            result.append(":00:00")
        
        if matches[6] == "Z":
            result.append(" UTC")
        elif matches[6] != "":
            result.append(" ")
            result.append(matches[6])
            if len(matches[6]) < 5:
                result.append("00")
        
        return "".join(result)

def decode_bit_string(value):
    unused_len = ord(value[0])
    value = value[1:]
    bits = []
    
    for i in range(len(value)):
        v = ord(value[i])
        l = 8
        if i == len(value)-1:
            l = l - unused_len
        for j in range(l):
            bits.append( (v & 0x80) >> 7 )
            v = v << 1
    
    def do_some_bits(slice):
        result = []
        for index, bit in enumerate(slice):
            if index % 4 == 0:
                result.append(" ")
            if index % 8 == 0:
                result.append(" ")
            result.append(str(bit))
        return result

    if len(bits) <= 16:
        return " '%s'B" % "".join(do_some_bits(bits)).strip()
    else:
        step = 32
        result = []
        head, tail = bits[:step], bits[step:]
        offset = 0
        while offset == 0 or len(tail) > 0:
            result.append("%05x:  %s" % (offset, "".join(do_some_bits(head)).strip()))
            offset += step
            head, tail = tail[:step], tail[step:]
        return "\n" + "\n".join(result)
    

def decode_lcs(value):
    value = ord(value[0])
    return " 0x%02x\n%s" % (value, "\n".join(
            utils.parse_binary(value, life_cycle_status_byte_descriptions, True)
        )
    )

def decode_sfi(value):
    if len(value) == 0: return ""
    return " 0x%02x" % (ord(value[0]) >> 3)

tags = {
    None: {
        0x01: (lambda a: (len(a) > 0 and ord(a[0]) != 0) and " True" or " False", "Boolean"),
        0x02: (number, "Integer"),
        0x03: (decode_bit_string, "Bit string"),
        0x04: (binary, "Octet string"),
        0x05: (lambda a: " Null", "Null"),
        0x06: (decode_oid, "Object identifier"),
        0x0A: (number, "Enumerated"),
        0x0C: (utf8, "UTF-8 string"),
        0x12: (ascii, "Numeric string"),
        0x13: (ascii, "Printable string"),
        0x14: (ascii, "Teletex string"), ## FIXME: support escape sequences?
        0x15: (ascii, "Videotext string"), ## dito
        0x16: (ascii, "IA5String"),
        0x17: (decode_utc_time, "UTC time"),
        0x18: (decode_generalized_time, "Generalized time"),
        0x30: (recurse, "Sequence", None),
        0x31: (recurse, "Set", None),
        
        0x62: (recurse, "File Control Parameters", context_FCP),
        0x64: (recurse, "File Management Data", context_FMD),
        0x6F: (recurse, "File Control Information", context_FCI),
    },
    context_FCI: {
        0x80: (number, "Number of data bytes in the file, excluding structural information"),
        0x81: (number, "Number of data bytes in the file, including structural information"),
        0x82: (decode_file_descriptor_byte, "File descriptor byte"),
        0x83: (binary, "File identifier"),
        0x84: (binary, "DF name"),
        0x85: (binary, "Proprietary information"),
        0x86: (binary, "Security attributes"),
        0x87: (binary, "Identifier of an EF containing an extension of the FCI"),
        0x88: (decode_sfi, "Short EF identifier"),
        0x8A: (decode_lcs, "Life cycle status byte"),
        
        0xA5: (recurse, "Proprietary information", None),
    },
}

tags[context_FCP] = tags[context_FCI]

BER_CLASSES = {
    0x0: "universal",
    0x1: "application",
    0x2: "context-specific",
    0x3: "private",
}

def tlv_unpack(data):
    ber_class = (ord(data[0]) & 0xC0) >> 6
    constructed = (ord(data[0]) & 0x20) != 0 ## 0 = primitive, 0x20 = constructed
    tag = ord(data[0]) 
    data = data[1:]
    if (tag & 0x1F) == 0x1F:
        tag = (tag << 8) | ord(data[0])
        while ord(data[0]) & 0x80 == 0x80:
            data = data[1:]
            tag = (tag << 8) | ord(data[0])
        data = data[1:]
    
    length = ord(data[0])
    if length < 0x80:
        data = data[1:]
    elif length & 0x80 == 0x80:
        length_ = 0
        data = data[1:]
        for i in range(0,length & 0x7F):
            length_ = length_ * 256 + ord(data[0])
            data = data[1:]
        length = length_
    
    value = data[:length]
    rest = data[length:]
    
    return ber_class, constructed, tag, length, value, rest

def decode(data, context = None, level = 0, tags=tags):
    result = []
    while len(data) > 0:
        if ord(data[0]) in (0x00, 0xFF):
            data = data[1:]
            continue
        
        ber_class, constructed, tag, length, value, data = tlv_unpack(data)
        
        interpretation = tags.get(context, tags.get(None, {})).get(tag, None)
        if interpretation is None:
            if not constructed: interpretation = [binary, "Unknown field"]
            else: interpretation = [recurse, "Unknown structure", ber_class in (0, 1) and context or None]
            
            interpretation[1] = "%s (%s class)" % (interpretation[1], BER_CLASSES[ber_class])
            interpretation = tuple(interpretation)
        
        current = ["\t"*level]
        current.append("Tag 0x%02X, Len 0x%02X, '%s':" % (tag, length, interpretation[1]))
        
        if interpretation[0] is recurse:
            current.append("\n")
            current.append( decode(value, interpretation[2], level+1, tags=tags) )
        elif interpretation[0] is number:
            num = 0
            for i in value:
                num = num * 256
                num = num + ord(i)
            current.append( " 0x%02x (%i)" % (num, num))
        elif interpretation[0] is ascii:
            current.append( " %s" % value)
        elif interpretation[0] is utf8:
            current.append( " %s" % unicode(value, "utf-8"))
        elif interpretation[0] is binary:
            if len(value) < 0x10:
                current.append( " %s" % utils.hexdump(value, short=True))
            else:
                current.append( "\n" + "\t"*(level+1) )
                current.append( ("\n" + "\t"*(level+1)).join( utils.hexdump(value).splitlines() ) )
        elif callable(interpretation[0]):
            current.append( ("\n"+"\t"*(level+1)).join(interpretation[0](value).splitlines()) )
        
        result.append( "".join(current) )
    
    return "\n".join(result)

def tlv_find_tag(tlv_data, tag, num_results = None):
    """Find (and return) all instances of tag in the given tlv structure (as returned by unpack).
    If num_results is specified then at most that many results will be returned."""
    
    results = []
    def find_recursive(tlv_data):
        for d in tlv_data:
            t,l,v = d[:3]
            if t == tag:
                results.append(d)
            else:
                if isinstance(v, list): # FIXME Refactor the whole TLV code into a class
                    find_recursive(v)
            
            if num_results is not None and len(results) >= num_results:
                return
    
    find_recursive(tlv_data)
    
    return results

def unpack(data, with_marks = None, offset = 0, include_filler=False):
    result = []
    while len(data) > 0:
        if ord(data[0]) in (0x00, 0xFF):
            if include_filler:
                if with_marks is None:
                    result.append( (ord(data[0]), None, None) )
                else:
                    result.append( (ord(data[0]), None, None, () ) )
            data = data[1:]
            offset = offset + 1
            continue
        
        l = len(data)
        ber_class, constructed, tag, length, value, data = tlv_unpack(data)
        stop = offset + (l - len(data))
        start = stop - length
        
        if with_marks is not None:
            marks = []
            for type, mark_start, mark_stop in with_marks:
                if (mark_start, mark_stop) == (start, stop):
                    marks.append(type)
            marks = (marks, )
        else:
            marks = ()
        
        if not constructed:
            result.append( (tag, length, value) + marks )
        else:
            result.append( (tag, length, unpack(value, with_marks, offset = start)) + marks )
        
        offset = stop
    
    return result

def pack(tlv_data, recalculate_length = False):
    result = []
    
    for data in tlv_data:
        tag, length, value = data[:3]
        if tag in (0xff, 0x00):
            result.append( chr(tag) )
            continue
        
        if not isinstance(value, str):
            value = pack(value, recalculate_length)
        
        if recalculate_length:
            length = len(value)
        
        t = ""
        while tag > 0:
            t = chr( tag & 0xff ) + t
            tag = tag >> 8
        
        if length < 0x7F:
            l = chr(length)
        else:
            l = ""
            while length > 0:
                l = chr( length & 0xff ) + l
                length = length >> 8
            assert len(l) < 0x7f
            l = chr( 0x80 | len(l) ) + l
        
        result.append(t)
        result.append(l)
        result.append(value)
    
    return "".join(result)

if __name__ == "__main__":
    test = binascii.unhexlify("".join(("6f 2b 83 02 2f 00 81 02 01 00 82 03 05 41 26 85" \
        +"02 01 00 86 18 60 00 00 00 ff ff b2 00 00 00 ff" \
        +"ff dc 00 00 00 ff ff e4 10 00 00 ff ff").split()))
    
    #decoded = decode(test)
    #print decoded
    #print decode(file("c100").read())
    
    marks = [ ('[', 5, 8) ]
    a = binascii.a2b_hex( "".join( "80 01 aa  b0 03 81 01 bb ff ff 00".split() ) )
    b = unpack( a, with_marks=marks, include_filler=True)
    print b
    c = pack(b, recalculate_length = True)
    print utils.hexdump(a)
    print utils.hexdump(c)
    
    loadOids()

