import binascii, utils

context_FCP = object()
context_FMD = object()
context_FCI = object()
recurse = object()
binary = object()
number = object()
ascii = object()

file_descriptor_byte_descriptions = [
    #byte  mask  no match match
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
    
    ##(0x87, 0x00, None,    "No EF structure information given"),
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
            for j in value[2:]:
                i = i * 256 + ord(j)
            attributes.append(
                "maximum record length: %s" % i
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
            for j in value[2:]:
                i = i * 256 + ord(j)
            result = result + "\nMaximum record length: %s" % i
        return result

tags = {
    None: {
        0x62: (recurse, "File Control Parameters", context_FCP),
        0x64: (recurse, "File Management Data", context_FMD),
        0x6F: (recurse, "File Control Information", context_FCI),
        0x80: (number, "Number of data bytes in the file, excluding structural information"),
        0x81: (number, "Number of data bytes in the file, including structural information"),
        0x82: (decode_file_descriptor_byte, "File descriptor byte"),
        0x83: (binary, "File identifier"),
        0x84: (binary, "DF name"),
        0x85: (binary, "Proprietary information"),
        0x86: (binary, "Security attributes"),
        0x87: (binary, "Identifier of an EF containing an extension of the FCI"),
    },
}

def tvl_unpack(data):
    tag = ord(data[0])
    length = ord(data[1])
    value = data[2:(2+length)]
    rest = data[(2+length):]
    
    return tag, length, value, rest

def decode(data, context = None, level = 0):
    result = []
    while len(data) > 0:
        tag, length, value, data = tvl_unpack(data)
        
        interpretation = tags.get(context, tags.get(None, {})).get(tag, (binary, "Unknown"))
        current = ["\t"*level]
        current.append("Tag 0x%02X, Len 0x%02X, '%s':" % (tag, length, interpretation[1]))
        
        if interpretation[0] is recurse:
            current.append("\n")
            current.append( decode(value, interpretation[2], level+1) )
        elif interpretation[0] is number:
            num = 0
            for i in value:
                num = num * 256
                num = num + ord(i)
            current.append( " 0x%02x (%i)" % (num, num))
        elif interpretation[0] is ascii:
            current.append( " %s" % value)
        elif interpretation[0] is binary:
            current.append( " %s" % utils.hexdump(value, short=True))
        elif callable(interpretation[0]):
            current.append( ("\n"+"\t"*(level+1)).join(interpretation[0](value).splitlines()) )
        
        result.append( "".join(current) )
    
    return "\n".join(result)

if __name__ == "__main__":
    test = binascii.unhexlify("".join(("6f 2b 83 02 2f 00 81 02 01 00 82 03 05 41 26 85" \
        +"02 01 00 86 18 60 00 00 00 ff ff b2 00 00 00 ff" \
        +"ff dc 00 00 00 ff ff e4 10 00 00 ff ff").split()))
    
    decoded = decode(test)
    print decoded
    
