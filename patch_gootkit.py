import os
import sys
import json
import r2pipe
import struct
import shutil
import StringIO

__author__ = "d00rt (@D00RT_RM)"
__info__ = "http://reversingminds-blog.logdown.com/posts/7369479"
__mail__ = "d00rt.fake@gmail.com"
__version__= "1.0"

OUTPUT_FORMAT = ["PLAINTEXT", "JSON"]

def patch_loop(offset, r):
    # In the original loop, the loop decrypts the string
    # but we patched the string so now it is decrypted so
    # we dont want to decrypt it.
    #
    # For decryption it just use the XOR instruction so
    # we are going to nop that instruction
    
    patched = False

    # Looking for the XOR instruction
    while not patched:
        
        # Disassembling the instruction
        ins = r.cmdj("pdj 1 @ {offset}".format(offset=offset))[0]
        if ins["type"] == "xor":
            # Get instruction offset
            patch_offset = ins["offset"]
            # Get instruction len
            bytes_to_patch = len(ins["bytes"])/2
            # Get the patch (NOP block)
            patch_block = '90' * bytes_to_patch
            # Patch the instruction
            r.cmd("wx %s @ 0x%X" % (patch_block, patch_offset))
            patched = True
            

        offset = ins["offset"] + len(ins["bytes"])/2


def patch_string(offset, string, key_size, r):
    # Patch each char of the string

    # Get as many instructions (mov [ebp + X], '?' instructions) as len(string)
    ins_set = r.cmdj("pdj {n} @ {offset}".format(n=len(string) + key_size, offset=offset))

    # Check if the block is what we are looking for
    # ERROR prevention
    if not len(filter(None, [ins["type"] == "mov" for ins in ins_set])) == len(string) + key_size:
        return False

    i = 0
    while i < len(string):
        # Patching each character
        # From encrypted char to decrypted char
        ins = ins_set[i]
        patch_offset = len(ins["bytes"])/2 + ins["offset"] - 1
        r.cmd("wx %02x @ 0x%X" % (ord(string[i]), patch_offset))
        i += 1 
    return True
        

def decrypt_string(s, k):
    # Simple XOR algorithm
    r = ''
    i = 0
    for c in s:
        r += chr(ord(c) ^ ord(k[i % len(k)]))
        i += 1
    return r


def get_data(size, offset, r):
    # It goes backwards looking for 0xC6 OPCODE (mov)
    # When a 0xC6 is found, it disassembles that instrucction
    # If it is a mov instruction we read the value of that instruction (The char we want to get)
    # The above described process is repeated until we find as many chars as the size value

    ins_offset = offset
    c_size = 0
    string = []

    while c_size < size:
        ins_offset -= 1

        # Read OPCODE
        opcode = r.cmdj("pxj 1 @ {offset}".format(offset=ins_offset))[0]
        if opcode == 0xC6:
            # Disassemble the "instruction"
            _ins = r.cmdj("pdj 1 @ {offset}".format(offset=ins_offset))   
            t = _ins[0]["type"]

            # If it is a mov it is the instruction that we are searching
            if t == "mov":
                string.append(_ins[0]["val"])
                c_size += 1

    return (ins_offset, ''.join([chr(c) for c in string[::-1]]))


def main(r, output=False, f="PLAINTEXT"):
    
    # Patters for detecting all loops where the strings are decrypted
    PATTERNS = [
        r.cmdj("/xj ..0189....837d....7d..b.01......85..74..8b....0f........8b....99be.."),
        r.cmdj("/xj ..0189....837d....7d..b.01......85..74..8b....0f..............8b....99be.."),
    ]

    OFFSET_ = 8 * 2

    ret_dic = {}

    for pat_matches in PATTERNS:
        # For each loop (string to decrypt)
        for path_match in pat_matches:

            # Get encrypted string size
            string_size = int(path_match["data"][OFFSET_: OFFSET_ + 2 ], 16)

            # Get size of the decryption key
            key_size = int(path_match["data"][-2:], 16)

            # Get the offset where our pattern matched
            offset = path_match["offset"]

            # Where our pattern matches is at the end of the (string + key) offset
            block_end_offset = offset

            # Get key and the offset where the key starts (or where our encrypted string ends)
            key_init_offset, k = get_data(key_size, block_end_offset, r)

            # Get string and the offset where the string starts
            string_init_offset, s = get_data(string_size, key_init_offset, r)
            
            # Decrypt the string
            ss = decrypt_string(s, k)

            ret_dic[string_init_offset] = ss

            # Patch the code with the decrypted string instead to leave the encrypted string
            patch_string(string_init_offset, ss, key_size, r)

            # Patch the loop where the string is decrypted (Now we patched and the string is decrypted)
            patch_loop(offset - 1, r)

    if output:

        if f == "PLAINTEXT":
            for k in ret_dic.keys():
                print "0x%x - %s" % (k, ret_dic[k])
        
        if f == "JSON":
            print ret_dic


def usage():
    print 'DESCRIPTION'
    print '    A python script using radare2 for decrypt and patch the strings of GootKit malware'
    print ''
    print ''
    print 'OPTIONS'
    print '    -o [JSON|PLAINTEXT]        print decrypted strings in the given format'
    print ''
    print ''
    print 'EXAMPLES'
    print '    {s} unpacked_gootkit.exe'.format(s=os.path.basename(__file__))
    print ''
    print '    {s} unpacked_gootkit.exe -o'.format(s=os.path.basename(__file__))
    print ''
    print '    {s} unpacked_gootkit.exe -o json'.format(s=os.path.basename(__file__))
    print ''
    print 'OUTPUT FILE'
    print '    unpacked_gootkit.exe__patched'



if __name__ == '__main__':
    global r

    if len(sys.argv) >= 2 and len(sys.argv) <= 4 and os.path.exists(sys.argv[1]):
        d = False
        f = None
        shutil.copyfile(sys.argv[1], sys.argv[1] + '__patched')
        FILE_NAME = sys.argv[1] + '__patched'

        if len(sys.argv) >= 3 and sys.argv[2] == '-o' and os.path.exists(sys.argv[1]):  
            d = True
            f = sys.argv[3].upper() if len(sys.argv) == 4 and sys.argv[3].upper() in OUTPUT_FORMAT else "PLAINTEXT"
                

        r = r2pipe.open(FILE_NAME, ["-w"])
        main(r, d, f)
    else:
        usage()


