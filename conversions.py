#A toolbox for converting between different representations of
#strings of bytes.  The schemes are

# Python strings---these are basically ASCII strings, but don't try to
# print them, because they typically contain nonprinting characters.
# If the value is displayed, the nonprinting characters appear in hex
# with the escape '\x' preceding.  This is the native form, we'll call it as.
# Each character is one byte.

#Hex strings.  These are Python strings over the alphabet
# 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f  Each byte is represented by two characters.
#we'll call this hex

#Base 64 encodings.  These are Python strings over the 64-character alphabet
#consisting of letters, digits, and two additional punctuation symbols. Each
#character represents 6 bits.  Extra alignment characters are appended in case
#the number of bits in the byte sequence is not a multiple of 6. We'll call this
#b64.

#Python lists of ints in the range 0 to 255.  We'll call this representation lis.

#The conversion routines have names like as_to_b64, hex_to_lis, etc.
import binascii

def as_to_lis(asrep):
    return [ord(c) for c in asrep]

def lis_to_as(lisrep):
    s=''
    for x in lisrep:
        s+=chr(x)
    return s

def lis_to_hex(lisrep):
    hexrep=''
    for x in lisrep:
        if x>=16:
            hexrep+=(hex(x)[2:])
        else:
            hexrep+=('0'+hex(x)[2:])
    return hexrep

def hex_to_lis(hexrep):
    return([int(hexrep[2*i:2*i+2],16) for i in range(len(hexrep)/2)])
    return hexrep

def as_to_b64(asrep):
    b64rep=binascii.b2a_base64(asrep)
    #you need to cut off the newline character at the end!
    return(b64rep[:-1])

def b64_to_as(b64rep):
    return binascii.a2b_base64(b64rep)

#We'll get the other conversions by composition
def as_to_hex(asrep):
    return lis_to_hex(as_to_lis(asrep))

def hex_to_as(hexrep):
    return lis_to_as(hex_to_lis(hexrep))

def lis_to_b64(lisrep):
    return as_to_b64(lis_to_as(lisrep))

def b64_to_lis(b64rep):
    return as_to_lis(b64_to_as(b64rep))

def hex_to_b64(hexrep):
    return as_to_b64(hex_to_as(hexrep))

def b64_to_hex(b64rep):
    return as_to_hex(b64_to_as(b64rep))


#xor is our basic operation.  This function computes the xor of two byte strings
#in the native representation.  If the two strings have different lengths
#then the additional bytes of the longer string are not used, and the length
#of the result is the minimum of the lengths of the two starting strings.

def xor(s1,s2):
    le=min(len(s1),len(s2))
    s=''
    for j in range(le):
        s+=chr(ord(s1[j])^ord(s2[j]))
    return s



    
    