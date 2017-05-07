import rsa_po_tools
import conversions
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA

def to_int(initNum):
	hexNum = initNum
	intNum = int(hexNum,16)
	return intNum
#print to_i


smallCiphertext = '5011ee363939c57ef857f85330db2a796b620145cbdaf20abb10c941436c421d'

smallModulus = '5b72b8210267044f2436817bc3b49a3229bb81276f87eabb09a6ddaf9ccfc67f'

bigCiphertext='01f5467c585896d061af690e1272bbe982d12ae8d9a8e985030d50f04d838106cb25f7a9cd64c268a490105c58e226860550e171faf83781adb82ebcf3125cf7'

bigModulus='98c7aa8856a0bf43c74541648148482fb0e554bab2caa87a52b40f1b10ed29741af87b8dcba40a7bb2c0755943b4cc99cf0a776ab4e95fd3c2f96cd85311f7df'





pubkey = (65537,41363160597721029885472283321473316054104792687939226295669553333550772635263)

def to_int(initNum):
	hexNum = initNum
	intNum = int(hexNum,16)
	return intNum
#print to_int(smallModulus)

def rsaDecrypt(c,d,n):
	return pow(c,d,n)

def int_to_as(initNum):
	hexNum = hex(initNum)[2:-1]
	final = conversions.hex_to_as(hexNum)
	return final

def rsaEncrypt(m,e,n):
	m = conversions.as_to_hex(m)
	m = int(m,16)
	return pow(m,e,n)



def padding_attack(encExp,mod,ciphertext,which,privkey): #which is small or big
	'''if which == 'small':
		k = 256/8
	else:
		k = 512/8
	'''
	k = 512/8
	e = encExp
	n = mod#to_int(mod)
	B = 2**(8*(k-2))
	print B, len(str(B))
	Mi = set([(2 * B, 3 * B - 1)])
	c_0 = ciphertext#to_int(ciphertext)		#blinding 1
	s_i = 1							#blinding 1
	count = 1
	working = True
	print("Step 1 complete")
	while working:
		siPrev = s_i	 			#step 2
		miPrev = Mi
		if count == 1:  			#2a
			print "2.a"
			s_i = n/(3*B)	#set s_1 as the first number above n/3B that has correct padding with C*(si)**e mod n
			print(s_i, n, B)

			#while rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == False:
			while not padding_oracle(k, privkey,(c_0 * pow(s_i, e, n))):
				#print s_i
				s_i+=1
		
		elif len(miPrev)>1: 		#2b
			print "2.b"
			s_i =  siPrev + 1		
			#while rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == False:
			while not padding_oracle(k, privkey,(c_0 * pow(s_i, e, n))):
				s_i+=1			#set s_1 as the first number above previous si that has correct padding with C*(si)**e mod n
		
		else: 						#2c 
			print "2.c"
			print miPrev
			a = list(miPrev)[0][0]
			b = list(miPrev)[0][1]

			ri = 2 * ((b * siPrev - 2 * B) / n)
			
			searching = True

			while searching:
				
				s_i = (2 * B + ri * n) / b
				maxSi = (3 * B + ri * n) / a

				#if maxSi-s_i < 0: return
				#print(maxSi-s_i)

				while s_i <= maxSi:
					#if rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == True:
					if padding_oracle(k, privkey,(c_0 * pow(s_i, e, n))):
						searching = False		#if fits padding stop looking
						break				#leave the while loop for iterating si
					s_i += 1		#iterate through all si in the range
				
				ri+=1 #iterate through each ri
		print("Step 2 complete",count)
		
		Mi = set()					#begin step 3
		for a,b in miPrev:
			r, mod1 = divmod((a * s_i - 3 * B + 1), n)
			if mod1 != 0:
				r+=1
			maxR = (b * s_i - 2 * B) / n 
			
			print(r,maxR)
			#break
			while r <= maxR:
				bottom,mod1 = divmod(((2*B)+(r*n)),s_i)
				if mod1 != 0:
					bottom +=1
				bottom = max(a,bottom)
				upper = divmod((((3*B)-1)+(r*n)),s_i)[0]
				upper = min(b,upper)
				Mi.add((bottom,upper))
				r+=1
		#break	
		print("step3 complete",count)		
		#print('a:',a,'b:',b, 'a-b:',a-b)
		if len(Mi)==1: #begin step 4
			a = list(Mi)[0][0]
			b = list(Mi)[0][1]
			#print('a:',a,'b:',b, 'a-b:',a-b)
			if a == b:
				message = long_to_bytes(a)

				m = '\x00'*(k-len(message)) + message
				#print m
				return m
		count += 1

#padding_attack(encExp,smallModulus,smallCiphertext,'small')

#HAVE TO ADDRESS PROBLEM OF LARGE E

'''You want to try this out on your own first by making a little 
'oracle' that runs on your own machine, without worrying about 
network stuff:  Just write a function that decrypts RSA-encrypted 
plaintexts, and checks whether the 2 high-order bytes are correct.  
Then you can point your attack at my server.  
Since you will need to query the server many times, you are not 
going to manually enter ciphertexts in the form.  
Instead, I've provided you with a tool for posting a query 
to the server, attached to this e-mail.'''
import binascii
import itertools
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, getStrongPrime, GCD



def invmod(a, b):
    m = b
    x, lastx = 0, 1
    y, lasty = 1, 0
    while b:
        q = a / b
        a, b = b, a % b
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx % m


def rsa_encrypt(m, e, n):
    return pow(bytes_to_long(m), e, n)


def rsa_decrypt(c, d, n):
    return long_to_bytes(pow(c, d, n))


def rsa_genkeys(bits, e):
    bits = bits / 2
    et = e
    while GCD(e, et) != 1:
        if bits < 512:
            #getStrongPrime won't accept bits < 512
            p, q = getPrime(bits), getPrime(bits)
        else:
            p, q = getStrongPrime(bits, e), getStrongPrime(bits, e)
        et = (p-1) * (q-1)

    n = p * q
    d = invmod(e, et)
    return (e,n), (d,n)

def padding_oracle(k, privkey, c):
    m = rsa_decrypt(c, *privkey)
    m = '\x00' * (k - len(m)) + m #I2OSP
    return m[:2] == '\x00\x02'


def pkcs_pad(k, m):
    if len(m) > k - 11:
        return ('m is too long')
    plen = k - len(m) - 3
    pad = ''.join(chr(random.randint(1, 255)) for _ in xrange(plen))
    return ''.join(['\x00\x02', pad, '\x00', m])



def try1():
	msg = "try this one"
	bits = 512
	k = bits/8
	pubkey, privkey = rsa_genkeys(bits=bits, e=65537)
	msg = pkcs_pad(k, msg)
	c = rsa_encrypt(msg, *pubkey)

	new = to_int(bigModulus)
	#print "big mod", len(str(new))

	#print "local mod",len(str(pubkey[1]))
	
	p = padding_attack(65537,pubkey[1],c,'big',privkey)
	print 'Match:', p == msg
try1()
