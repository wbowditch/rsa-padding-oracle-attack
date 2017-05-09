import rsa_po_tools
import conversions
import string
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time

def to_int(initNum):
	hexNum = initNum
	intNum = int(hexNum,16)
	return intNum


#global Variables
smallCiphertext = to_int('5011ee363939c57ef857f85330db2a796b620145cbdaf20abb10c941436c421d')
smallModulus = to_int('5b72b8210267044f2436817bc3b49a3229bb81276f87eabb09a6ddaf9ccfc67f')
bigCiphertext = to_int('01f5467c585896d061af690e1272bbe982d12ae8d9a8e985030d50f04d838106cb25f7a9cd64c268a490105c58e226860550e171faf83781adb82ebcf3125cf7')
bigModulus = to_int('98c7aa8856a0bf43c74541648148482fb0e554bab2caa87a52b40f1b10ed29741af87b8dcba40a7bb2c0755943b4cc99cf0a776ab4e95fd3c2f96cd85311f7df')
encExp = 65537


def to_int(initNum):
	hexNum = initNum
	intNum = int(hexNum,16)
	return intNum
#print to_int(smallModulus)

def padding_attack(encExp,mod,ciphertext,which): #which is small or big
	if which == 'small':
		k = 256/8
	else:
		k = 512/8
	
	e = encExp
	n = mod#to_int(mod)
	B = 2**(8*(k-2))
	#print B, len(str(B))
	Mi = set([(2 * B, 3 * B - 1)])
	c_0 = ciphertext#to_int(ciphertext)		#blinding 1
	s_i = 1							#blinding 1
	count = 1
	working = True
#print("Step 1 complete")
	while working:
		siPrev = s_i	 			#step 2
		miPrev = Mi
		if count == 1:  			#2a
#print("2.a")
			s_i = n /(3*B)	#set s_1 as the first number above n/3B that has correct padding with C*(si)**e mod n
			#print s_i, n, B
			#print format(((c_0 * pow(s_i,e,n))),'x')
			while rsa_po_tools.correctPadding(format(((c_0 * pow(s_i,e,n))),'x'),which) == False:
			#while not fcrypt(c_0 * pow(s_i, e, n)):
				#print s_i
				s_i+=1
			#print "2.a",s_i

		elif len(miPrev)>1: 		#2b
#print("2.b")
			s_i =  siPrev + 1	
#print (c_0 * pow(s_i,e,n))
			while rsa_po_tools.correctPadding(format(((c_0 * pow(s_i,e,n))),'x'),which) == False:
			#while not fcrypt(c_0 * pow(s_i, e, n)):
				s_i+=1			#set s_1 as the first number above previous si that has correct padding with C*(si)**e mod n
				#print s_i
		
		else: 						#2c 
#print("2.c")
			a = list(miPrev)[0][0]
			b = list(miPrev)[0][1]

			ri = 2 * ((b * siPrev - 2 * B) / n)
			
			searching = True

			while searching:
				
				s_i = (2 * B + ri * n) / b
				maxSi = (3 * B + ri * n) / a

				if maxSi-s_i < 0: return
#print(maxSi-s_i)
				while s_i <= maxSi:
					if rsa_po_tools.correctPadding(format(((c_0 * pow(s_i,e,n))),'x'),which) == True:
						searching = False		#if fits padding stop looking
						break				#leave the while loop for iterating si
		
					s_i += 1		#iterate through all si in the range
				
				ri+=1 #iterate through each ri
#print("Step 2 complete",count)
		
		Mi = set()					#begin step 3
		for a,b in miPrev:
			r, mod1 = divmod(((a * s_i) - ((3 * B) + 1)), n)
			if mod1 != 0:
				r+=1
			maxR = (b * s_i - 2 * B) / n 
#print (a*s_i) < (3*B+1)
			
#print(r,maxR)
			while r <= maxR:
				bottom,mod1 = divmod(((2*B)+(r*n)),s_i)
				if mod1 != 0:
					bottom +=1
				bottom = max(a,bottom)
				upper = divmod((((3*B)-1)+(r*n)),s_i)[0]
				upper = min(b,upper)
				Mi.add((bottom,upper))
				r+=1
				
#print("step3 complete",count)		
#print('a:',a,'b:',b, 'a-b:',a-b)
		if len(Mi)==1: #begin step 4
			a = list(Mi)[0][0]
			b = list(Mi)[0][1]
#print('a:',a,'b:',b, 'a-b:',a-b)
			if a == b:
				message = long_to_bytes(a)
				m = '\x00'*(k-len(message)) + message
#print(m)		
				#print count
				return m
		count += 1


#padding_attack(encExp,smallModulus,smallCiphertext,'small')

'''You want to try this out on your own first by making a little 
'oracle' that runs on your own machine, without worrying about 
network stuff:  Just write a function that decrypts RSA-encrypted 
plaintexts, and checks whether the 2 high-order bytes are correct.  
Then you can point your attack at my server.  
Since you will need to query the server many times, you are not 
going to manually enter ciphertexts in the form.  
Instead, I've provided you with a tool for posting a query 
to the server, attached to this e-mail.'''


def try1():
	question = raw_input("would you like to try 256 or 512 input? (input 256 or 512):")
	if question == '256':
	
		bits = 256
		k = bits/8
		pubkey = smallModulus
		c = smallCiphertext
		start = time.time()
		msg = padding_attack(65537,pubkey,c,'small')
		end = time.time()
		total = end-start
		
		print"256\n", msg,'\n', total
	elif question == '512':
	
		bits = 512
		k = bits/8
		pubkey = bigModulus
		c = bigCiphertext
		start = time.time()
		msg = padding_attack(65537,pubkey,c,'big')
		end = time.time()
		total = end-start
		
		print"512\n", msg,'\n', total
	else: 
		print "Invalid Input"
	
	
try1()
