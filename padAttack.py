import rsa_po_tools
import conversions

smallCiphertext = '5011ee363939c57ef857f85330db2a796b620145cbdaf20abb10c941436c421d'

smallModulus = '5b72b8210267044f2436817bc3b49a3229bb81276f87eabb09a6ddaf9ccfc67f'

bigCiphertext='01f5467c585896d061af690e1272bbe982d12ae8d9a8e985030d50f04d838106cb25f7a9cd64c268a490105c58e226860550e171faf83781adb82ebcf3125cf7'

bigModulus='98c7aa8856a0bf43c74541648148482fb0e554bab2caa87a52b40f1b10ed29741af87b8dcba40a7bb2c0755943b4cc99cf0a776ab4e95fd3c2f96cd85311f7df'

encExp = 65537



pubkey = (65537,41363160597721029885472283321473316054104792687939226295669553333550772635263)

def as_to_int(initNum):
	hexNum = initNum#conversions.as_to_hex(initNum)
	#print hexNum,len(hexNum)
	intNum = int(hexNum,16)
	#print intNum,len(str(intNum))
	return intNum


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


def padding_attack(encExp,mod,ciphertext,k,which): #which is small or big
	e = encExp
	n = as_to_int(mod)
	B = 2**(8*(k-2))
	#print B, len(str(B))
	Mi = set([(2 * B, 3 * B - 1)])
	#print Mi
	c_0 = as_to_int(ciphertext)		#blinding 1
	s_i = 1							#blinding 1
	count = 1
	working = True
	print("Step 1 complete")
	while working:
		siPrev = s_i	 			#step 2
		miPrev = Mi
		print(Mi, count)
		if count == 1:  			#2a
			s_i = n/(3*B)	#set s_1 as the first number above n/3B that has correct padding with C*(si)**e mod n
			while rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == False:
				s_i+=1
		elif len(miPrev)>1: 			#2b
			print "2.b"
			s_i =  siPrev + 1		
			while rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == False:
				s_i+=1			#set s_1 as the first number above previous si that has correct padding with C*(si)**e mod n
		else: 						#2c 
			print "2.c"
			a = list(miPrev)[0][0]
			b = list(miPrev)[0][1]
			#print a
			#print b 
			ri = 2 * ((b * siPrev - 2 * B) / n)
			
			searching = True

			print "a:",a, count
			print "b:",b , b-a
			print "a", len(str(a)), "b",len(str(b))

			while searching:
				
				s_i = (2 * B + ri * n) / b
				maxSi = (3 * B + ri * n) / a
				if maxSi-s_i < 0: return
				print ri
				while s_i <= maxSi:
					if rsa_po_tools.correctPadding(int_to_as(c_0 * pow(s_i,e,n)),which) == True:
						searching = False		#if fits padding stop looking
						break				#leave the while loop for iterating si
					#print maxSi - s_i	
					s_i += 1		#iterate through all si in the range
				
				ri+=1 #iterate through each ri
		print("Step 2 complete")
		#print(s_i)
		#print Mi
		#print miPrev
		Mi = set()					#begin step 3
		for a,b in miPrev:
			r= (a * s_i - 3 * B + 1)/ n 
			maxR = (b * s_i - 2 * B) / n 
			#print (b * s_i - 2 * B)
			#print n
			
			#print s_i
			#print(len(str(a)),len(str(b)),len(str(B)),len(str(s_i)), len(str(n)))

			print r,maxR
			
			while r <= maxR:
				bottom = (((2*B)+(r*n))/s_i)
				
				bottom = max(a,bottom)
				#upper = (((3*B)-1)+(r*n))/s_i
				upper = min(b,((3 * B - 1 + (r * n))/s_i))
				print Mi
				Mi.add((bottom,upper))
				r+=1
				print Mi
		print("step3 done")		
		
		if len(Mi)==1: #begin step 4
			a = list(Mi)[0][0]
			b = list(Mi)[0][1]

			if a == b:
				message = int_to_as(a)

				m = '\x00'*(k-len(message)) + message
				print m
				return m
		count += 1
padding_attack(encExp,smallModulus,smallCiphertext,32,'small')



'''You want to try this out on your own first by making a little 
'oracle' that runs on your own machine, without worrying about 
network stuff:  Just write a function that decrypts RSA-encrypted 
plaintexts, and checks whether the 2 high-order bytes are correct.  
Then you can point your attack at my server.  
Since you will need to query the server many times, you are not 
going to manually enter ciphertexts in the form.  
Instead, I've provided you with a tool for posting a query 
to the server, attached to this e-mail.'''