
import urllib
import urllib2
#routines for posting a request
#to the RSA padding oracle servers



#This makes a post request to the server.  The guess is
#the ciphertext in hex. The argument which is the string
#'small' or 'big' depending on which of the two servers you want to query.

def post_dictionary_guess(guess,which):
    url_2='http://cscicrypto.bc.edu:8080/'+which+'rsa'

    values=[('Entry',guess)]
    data = urllib.urlencode(values)
    req = urllib2.Request(url_2, data)
    rsp=urllib2.urlopen(req)
    #print rsp.code

    return rsp.read()





def correctPadding(guess,which):
    response = post_dictionary_guess(guess,which)
    if len(response)==355:
        return False
    else:
        return True
#smallCiphertext = '5011ee363939c57ef857f85330db2a796b620145cbdaf20abb10c941436c421d'
#correctPadding(smallCiphertext,'small')