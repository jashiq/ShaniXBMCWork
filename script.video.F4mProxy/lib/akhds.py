
import base64
from struct import unpack, pack
import sys
import io
import os
import time
import itertools
import urllib2,urllib
import traceback
import urlparse
import posixpath
import re
import hmac
import hashlib
import binascii 
import zlib
from hashlib import sha256, sha1,md5,sha512
import cookielib
import array

try:
    from Crypto.Cipher import AES
    USEDec=1 ## 1==crypto 2==local, local pycrypto
except:
    print 'pycrypt not available using slow decryption'
    USEDec=3 ## 1==crypto 2==local, local pycrypto
    
USEDec=3 

if USEDec==1:
    #from Crypto.Cipher import AES
    print 'using pycrypto'
elif USEDec==2:
    from decrypter import AESDecrypter
    AES=AESDecrypter()
else:
    from utils import python_aes
    
value_unsafe = '%+&;#'
VALUE_SAFE = ''.join(chr(c) for c in range(33, 127)
    if chr(c) not in value_unsafe)


def tagDecrypt(data,key):
    enc_data=data#binascii.unhexlify(enc_data)
    enc_key=key#binascii.unhexlify(enc_key)

#    print 'DataIn',binascii.hexlify(data)
#    print 'KeyIn',binascii.hexlify(key)
    

    keydatalen=0
    if 'key_' in enc_data[0:100]: #quick check?? need to find better way to predict offsets
        keydatalen=enc_data[0:200].find(chr(0),13+16)-(13+16)+1
       
       
#    print 'keydatalen',keydatalen       
    stage_4a_finaldataIndex=13+16+1+keydatalen  #?? dynamic calc req
    enc_data_index=stage_4a_finaldataIndex+32+40

    stage_4a_finaldata=enc_data[stage_4a_finaldataIndex:stage_4a_finaldataIndex+32]
    globalivIndex=13
    global_iv=enc_data[globalivIndex:globalivIndex+16]
#    print 'global  iv',binascii.hexlify(global_iv)

    stage_4a_data=enc_key+global_iv

#    print len (stage_4a_data)

    #??static data
    stage_4a_key=binascii.unhexlify("3b27bdc9e00fd5995d60a1ee0aa057a9f1416ed085b21762110f1c2204ddf80ec8caab003070fd43baafdde27aeb3194ece5c1adff406a51185eb5dd7300c058")
#    stage_4a_key=key#fixed


#    print 'stage_4a_key',binascii.hexlify(stage_4a_key),len(stage_4a_key)
#    print 'data',binascii.hexlify(stage_4a_data) ,len(stage_4a_data)

    stage_4a_key2 = hmac.new(stage_4a_key,stage_4a_data , sha1).digest()

    #stage_4a_key2+=chr(0)*12
#    print 'first HMAC ',binascii.hexlify(stage_4a_key2) ,len(stage_4a_key2)



    #??static data
    stage_4a_data2=binascii.unhexlify("d1ba6371c56ce6b498f1718228b0aa112f24a47bcad757a1d0b3f4c2b8bd637cb8080d9c8e7855b36a85722a60552a6c00")

#    print 'stage_4a_data2',binascii.hexlify(stage_4a_data2),len(stage_4a_data2)
    
    
    auth = hmac.new(stage_4a_key2,stage_4a_data2 , sha1).digest()
    stage_4a_finalkey=auth[:16]

     
#    print stage_4a_finalkey, repr(stage_4a_finalkey), len(stage_4a_finalkey)
#    print binascii.hexlify(stage_4a_finalkey)
#    print 'first end HMAC >>>>>>>>>>>>>>>>>>>>>>>>>'
#    print 'final data',binascii.hexlify(stage_4a_finaldata)
#    print 'final iv',binascii.hexlify(global_iv)
#    print 'final key',binascii.hexlify(stage_4a_finalkey)





    #import  pyaes   
#    de =AES.new(stage_4a_finalkey, AES.MODE_CBC, global_iv)
#    # pyaes.new(stage_4a_finalkey, pyaes.MODE_CBC, IV=global_iv)
    de=getDecrypter(stage_4a_finalkey,global_iv )
    stage_4a_finaloutput=decryptData(de,stage_4a_finaldata)
#    print stage_4a_finaloutput
    stage_4a_finaloutput=stage_4a_finaloutput[4:4+16]
#    print 'final',binascii.hexlify(stage_4a_finaloutput)

    stage_4_key=stage_4a_key
    stage_5_key = hmac.new(stage_4_key,stage_4a_finaloutput , sha1).digest()

#    print 'stage_4_hmac ',binascii.hexlify(stage_5_key)


    #??static data
    stage_5_data=binascii.unhexlify("d1ba6371c56ce6b498f1718228b0aa112f24a47bcad757a1d0b3f4c2b8bd637cb8080d9c8e7855b36a85722a60552a6c01")
    
#    print 'stage_5_data',binascii.hexlify(stage_5_data),len(stage_5_data)
    
    stage_5_hmac = hmac.new(stage_5_key,stage_5_data , sha1).digest()

#    print 'stage_5_hmac ',binascii.hexlify(stage_5_hmac), len(stage_5_hmac)

    stage_5_hmac=stage_5_hmac[:16]

#    print 'stage_5_hmac trmimed ',binascii.hexlify(stage_5_hmac), len(stage_5_hmac)

#    de =AES.new(stage_5_hmac, AES.MODE_CBC, global_iv)
#    #de = pyaes.new(stage_5_hmac, pyaes.MODE_CBC, IV=global_iv)
    de=getDecrypter(stage_5_hmac,global_iv )

#    print 'enc_data_index',enc_data_index
    enc_data_todec=enc_data[enc_data_index:]
    datatocut=len(enc_data_todec) % 16
#    print 'datatocut',datatocut

    unEncdata=enc_data_todec[-datatocut:]
#    print 'unEncdata',binascii.hexlify(unEncdata)
    enc_data_todec=enc_data_todec[:len(enc_data_todec)-datatocut]
    decData=""
    if len(enc_data_todec)>0:
#        print 'enc_data_todec',binascii.hexlify(enc_data_todec), len(enc_data_todec)
        #enc_data_remaining
        decData=decryptData(de,enc_data_todec)
        
    decData+=unEncdata
#    if len(decData)<300:
#        print 'key received',binascii.hexlify(key), len(key)
#        print 'data received',binascii.hexlify(data), len(data)
#        print 'final return',binascii.hexlify(decData), len(decData)
    return decData

## function to create the cbc decrypter object
def getDecrypter(key,iv):
    global USEDec
    if USEDec==1:
        enc =AES.new(key, AES.MODE_CBC, iv)
    else:
        ivb=array.array('B',iv)
        keyb= array.array('B',key)
        enc=python_aes.new(keyb, 2, ivb)
    return  enc       

## function to create the cbc decrypter    
def decryptData(d,encdata):
    global USEDec
    if USEDec==1:
        data =d.decrypt(encdata)
    else:
        chunkb=array.array('B',encdata)
        data = d.decrypt(chunkb)
        data="".join(map(chr, data))
    return  data       

    
#enc_data="0c0000000055e975370000ffff2cc98372afe2d8418ed47c36b7cc5b2c2f7a2f5353315f31403330393730312f6b65795f415142534c5a684350767738787a64313656564965484f47567a36764c727a37436d47644f55675a47443571563350684647637a344333727372583955473372333732625030592b00017147a7c17c3fb29ba210dd6fbb542d689ee6c1578635b7545358a260ddb808ac00000000000000000000000000000000000000003f106033e78c4842f66e12489d7d0ec974cb4780a912366394fe3eb1eaa6f1f9f7de4ed81d3ec642fe9c42c7887962b4d62f9969bbe8e1102a3bedf6f1f19fcab6f073d36801000428f96bc8"
#enc_data=binascii.unhexlify(enc_data)
#enc_key="93ac1d5925eadd38f61fee4c321cc843"
#enc_key=binascii.unhexlify(enc_key)
    
#print 'final data',binascii.hexlify(tagDecrypt(enc_data,enc_key)    )

