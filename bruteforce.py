import hashlib 
import time
import threading
import sys
#password: zhgnnd
#salt: hfT7jp2q
passhash = 'e5d9E90pfMujbSTn/h4E6.'


def md5(password):
    magic = "$1$"
    salt = "4fTgjp6q"
    pms = password + magic + salt
    psp = password + salt + password

    altSum = hashlib.md5(psp.encode())
    intSum = hashlib.md5(pms.encode())
    #print(intSum.digest())

    #length(password) bytes of the Alternate sum, repeated as necessary
    if(altSum.digest_size > len(password)):
        intSum.update((altSum.digest()[:len(password)]))
        #print(intSum.digest())

    #For each bit in length(password), from low to high and stopping after the most significant set bit
        #If the bit is set, append a NUL byte
        #If it’s unset, append the first byte of the password

    length = "{0:b}".format(len(password)) #bits
    length = length[::-1] #reverse // low to high

    for i in length:
        if(i == '0'):
            intSum.update(password[0].encode())
        else:
            intSum.update(b'\x00')



    #1000 loop
    #For i = 0 to 999 (inclusive), compute Intermediatei+1 by concatenating and hashing the following:
    #    If i is even, Intermediatei
    #    If i is odd, password
    #    If i is not divisible by 3, salt
    #    If i is not divisible by 7, password
    #   If i is even, password
    #   If i is odd, Intermediatei

    prev = intSum
    curr = hashlib.md5()

    for i in range(1000):
        if( i % 2 == 0):
            curr.update(prev.digest())
        
        if (i % 2 != 0):
            curr.update(password.encode())
        
        if(i % 3 != 0):
            curr.update(salt.encode())
      
        if(i % 7 != 0):
            curr.update(password.encode())
        
        if(i % 2 == 0):
            curr.update(password.encode())
        
        if(i % 2 != 0):
            curr.update(prev.digest())
        prev = curr
        curr = hashlib.md5()




    #Output the magic
    #Output the salt
    #Output a “$” to separate the salt from the encrypted section
    #Pick out the 16 bytes in this order: 11 4 10 5 3 9 15 2 8 14 1 7 13 0 6 12.
        #For each group of 6 bits (there are 22 groups), 
            #starting with the least significant
                #Output the corresponding base64 character with this index

    pickOut = [11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12]
    base64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    specialOrder = []
    for i in range(16):
        binary = "{0:b}".format(prev.digest()[pickOut[i]]) #grabbing 16 bytes in order
        #print(binary)
        howManyZeros = 8 - len(binary)  #cat zeros to make equal length
        #print("calc",'0'*howManyZeros + binary)
        specialOrder.append('0'*howManyZeros + binary)


    specialOrder = ''.join(specialOrder) #convert to string

    asci = []
    asci.append(specialOrder[0:2]) #grabbing the 2 bits for 'padding'
    j = 2
    k = 8
    #print(asci)
    for i in range(21): #rest of groups
        asci.append(specialOrder[j:k])
        j += 6
        k += 6

    #print("asci", asci)
    asci = asci[::-1]
    for i, r in enumerate(asci):
        asci[i] = int(r,2)  #binary to decimal

    md5Hash = ''
    for r in asci:
        md5Hash += base64[r]
    return md5Hash



def loop(filename, checkpoint):
    timer = 0
    print("this is the filename:" + filename)
    with open(filename) as fp:
        
        for line in fp:
            if line <= checkpoint:
                continue
            if timer == 0:
                t0 = time.time()
            timer += 1
            line = line.replace("\n","")
            hash = md5(line)
            if(timer == 1000):
                t1 = time.time()
                print("throughtput: " + str(t1-t0) + " seconds for 1000 passwords")
                print("line: " + line)
                timer = 0
            if(hash == passhash):
                print("WE DID IT BOYS")
                print("WE DID IT BOYS")
                print("WE DID IT BOYS")
                print("pass: " + line)
                break
        print("Password = " + line)

arg = sys.argv[1]
checkpoint = sys.argv[2] + "\n"
loop(arg,checkpoint)

#a, o, h, n, l, i t
#x y z w v u 