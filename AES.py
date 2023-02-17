#AES operation 
#1- Substituting bytes (using S BOX)
#2- Shifting rows
#3- Mixing columns
#4 -Adding (XORing) the round key
#5- Key Expansion

# p.s input and output will be given as hexadecimal 
#-------------------------------------------------------------------------------------------------------------------

# the S BOX
from collections import deque
from numpy import *
import numpy as np
SBox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )
roundKeys=array([1,0,0,0,2,0,0,0,4,0,0,0,8,0,0,0,16,0,0,0,32,0,0,0,64,0,0,0,128,0,0,0,27,0,0,0,54,0,0,0]).reshape(10,4)

def makeHex(txt):
    new=[]
    length = len(txt)
    for i in range(length):
        if i%2==0 :
            new.append("-")
            new.append(txt[i])
        else :
            new.append(txt[i])
    new.pop(0)
    s =  "".join(new)
    return np.fromiter((int(x, 16) for x in s.split('-')), dtype=np.int32)
    
    
    # create the initial State

# create the initial State as integers
def createStat2(txt):
    state = array(range(16)).reshape(4,4)
    start =0
    for i in range(4):
        for j in range(4):
            state[j][i]=txt[start]
            start +=1
    return state
#------------------------------------------------------------------------------------------------------------------
#1- Substituting bytes (using S BOX)
def intToHex(intArr):
    state = array(range(16), dtype='<U2').reshape(4,4)
    for i in range(4):
        for j in range (4):
            state[i][j]=hex(intArr[i][j])[2:4]
            if len(state[i][j])==1:
                state[i][j]="0"+state[i][j]        
    return state
def subBytes(plain):
    plain=intToHex(plain)
    lut={'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}
    state = array(range(16)).reshape(4,4)
    index=0
    temp=""
    for i in range(4):
        for j in range (4):
            temp=str(plain[i][j])
            index = lut[temp[0]]*16+lut[temp[1]]
            state[i][j]=(int(SBox[index]))
            
    return state
#-------------------------------------------------------------------------------------------------------------------
#2- Shift Rows 
def shiftRow(plain):
    dq = deque(range(4), maxlen=4)
    state = array(range(16)).reshape(4,4)
    temp=[]
    for i in range(4):
        dq.clear()
        temp=plain[i]
        dq.extend(temp)
        dq.rotate(-i)
        state[i]=dq
    return state
#-----------------------------------------------------------------------------------------------------------------------------------
# 3- Mix Columns
def mul2(y):
    if int(bin(y)[2])==1 :
        if len(bin(y))==10:
            return ((2*y)%256)^27
        else :
            return 2*y
        
def mult(x,y):
    sum=0
    for i in range(4):
        if x[i]==2:
            sum^=mul2(y[i])
        elif x[i]==3:
            sum^=y[i]^(mul2(y[i]))
        else : 
            sum^=y[i]
            
    return sum

def mixColumn(plain):
    state = array(range(16)).reshape(4,4)
    mix = array([2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2]).reshape(4,4)
    for i in range(4):
        for j in range (4):
            state[i][j]= mult(mix[i],plain[:,j])
    return state
#----------------------------------------------------------------------------------------------------------------------------
# 4- Adding (XORing) the round key
def xoring(state,rKey):
    return state^rKey
#---------------------------------------------------------------------------------------------------------------------------
#5- Key Expansion
#A- Create Words
def word(key):
    return key.transpose()
#B- Rotate Word
def rotWord(key):
    dq = deque(range(4), maxlen=4)
    dq.clear()
    dq.extend(key)
    dq.rotate(-1)
    return dq
#C- Substitute Word
def intToHexKey(intArr):
    state = array(range(4), dtype='<U2')
    for i in range(4):
        state[i]=hex(intArr[i])[2:4]
        if len(state[i])==1:
            state[i]="0"+state[i]      
    return state
def subWord (key):
    key=intToHexKey(key)
    lut={'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}
    state = array(range(4))
    index=0
    temp=""
    for i in range(4):
        temp=str(key[i])
        index = lut[temp[0]]*16+lut[temp[1]]
        state[i]=(int(SBox[index]))
            
    return state

#D- New Key Generation
def nxtKey(oldKey,row):
    oldKey[0]=oldKey[0]^row
    oldKey[1]=oldKey[0]^oldKey[1]
    oldKey[2]=oldKey[1]^oldKey[2]
    oldKey[3]=oldKey[2]^oldKey[3]
    return oldKey

# All Together 
def keyExpansion(oldKey ,roundNumber):
    # Old key is an array of type integer
    words = word(oldKey)
    state = array(words[-1])
    state=rotWord(state)
    state=subWord(state)
    state=xoring(state,roundKeys[roundNumber])
    words=nxtKey(words,state)
    return words.transpose()
#-----------------------------------------------------------------------------------------------------------------------------
#Format Output
def output(cipher):
    out=[]
    for i in range(4):
        for j in range(4):
            out.append(cipher[j][i])
    return "".join(out)
#----------------------------------------------------------------------------------------------------------------------------
#THIS CODE WORKS FOR PLAIN TEXT AND KEY OF SIZE 128 BITS
#------------------------------------------------------------------------------------------------------------------------------
# Final Cipher
def AESCipher(plain,key,noOfRounds):
    # turn the string into 1-D array
    hexText=makeHex(plain)
    hexKey=makeHex(key)
    
    # Turn Array to (4*4)
    hexKeyInt= createStat2(hexKey)
    hexTextInt= createStat2(hexText)
    
    #Plain Text after initial transformation
    plainText= xoring(hexTextInt,hexKeyInt)
    
    # Repeated Cipher 
    for i in range(noOfRounds-1):
        plainText=subBytes(plainText)
        plainText=shiftRow(plainText)
        plainText=mixColumn(plainText)
        
        hexKeyInt=keyExpansion(hexKeyInt,i);
        plainText= xoring(plainText,hexKeyInt)
    
    plainText=subBytes(plainText)
    plainText=shiftRow(plainText)
    hexKeyInt=keyExpansion(hexKeyInt,noOfRounds-1);
    plainText= xoring(plainText,hexKeyInt)
    return output(intToHex(plainText))
#--------------------------------------------------------------------------------------------------------------------------------
# input the Key and Plain Text
key = input("Enter the key for AES Cipher (128 bit) :\n")
plainText = input ("Enter the message you want to encrypt (128 bit):\n ")
#Conversion To Hexadecimal
# no Of Rounds 
numberOfRounds=10
#----------------------------------------------------------------------------------------------------------------------------
#The Final Result
cipherText=AESCipher(plainText,key,numberOfRounds)
print("The encrypted Message :\n")
print(cipherText)
