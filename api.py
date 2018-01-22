#!/usr/bin/python

import sys, posix, time, md5, binascii, socket

class ApiRos:
    "Routeros api"
    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0
        
    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login"]):
            chal = binascii.unhexlify(attrs['=ret'])
        md = md5.new()
        md.update('\x00')
        md.update(pwd)
        md.update(chal)
        self.talk(["/login", "=name=" + username,
                   "=response=00" + binascii.hexlify(md.digest())])

    def talk(self, words):
        if self.writeSentence(words) == 0: return
        r = []
        while 1:
            i = self.readSentence();
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j+1:]
            r.append((reply, attrs))
            if reply == '!done': return r

    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret

    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '': return r
            r.append(w)
            
    def writeWord(self, w):
        #print "<<< " + w
        self.writeLen(len(w))
        self.writeStr(w)

    def readWord(self):
        ret = self.readStr(self.readLen())
        #print ">>> " + ret
        return ret

    def writeLen(self, l):
        if l < 0x80:
            self.writeStr(chr(l))
        elif l < 0x4000:
            l |= 0x8000
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        elif l < 0x200000:
            l |= 0xC00000
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        elif l < 0x10000000:        
            l |= 0xE0000000         
            self.writeStr(chr((l >> 24) & 0xFF))
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        else:                       
            self.writeStr(chr(0xF0))
            self.writeStr(chr((l >> 24) & 0xFF))
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))

    def readLen(self):              
        c = ord(self.readStr(1))    
        if (c & 0x80) == 0x00:      
            pass                    
        elif (c & 0xC0) == 0x80:    
            c &= ~0xC0              
            c <<= 8                 
            c += ord(self.readStr(1))    
        elif (c & 0xE0) == 0xC0:    
            c &= ~0xE0              
            c <<= 8                 
            c += ord(self.readStr(1))    
            c <<= 8                 
            c += ord(self.readStr(1))    
        elif (c & 0xF0) == 0xE0:    
            c &= ~0xF0              
            c <<= 8                 
            c += ord(self.readStr(1))    
            c <<= 8                 
            c += ord(self.readStr(1))    
            c <<= 8                 
            c += ord(self.readStr(1))    
        elif (c & 0xF8) == 0xF0:    
            c = ord(self.readStr(1))     
            c <<= 8                 
            c += ord(self.readStr(1))    
            c <<= 8                 
            c += ord(self.readStr(1))    
            c <<= 8                 
            c += ord(self.readStr(1))    
        return c                    

    def writeStr(self, str):        
        n = 0;                      
        while n < len(str):         
            r = self.sk.send(str[n:])
            if r == 0: raise RuntimeError, "connection closed by remote end"
            n += r                  

    def readStr(self, length):      
        ret = ''                    
        while len(ret) < length:    
            s = self.sk.recv(length - len(ret))
            if s == '': raise RuntimeError, "connection closed by remote end"
            ret += s
        return ret

def AddIpToList(ip,BilLogin,BilPass,BilIP,log):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((BilIP, 8728))  
    apiros = ApiRos(s);
    apiros.login(BilLogin, BilPass);
    SString="?address=%s" % ip
    AString="=address=%s" % ip
    inputsentence = ['/ip/firewall/address-list/print','?list=BillBlock',SString]
    apiros.writeSentence(inputsentence)
    InList=False
    resp=["init"]
    while resp[0].strip()!="!done":
	resp=apiros.readSentence()
	log.write(resp[0].strip()+"\n")
	if resp[0].strip()=="!re":
	    InList=True
    if InList==False:
	inputsentence = ['/ip/firewall/address-list/add','=list=BillBlock',AString,'=disabled=no']
	apiros.writeSentence(inputsentence)
	resp=["init"]
	while resp[0].strip()!="!done":
	    resp=apiros.readSentence()
	    log.write(resp[0].strip()+"\n")
    return 0

def RemIpFromList(ip,BilLogin,BilPass,BilIP,log):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((BilIP, 8728))  
    apiros = ApiRos(s);
    apiros.login(BilLogin, BilPass);
    SString="?address=%s" % ip
    inputsentence = ['/ip/firewall/address-list/print','?list=BillBlock',SString,"=.proplist=.id"]
    apiros.writeSentence(inputsentence)
    IDList=[]
    resp=["init"]
    while resp[0].strip()!="!done":
	resp=apiros.readSentence()
	if resp[0].strip()=="!re":
	    IDList.append(resp[1])
    for id in IDList:
	inputsentence = ['/ip/firewall/address-list/remove',id]
	apiros.writeSentence(inputsentence)
	resp=["init"]
	while resp[0].strip()!="!done":
	    resp=apiros.readSentence()
    return 0

def main():
    output_file = open ('/var/log/api.log','w')
    BilLogin="billing"
    BilPass="n9j89vuYw61k851"
    BilIP="192.168.10.1"
    Cmd = sys.argv[1].strip()
    ip = sys.argv[2].strip()
    if Cmd == "enable":
	RemIpFromList(ip,BilLogin,BilPass,BilIP,output_file)
	output_file.write("Enable - done\n")
    elif Cmd == "disable":
	AddIpToList(ip,BilLogin,BilPass,BilIP,output_file)
	output_file.write("disable-done\n")
    elif Cmd == "tarif":
	output_file.write("tarif-done - %s\n"%ip)

    else: print "Unknown command"
    
    
    output_file.write(Cmd+" ")
    output_file.write(ip)
    output_file.close

if __name__ == '__main__':
    main()
