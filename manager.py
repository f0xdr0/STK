#!/usr/bin/python3

import socket
import argparse
import sys
from mikrotik import ApiRos

Login  = 'apiusr'
Password = 'qwertyqwerty1'
BrasIP = '192.168.111.1'
ListName = 'BillBlockq'


def init(Login,Password,RouterIP):
    s = None
    for res in socket.getaddrinfo(RouterIP, "8728", socket.AF_UNSPEC, socket.SOCK_STREAM):
      af, socktype, proto, canonname, sa = res
      try:
           s = socket.socket(af, socktype, proto)
      except (socket.error, msg):
          s = None
          continue
      try:
          s.connect(sa)
      except (socket.error, msg):
          s.close()
          s = None
          continue
      break
    if s is None:
      print ('could not open socket')
      sys.exit(1)
    apiros = ApiRos(s);
    apiros.login(Login, Password);
    return apiros


def AddIpToList(apiros,ClientIP,ListName):
    InList = False
    inputsentence = ['/ip/firewall/address-list/print','?list={}'.format(ListName),'?address={}'.format(ClientIP)]
    apiros.writeSentence(inputsentence)
    resp = ['init']
    while resp[0].strip() != '!done':
      resp=apiros.readSentence()
      if resp[0].strip() == '!re':
          InList = True
    if not InList:
      inputsentence = ['/ip/firewall/address-list/add','=list={}'.format(ListName),'=address={}'.format(ClientIP),'=disabled=no']
      apiros.writeSentence(inputsentence)
      resp=['init']
      while resp[0].strip()!='!done':
        resp=apiros.readSentence()
    return 0

def RemIpFromList(apiros,ClientIP,ListName):
    inputsentence = ['/ip/firewall/address-list/print','?list={}'.format(ListName),'?address={}'.format(ClientIP),'=.proplist=.id']
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

def ChangeList(apiros,ClientIP,OldListName,NewListName):
    inputsentence = ['/ip/firewall/address-list/print','?list={}'.format(OldListName),'?address={}'.format(ClientIP),'=.proplist=.id']
    apiros.writeSentence(inputsentence)
    IDList=[]
    resp=["init"]
    while resp[0].strip()!="!done":
      resp=apiros.readSentence()
      if resp[0].strip()=="!re":
        IDList.append(resp[1])
    for id in IDList:
      inputsentence = ['/ip/firewall/address-list/set',id,'=list={}'.format(NewListName)]
      apiros.writeSentence(inputsentence)
      resp=["init"]
      while resp[0].strip()!="!done":
        resp=apiros.readSentence()
    return 0


def main ():
    sock=init(Login,Password,BrasIP)
    AddIpToList(sock,'192.168.111.200',ListName)
    #RemIpFromList(sock,'192.168.111.200',ListName)
#    ChangeList(sock,'192.168.111.200',ListName,'GoGoGoGMBT')
if __name__ == '__main__':
    main()

