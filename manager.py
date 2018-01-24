#!/usr/bin/env python
#! -*- coding: utf-8 -*-

import socket
import argparse
import sys
import yaml
import re
from api import ApiRos


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

def SetTarif(apiros,ClientIP,ListName):
    tpattern = re.compile('^=list=shaper_\w+')
    inputsentence = ['/ip/firewall/address-list/print','?address={}'.format(ClientIP),'=.proplist=.id,list']
    apiros.writeSentence(inputsentence)
    IDList=[]
    resp=["init"]
    while resp[0].strip()!="!done":
      resp=apiros.readSentence()
      if resp[0].strip()=="!re":
        if tpattern.match(resp[2].strip()):
          IDList.append(resp[1])
    for id in IDList:
      inputsentence = ['/ip/firewall/address-list/set',id,'=list={}'.format(ListName)]
      apiros.writeSentence(inputsentence)
      resp=["init"]
      while resp[0].strip()!="!done":
        resp=apiros.readSentence()
    return 0

def AddNat(apiros,ClientIP,WhiteIP):
    InList = False
    inputsentence = ['/ip/firewall/nat/print','?src-address={}'.format(ClientIP)]
    apiros.writeSentence(inputsentence)
    resp = ['init']
    while resp[0].strip() != '!done':
      resp=apiros.readSentence()
      if resp[0].strip() == '!re':
          InList = True
    if not InList:
      inputsentence = ['/ip/firewall/nat/add','=chain=srcnat','=action=src-nat','=to-addresses={}'.format(WhiteIP),'=src-address={}'.format(ClientIP),'=disabled=no']
      apiros.writeSentence(inputsentence)
      resp=['init']
      while resp[0].strip()!='!done':
        resp=apiros.readSentence()
    return 0

def DelNat(apiros,ClientIP,WhiteIP):
    inputsentence = ['/ip/firewall/nat/print','?src-address={}'.format(ClientIP),'?to-addresses={}'.format(WhiteIP),'=.proplist=.id']
    apiros.writeSentence(inputsentence)
    IDList=[]
    resp=["init"]
    while resp[0].strip()!="!done":
      resp=apiros.readSentence()
      if resp[0].strip()=="!re":
        IDList.append(resp[1])
    for id in IDList:
      inputsentence = ['/ip/firewall/nat/remove',id]
      apiros.writeSentence(inputsentence)
      resp=["init"]
      while resp[0].strip()!="!done":
        resp=apiros.readSentence()
    return 0


def main ():
    with open('config.yaml','r') as cfg_file:
      bras = yaml.load(cfg_file)

    parser = argparse.ArgumentParser(description='Управление BRAS')
    parser.add_argument('-cmd', action='store',type=str, dest='cmd',choices=['logon','logoff','set_tarif','naton','natoff'],required=True, help='Executable command ')
    parser.add_argument('-bras', action='store',type=str, dest='bras',choices=bras.keys(),required=True, help='Bras name from config.yaml')
    parser.add_argument('-ip', action='store',type=str, dest='clientIP',required=True, help='Client ip address ')
    parser.add_argument('-tarif_id', action='store',type=int, dest='tarifID', help='Tariff ID (see config.yaml) ')
    parser.add_argument('-white_ip', action='store',type=str, dest='whiteIP', help='White ip for 1to1 NAT ')
    args = parser.parse_args()
    sock=init(bras[args.bras]['username'], bras[args.bras]['password'], bras[args.bras]['ip'])

    if args.cmd == 'logon':
      RemIpFromList(sock, args.clientIP, bras[args.bras]['BlockListName'])

    elif args.cmd == 'logoff':
      AddIpToList(sock, args.clientIP, bras[args.bras]['BlockListName'])

    elif args.cmd == 'set_tarif':
      if args.tarifID:
        SetTarif(sock, args.clientIP, bras[args.bras]['tarif_id'][args.tarifID])
      else:
        print ('Error: tarif id  required!')
        sys.exit(1)


    elif args.cmd == 'naton':
      if args.whiteIP:
        AddNat(sock, args.clientIP,args.whiteIP)
      else:
        print ('Error: white ip required!')
        sys.exit(1)

    elif args.cmd == 'natoff':
      if args.whiteIP:
        DelNat(sock, args.clientIP,args.whiteIP)
      else:
        print ('Error: white ip required!')
        sys.exit(1)

if __name__ == '__main__':
    main()

